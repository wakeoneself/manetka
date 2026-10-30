import {randomUUID} from 'node:crypto'
import {basename,join,resolve,extname,dirname,isAbsolute} from 'node:path'
import {readFile,writeFile,mkdir,rename,stat,realpath,chmod,copyFile,unlink} from 'node:fs/promises'
import {z} from 'zod'
import type {PublicState,VaultData,VaultLibraryState} from '../../src/model'
import {Vault,validateVaultFile} from './vault'
const entrySchema=z.object({id:z.uuid(),path:z.string().min(1).max(4096).refine(p=>isAbsolute(p)&&!p.includes('\0')),lastUsedAt:z.iso.datetime().optional()}).strict()
const catalogSchema=z.object({version:z.literal(1),selectedId:z.uuid().optional(),files:z.array(entrySchema).max(100)}).strict().superRefine((d,c)=>{if(new Set(d.files.map(f=>f.id)).size!==d.files.length||new Set(d.files.map(f=>f.path)).size!==d.files.length||d.selectedId&&!d.files.some(f=>f.id===d.selectedId))c.addIssue({code:'custom',message:'Повреждён список хранилищ'})})
type Catalog=z.infer<typeof catalogSchema>
export class VaultLibrary {
 readonly directory:string
 readonly catalogPath:string
 private catalog:Catalog={version:1,files:[]}
 current?:Vault
 warning?:string
 private preserveCatalog?:string
 constructor(readonly root:string,readonly legacyRoot?:string){this.directory=join(root,'vaults');this.catalogPath=join(root,'vaults.json')}
 async init(){
  await mkdir(this.directory,{recursive:true,mode:0o700})
  let loaded=false,imported=false,source=this.catalogPath
  try{
   try{await stat(source)}catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT'&&this.legacyRoot){source=join(this.legacyRoot,'vaults.json');imported=true}else throw e}
   if((await stat(source)).size>512*1024)throw new Error('catalog limit')
   this.catalog=catalogSchema.parse(JSON.parse(await readFile(source,'utf8')));loaded=true
  }
  catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT'){this.warning='Список недавних хранилищ не удалось прочитать. Сами файлы не изменены — откройте нужный файл вручную.';this.preserveCatalog=source}}
  // Import paths only. Existing files and the old catalog are never moved or rewritten.
  if(!loaded)for(const candidate of [join(this.root,'manetka.vault'),join(this.root,'monetka.vault'),...(this.legacyRoot?[join(this.legacyRoot,'monetka.vault')]:[])]){
   const legacy=await realpath(candidate).catch(()=>candidate)
   if(await this.isFile(legacy)&&!this.catalog.files.some(f=>f.path===legacy)){
    const entry={id:randomUUID(),path:legacy};this.catalog.files.push(entry)
    if(!this.catalog.selectedId)this.catalog.selectedId=entry.id
   }
  }
  if((imported&&loaded)||!loaded)await this.save(this.catalog)
  const entry=this.catalog.files.find(f=>f.id===this.catalog.selectedId)
  if(entry)this.current=new Vault(entry.path)
 }
 private async isFile(path:string){try{return(await stat(path)).isFile()}catch{return false}}
 private async save(next:Catalog){
  catalogSchema.parse(next)
  if(this.preserveCatalog){await copyFile(this.preserveCatalog,this.catalogPath+'.previous-'+randomUUID());this.preserveCatalog=undefined}
  const temp=this.catalogPath+'.'+randomUUID()+'.tmp'
  try{await writeFile(temp,JSON.stringify(next),{mode:0o600,flag:'wx',flush:true});await rename(temp,this.catalogPath);await chmod(this.catalogPath,0o600)}finally{await unlink(temp).catch(()=>{})}
 }
 private async activate(path:string,vault=new Vault(path)){
  const next=structuredClone(this.catalog);let entry=next.files.find(f=>f.path===path)
  if(!entry){if(next.files.length>=100)throw new Error('В списке уже 100 хранилищ. Уберите ненужные записи из списка.');entry={id:randomUUID(),path};next.files.push(entry)}
  entry.lastUsedAt=new Date().toISOString();next.selectedId=entry.id
  await this.save(next)
  this.current?.lock();this.current=vault;this.catalog=next
 }
 async open(path:string){path=await realpath(resolve(path));await validateVaultFile(path);await this.activate(path)}
 async select(id:string){const entry=this.catalog.files.find(f=>f.id===z.uuid().parse(id));if(!entry)throw new Error('Хранилище не найдено в списке');await this.open(entry.path)}
 async create(path:string,password:string,data?:VaultData){
  path=resolve(path);path=join(await realpath(dirname(path)),basename(path))
  if(!['.manetka','.vault'].includes(extname(path).toLowerCase()))throw new Error('Используйте расширение .manetka')
  if(this.catalog.files.length>=100)throw new Error('Уберите ненужные записи из списка хранилищ перед созданием нового файла')
  const created=new Vault(path)
  try{await created.create(password,data);await this.activate(path,created)}catch(error){created.lock();throw error}
 }
 async close(){const next={...this.catalog,selectedId:undefined};await this.save(next);this.current?.lock();this.current=undefined;this.catalog=next}
 async forget(id:string){
  z.uuid().parse(id);if(!this.catalog.files.some(f=>f.id===id))throw new Error('Хранилище не найдено в списке')
  const next={...this.catalog,files:this.catalog.files.filter(f=>f.id!==id),selectedId:this.catalog.selectedId===id?undefined:this.catalog.selectedId}
  await this.save(next);if(this.catalog.selectedId===id){this.current?.lock();this.current=undefined}this.catalog=next
 }
 pathFor(id?:string){const entry=this.catalog.files.find(f=>f.id===(id??this.catalog.selectedId));if(!entry)throw new Error('Сначала выберите хранилище');return entry.path}
 async info():Promise<VaultLibraryState>{return{selectedId:this.catalog.selectedId,directory:this.directory,warning:this.warning,files:await Promise.all(this.catalog.files.map(async f=>({...f,name:/^(?:manetka|monetka)\.vault$/.test(basename(f.path))?'Основное':basename(f.path,extname(f.path)),missing:!await this.isFile(f.path)})))}}
 async publicState(busy?:string):Promise<PublicState>{
  const state=this.current?await this.current.publicState(busy):{exists:false,locked:true,profiles:[],sshKeys:[],autoLockMinutes:5,audit:[],busy}
  return {...state,vaults:await this.info()}
 }
}
