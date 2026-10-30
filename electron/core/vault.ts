import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID, scrypt as scryptCb } from 'node:crypto'
import { readFile, writeFile, mkdir, rename, chmod, stat, unlink } from 'node:fs/promises'
import { dirname } from 'node:path'
import { z } from 'zod'
import type { PublicState, VaultData } from '../../src/model'
import { passwordSchema, vaultDataSchema } from './validation'
import { publishNewFile } from './file-write'
import { keyUses, migrateSSHKeys, validateStoredSSHKeys } from './ssh-keys'

const MAX = 32 * 1024 * 1024
const AAD = Buffer.from('manetka:vault:v1:scrypt:32768:8:1')
// The original header is authenticated too: selecting its AAD preserves old files
// while changing only the header of either format still fails authentication.
const LEGACY_AAD = Buffer.from('monetka:vault:v1:scrypt:32768:8:1')
const envelopeSchema = z.object({ format: z.enum(['manetka-vault','monetka-vault']), version: z.literal(1), kdf: z.literal('scrypt-32768-8-1'), salt: z.string().regex(/^[A-Za-z0-9+/]{43}=$/), iv: z.string().regex(/^[A-Za-z0-9+/]{16}$/), tag: z.string().regex(/^[A-Za-z0-9+/]{22}==$/), ciphertext: z.string().min(1).max(MAX * 2).regex(/^[A-Za-z0-9+/]+={0,2}$/) }).strict()
type Envelope = z.infer<typeof envelopeSchema>
const derive = (password: string, salt: Buffer) => new Promise<Buffer>((resolve,reject) => scryptCb(password,salt,32,{N:32768,r:8,p:1,maxmem:64*1024*1024},(e,k)=> e ? reject(e) : resolve(k)))
function encrypt(data: VaultData, key: Buffer, salt: Buffer): Envelope {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm',key,iv)
  cipher.setAAD(AAD)
  const bytes = Buffer.from(JSON.stringify(data))
  try { const ciphertext = Buffer.concat([cipher.update(bytes),cipher.final()]); return {format:'manetka-vault',version:1,kdf:'scrypt-32768-8-1',salt:salt.toString('base64'),iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),ciphertext:ciphertext.toString('base64')} } finally { bytes.fill(0) }
}
export async function validateVaultFile(path:string) {
  const info=await stat(path)
  if(!info.isFile()||info.size>MAX)throw new Error('Выберите файл хранилища maNETka до 32 МБ')
  try{envelopeSchema.parse(JSON.parse(await readFile(path,'utf8')))}catch{throw new Error('Это не файл хранилища maNETka или файл повреждён')}
}
const hash=(raw:string)=>createHash('sha256').update(raw).digest('hex')
async function decrypt(raw: string, password: string): Promise<{ data: VaultData; key: Buffer; salt: Buffer; migrated:boolean }> {
  if (Buffer.byteLength(raw) > MAX) throw new Error('Хранилище слишком большое')
  const envelope = envelopeSchema.parse(JSON.parse(raw))
  const salt = Buffer.from(envelope.salt,'base64')
  const key = await derive(password,salt)
  let bytes: Buffer | undefined
  try {
    const cipher = createDecipheriv('aes-256-gcm',key,Buffer.from(envelope.iv,'base64'))
    cipher.setAAD(envelope.format==='monetka-vault'?LEGACY_AAD:AAD); cipher.setAuthTag(Buffer.from(envelope.tag,'base64'))
    bytes = Buffer.concat([cipher.update(Buffer.from(envelope.ciphertext,'base64')),cipher.final()])
    const data = vaultDataSchema.parse(JSON.parse(bytes.toString('utf8'))) as VaultData
    validateStoredSSHKeys(data.sshKeys)
    const migrated=migrateSSHKeys(data)
    vaultDataSchema.parse(data)
    return { data, key, salt, migrated }
  } catch { key.fill(0); throw new Error('Неверный пароль или повреждённое хранилище') } finally { bytes?.fill(0) }
}
export async function seal(data: VaultData, password: string): Promise<string> {
  passwordSchema.parse(password); vaultDataSchema.parse(data)
  const salt = randomBytes(32); const key = await derive(password,salt)
  try { return JSON.stringify(encrypt(data,key,salt)) } finally { key.fill(0) }
}
export async function openSealed(raw: string, password: string): Promise<VaultData> {
  const opened = await decrypt(raw,password); opened.key.fill(0); return opened.data
}
export class Vault {
  private key?: Buffer
  private salt?: Buffer
  private data?: VaultData
  private savedHash?:string
  constructor(readonly path: string) {}
  get unlocked() { return !!this.data }
  async exists() { try { await stat(this.path); return true } catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') return false; throw e } }
  require(): VaultData { if (!this.data || !this.key) throw new Error('Хранилище заблокировано'); return this.data }
  async create(password: string,initialData?:VaultData) {
    if (await this.exists()) throw new Error('Хранилище уже существует')
    passwordSchema.parse(password)
    const id = randomUUID()
    this.salt = randomBytes(32); this.key = await derive(password,this.salt)
    this.data = { version:1,installationId:randomUUID(),activeProfileId:id,sshKeys:[],profiles:[{id,name:'Личный',servers:[],configs:[],routes:[]}],autoLockMinutes:5,audit:[] }
    try { if(initialData){this.data=vaultDataSchema.parse(structuredClone(initialData)) as VaultData;validateStoredSSHKeys(this.data.sshKeys);migrateSSHKeys(this.data)}
    await this.save(true) } catch(e) { this.lock(); throw e }
  }
  async unlock(password: string) {
    if (password.length > 1024) throw new Error('Слишком длинный пароль')
    const info = await stat(this.path)
    if (info.size > MAX) throw new Error('Хранилище слишком большое')
    const raw=await readFile(this.path,'utf8')
    const opened = await decrypt(raw,password)
    this.lock(); this.data = opened.data; this.key = opened.key; this.salt = opened.salt; this.savedHash=hash(raw)
    try { if(opened.migrated)await this.save() } catch(e) { this.lock(); throw e }
  }
  lock() { this.key?.fill(0); this.key=undefined; this.salt=undefined; this.data=undefined;this.savedHash=undefined }
  async save(createOnly=false) {
    const data = this.require()
    vaultDataSchema.parse(data)
    if (!this.key || !this.salt) throw new Error('Хранилище заблокировано')
    const serialized = JSON.stringify(encrypt(data,this.key,this.salt))
    if (Buffer.byteLength(serialized)>MAX) throw new Error('Превышен размер хранилища')
    await mkdir(dirname(this.path),{recursive:true,mode:0o700})
    const temp = this.path + '.' + randomUUID() + '.tmp'
    try {
      await writeFile(temp,serialized,{mode:0o600,flag:'wx',flush:true})
      if(createOnly){try{await publishNewFile(temp,this.path)}catch(error){if((error as NodeJS.ErrnoException).code==='EEXIST')throw new Error('Хранилище уже существует. Выберите другое имя файла.');throw error}}
      else {
        const current=await readFile(this.path,'utf8').catch(()=>undefined)
        if(!this.savedHash||current===undefined||hash(current)!==this.savedHash)throw new Error('Файл хранилища изменён или перемещён вне приложения. Закройте и откройте его заново; внешняя версия не перезаписана.')
        await rename(temp,this.path)
      }
      this.savedHash=hash(serialized)
      await chmod(this.path,0o600)
    }finally{await unlink(temp).catch(()=>{})}
  }
  async copyTo(path:string) {
    if(path===this.path)throw new Error('Для копии выберите другое имя файла')
    let serialized:string
    if(this.data&&this.key&&this.salt){vaultDataSchema.parse(this.data);serialized=JSON.stringify(encrypt(this.data,this.key,this.salt))}
    else {await validateVaultFile(this.path);serialized=await readFile(this.path,'utf8');envelopeSchema.parse(JSON.parse(serialized))}
    if(Buffer.byteLength(serialized)>MAX)throw new Error('Превышен размер хранилища')
    const temp=path+'.'+randomUUID()+'.tmp'
    try {
      await writeFile(temp,serialized,{mode:0o600,flag:'wx',flush:true})
      try{await publishNewFile(temp,path)}catch(error){if((error as NodeJS.ErrnoException).code==='EEXIST')throw new Error('Файл уже существует. Выберите новое имя для копии.');throw error}
      await chmod(path,0o600)
    }finally{await unlink(temp).catch(()=>{})}
  }
  async replace(data: VaultData) {
    this.require(); data = vaultDataSchema.parse(structuredClone(data)) as VaultData
    validateStoredSSHKeys(data.sshKeys);migrateSSHKeys(data);vaultDataSchema.parse(data)
    const old = this.data; this.data = data
    try { await this.save() } catch(e) { this.data=old; throw e }
  }
  async publicState(busy?: string): Promise<PublicState> {
    if (!this.data) return {exists:await this.exists(),locked:true,profiles:[],sshKeys:[],autoLockMinutes:5,audit:[],busy}
    return {exists:true,locked:false,activeProfileId:this.data.activeProfileId,autoLockMinutes:this.data.autoLockMinutes,audit:this.data.audit,busy,sshKeys:this.data.sshKeys.map(({privateKey,passphrase,...key})=>{const uses=keyUses(this.data!,key.id);return {...key,encrypted:!!passphrase,uses,canDelete:uses.length===0}}),profiles:this.data.profiles.map(p=>({...p,servers:p.servers.map(({credential,protocols,...s})=>({...s,authType:credential.type,sshKeyId:credential.keyId,protocols:Object.fromEntries(Object.entries(protocols).map(([k,{privateKey,...settings}])=>[k,settings]))})),configs:p.configs.map(({content,publicKey,clientId,...c})=>c)}))}
  }
}
