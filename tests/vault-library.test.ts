import {test} from 'node:test'
import assert from 'node:assert/strict'
import {mkdtemp,readFile,rm,copyFile,writeFile,stat,mkdir,chmod,symlink,readdir,realpath} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {Vault,seal} from '../electron/core/vault'
import {VaultLibrary} from '../electron/core/vault-library'
import {fixture} from './fixtures'
const firstPassword='first vault unique password',secondPassword='second vault unique password'
async function temporary(fn:(root:string)=>Promise<void>){const root=await mkdtemp(join(tmpdir(),'manetka-files-'));try{await fn(root)}finally{await rm(root,{recursive:true,force:true})}}

test('legacy is registered without touching bytes; forgotten password never prevents creating another independent vault',async()=>temporary(async root=>{
 const original=new Vault(join(root,'manetka.vault'));await original.create(firstPassword,fixture().data);original.lock()
 const before=await readFile(original.path);const library=new VaultLibrary(root);await library.init()
 assert.equal(library.current?.path,await realpath(original.path));assert.equal(library.current?.unlocked,false)
 await assert.rejects(library.current!.unlock('forgotten'))
 await library.create(join(library.directory,'Second.manetka'),secondPassword)
 assert.equal(library.current!.require().profiles[0].servers.length,0)
 assert.deepEqual(await readFile(original.path),before)
 const info=await library.info();assert.equal(info.files.length,2);assert(!JSON.stringify(info).includes('Helsinki'))
 const legacyPath=await realpath(original.path);await library.select(info.files.find(f=>f.path===legacyPath)!.id)
 assert.equal(library.current!.unlocked,false);await library.current!.unlock(firstPassword)
 assert.equal(library.current!.require().profiles[0].servers[0].name,'Private Helsinki')
 library.current!.lock();const restart=new VaultLibrary(root);await restart.init();assert.equal(restart.current!.path,await realpath(original.path));assert.equal(restart.current!.unlocked,false)
}))

test('vault file is portable, preserves parent permissions and metadata forget never deletes a file',async()=>temporary(async root=>{
 const shared=join(root,'shared');await mkdir(shared,{mode:0o755});await chmod(shared,0o755)
 const library=new VaultLibrary(join(root,'app'));await library.init()
 const path=join(shared,'Portable.manetka');await library.create(path,firstPassword,fixture().data)
 assert.equal((await stat(shared)).mode&0o777,0o755);assert.equal((await stat(path)).mode&0o777,0o600)
 assert.equal((await stat(library.catalogPath)).mode&0o777,0o600)
 const copy=join(shared,'Moved.manetka');await copyFile(path,copy)
 const other=new VaultLibrary(join(root,'other-app'));await other.init();await other.open(copy);await other.current!.unlock(firstPassword)
 assert.equal(other.current!.require().profiles[0].servers.length,1)
 const selected=(await other.info()).selectedId!;await other.forget(selected)
 assert.equal(other.current,undefined);assert((await stat(copy)).isFile())
 const restart=new VaultLibrary(other.root);await restart.init();assert.equal((await restart.info()).files.length,0)
}))

test('invalid or missing files do not replace an open vault; missing recents are retained and aliases deduplicated',async()=>temporary(async root=>{
 const library=new VaultLibrary(root);await library.init();const path=join(library.directory,'A.manetka');await library.create(path,firstPassword)
 const old=library.current;await writeFile(join(root,'bad.manetka'),'not a vault')
 await assert.rejects(library.open(join(root,'bad.manetka')),/не файл/);assert.equal(library.current,old);assert.equal(old!.unlocked,true)
 const alias=join(root,'Alias.manetka');await symlink(path,alias);await library.open(alias);assert.equal((await library.info()).files.length,1)
 const id=(await library.info()).selectedId!;await rm(path);assert.equal((await library.info()).files[0].missing,true)
 await assert.rejects(library.select(id));assert.equal((await library.info()).selectedId,id)
 await library.close();assert.equal(library.current,undefined);assert.equal((await library.info()).files.length,1)
}))

test('new files are never overwritten, including simultaneous creation; external changes cause save conflicts',async()=>temporary(async root=>{
 const path=join(root,'Shared.manetka'),a=new Vault(path),b=new Vault(path)
 const results=await Promise.allSettled([a.create(firstPassword),b.create(secondPassword)])
 assert.equal(results.filter(r=>r.status==='fulfilled').length,1)
 const winner=results[0].status==='fulfilled'?a:b;const before=await readFile(path)
 await assert.rejects(new Vault(path).create('another unique password'),/существует/);assert.deepEqual(await readFile(path),before)
 const external=await seal(fixture().data,'external unique password');await writeFile(path,external)
 winner.require().profiles[0].name='Unsaved edit';await assert.rejects(winner.save(),/вне приложения/)
 assert.equal(await readFile(path,'utf8'),external);assert(!(await readdir(root)).some(f=>f.endsWith('.tmp')))
 a.lock();b.lock()
}))

test('forgetting the legacy entry is respected after restart; corrupt catalog is preserved on recovery',async()=>temporary(async root=>{
 const legacy=new Vault(join(root,'manetka.vault'));await legacy.create(firstPassword);legacy.lock()
 const library=new VaultLibrary(root);await library.init();await library.forget((await library.info()).selectedId!)
 const restart=new VaultLibrary(root);await restart.init();assert.equal((await restart.info()).files.length,0)
 await writeFile(restart.catalogPath,'broken catalog')
 const damaged=new VaultLibrary(root);await damaged.init();assert(damaged.warning)
 const backups=(await readdir(root)).filter(f=>f.startsWith('vaults.json.previous-'));assert.equal(backups.length,1)
 assert.equal(await readFile(join(root,backups[0]),'utf8'),'broken catalog')
 assert.equal(damaged.current?.path,await realpath(legacy.path))
}))

test('encrypted .manetka copies include all data, retain the password, work while locked and never overwrite',async()=>temporary(async root=>{
 const source=new Vault(join(root,'Source.manetka'));await source.create(firstPassword,fixture().data)
 const before=await readFile(source.path);const copy=join(root,'Copy.manetka');await source.copyTo(copy)
 assert.deepEqual(await readFile(source.path),before);assert.equal((await stat(copy)).mode&0o777,0o600)
 const restored=new Vault(copy);await restored.unlock(firstPassword)
 assert.deepEqual(restored.require(),source.require());restored.lock()
 await assert.rejects(restored.unlock(secondPassword));await assert.rejects(source.copyTo(copy),/существует/)
 assert(!(await readFile(copy,'utf8')).includes('Private Helsinki'))
 source.lock();const lockedCopy=join(root,'Locked-copy.manetka');await source.copyTo(lockedCopy)
 const portable=new Vault(lockedCopy);await portable.unlock(firstPassword);assert.equal(portable.require().profiles[0].servers.length,1);portable.lock()
}))

test('copy fallback on filesystems without hard links retains exclusive-create semantics',async()=>temporary(async root=>{
 const {publishNewFile}=await import('../electron/core/file-write')
 const temp=join(root,'source.tmp'),target=join(root,'target.manetka')
 await writeFile(temp,'encrypted bytes',{mode:0o600})
 const unsupported=async()=>{throw Object.assign(new Error('not supported'),{code:'ENOTSUP'})}
 await publishNewFile(temp,target,unsupported);assert.equal(await readFile(target,'utf8'),'encrypted bytes')
 await writeFile(temp,'new bytes');await assert.rejects(publishNewFile(temp,target,unsupported));assert.equal(await readFile(target,'utf8'),'encrypted bytes')
}))
