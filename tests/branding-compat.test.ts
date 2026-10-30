import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createCipheriv, randomBytes, scryptSync } from 'node:crypto'
import { mkdtemp, mkdir, readFile, rm, writeFile, realpath } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import type { Server, VaultData } from '../src/model'
import { Vault, openSealed, seal } from '../electron/core/vault'
import { VaultLibrary } from '../electron/core/vault-library'
import { resourceNamespace } from '../electron/core/resource-namespace'
import { applyConfigs } from '../electron/core/provision'
import type { Remote } from '../electron/core/ssh'
import * as scripts from '../electron/core/scripts'
import { makeMaterial } from '../electron/core/protocols'
import { fixture } from './fixtures'

const password='old vault password stays valid'
// Generate the actual pre-rename envelope independently of the current encoder.
function legacyEnvelope(data:VaultData){
 const salt=randomBytes(32),iv=randomBytes(12),key=scryptSync(password,salt,32,{N:32768,r:8,p:1,maxmem:64*1024*1024})
 try{
  const cipher=createCipheriv('aes-256-gcm',key,iv)
  cipher.setAAD(Buffer.from('monetka:vault:v1:scrypt:32768:8:1'))
  const ciphertext=Buffer.concat([cipher.update(JSON.stringify(data)),cipher.final()])
  return JSON.stringify({format:'monetka-vault',version:1,kdf:'scrypt-32768-8-1',salt:salt.toString('base64'),iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),ciphertext:ciphertext.toString('base64')})
 }finally{key.fill(0)}
}
async function temporary(fn:(root:string)=>Promise<void>){const root=await mkdtemp(join(tmpdir(),'manetka-compat-'));try{await fn(root)}finally{await rm(root,{recursive:true,force:true})}}

test('pre-rename encrypted files retain their password; new saves use authenticated manetka headers',async()=>temporary(async root=>{
 const {data}=fixture();delete data.profiles[0].servers[0].resourceNamespace
 const raw=legacyEnvelope(data),path=join(root,'old.monetka');await writeFile(path,raw)
 const library=new VaultLibrary(join(root,'manetka'));await library.init();await library.open(path)
 await library.current!.unlock(password);assert.deepEqual(library.current!.require(),data)
 assert.equal(await readFile(path,'utf8'),raw)
 const copy=join(root,'copy.manetka');await library.current!.copyTo(copy)
 assert.equal(JSON.parse(await readFile(copy,'utf8')).format,'manetka-vault')
 assert.deepEqual(await openSealed(await readFile(copy,'utf8'),password),data)
 await library.current!.save();assert.equal(JSON.parse(await readFile(path,'utf8')).format,'manetka-vault')
 library.current!.lock()
 for(const [encoded,changedFormat] of [[raw,'manetka-vault'],[await seal(data,password),'monetka-vault']]){
  const changed=JSON.parse(encoded);changed.format=changedFormat
  await assert.rejects(openSealed(JSON.stringify(changed),password))
 }
}))

test('renamed application imports recent paths once without modifying old catalog or vault files',async()=>temporary(async root=>{
 const oldRoot=join(root,'monetka'),newRoot=join(root,'manetka'),old=new VaultLibrary(oldRoot)
 await old.init();const path=join(old.directory,'Production.monetka');await writeFile(path,legacyEnvelope(fixture().data));await old.open(path)
 const oldCatalog=await readFile(old.catalogPath),oldBytes=await readFile(path)
 const renamed=new VaultLibrary(newRoot,oldRoot);await renamed.init()
 assert.equal(renamed.current!.path,await realpath(path));assert.equal(renamed.current!.unlocked,false)
 assert.equal(renamed.directory,join(newRoot,'vaults'))
 await renamed.current!.unlock(password);assert.equal(renamed.current!.require().profiles[0].servers.length,1)
 renamed.current!.lock();await renamed.forget((await renamed.info()).selectedId!)
 const restart=new VaultLibrary(newRoot,oldRoot);await restart.init();assert.equal((await restart.info()).files.length,0)
 assert.deepEqual(await readFile(old.catalogPath),oldCatalog);assert.deepEqual(await readFile(path),oldBytes)
}))

test('pre-library vault is found in the old app directory; corrupt legacy catalog is preserved safely',async()=>temporary(async root=>{
 const oldRoot=join(root,'monetka'),newRoot=join(root,'manetka');await mkdir(oldRoot)
 const path=join(oldRoot,'monetka.vault'),raw=legacyEnvelope(fixture().data);await writeFile(path,raw)
 await writeFile(join(oldRoot,'vaults.json'),'corrupt legacy list')
 const renamed=new VaultLibrary(newRoot,oldRoot);await renamed.init();assert(renamed.warning)
 assert.equal(renamed.current!.path,await realpath(path));await renamed.current!.unlock(password);renamed.current!.lock()
 assert.equal(await readFile(path,'utf8'),raw);assert.equal(await readFile(join(oldRoot,'vaults.json'),'utf8'),'corrupt legacy list')
}))

test('new and legacy server records address their own services without altering VPN content',async()=>{
 for(const namespace of ['manetka','monetka'] as const){
  const {server,data}=fixture();if(namespace==='monetka')delete server.resourceNamespace
  assert.equal(resourceNamespace(server),namespace)
  const bashScripts=[scripts.ownerCheck(server),scripts.preflight(server),scripts.initialize(server),scripts.hardeningScript(server),scripts.disablePasswordLoginScript(server),scripts.cleanupScript(server)]
  for(const script of bashScripts)assert.equal(spawnSync('bash',['-n'],{input:script}).status,0)
  const cleanup=scripts.cleanupScript(server)
  assert(cleanup.includes(`systemd/system/${namespace}-{wireguard`));assert(cleanup.includes(`sed -i '/ ${namespace}-${server.ownerId}$/d'`))
  assert(scripts.tunnelUnit('amneziawg',server).includes(`ExecStart=/usr/local/lib/${namespace}/awg-tools/bin/awg-quick`))
  server.protocols['vless-ws']=makeMaterial('vless-ws',{port:2053,sni:'manetka.example.com',domain:'manetka.example.com',path:'/manetka'})
  const writes:{path:string;content:string}[]=[],commands:string[]=[]
  const remote={write:async(path:string,content:string)=>{writes.push({path,content})},exec:async(command:string)=>{commands.push(command);return ''}} as unknown as Remote
  await applyConfigs(remote,server,data.profiles[0])
  assert(writes.some(w=>w.path===`/etc/${namespace}/xray.json`))
  assert(writes.some(w=>w.path===`/etc/systemd/system/${namespace}-wireguard.service`))
  assert(writes.find(w=>w.path.endsWith('/xray.json'))!.content.includes('/manetka'))
  for(const command of commands){assert.equal(spawnSync('bash',['-n'],{input:command}).status,0);assert(!command.includes('${ns}'))}
 }
})
