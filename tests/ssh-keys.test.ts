import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { execFileSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from '../src/model'
import { Controller } from '../electron/core/controller'
import { Vault, openSealed, seal } from '../electron/core/vault'
import { describePrivateKey, generateSSHKey, keyUses, resolveCredential } from '../electron/core/ssh-keys'
import { fixture } from './fixtures'
const password='a long unique vault password'
async function temporary(fn:(vault:Vault,controller:Controller,dir:string)=>Promise<void>){
 const dir=await mkdtemp(join(tmpdir(),'manetka-keys-'));const vault=new Vault(join(dir,'vault'))
 try{await vault.create(password);await fn(vault,new Controller(vault,()=>{}),dir)}finally{vault.lock();await rm(dir,{recursive:true,force:true})}
}

test('Ed25519 generation interoperates with OpenSSH, including encrypted private keys',async()=>{
 await temporary(async(_vault,_controller,dir)=>{
  const passphrase='separate key passphrase';const key=await generateSSHKey('Deploy',passphrase)
  assert.equal(key.algorithm,'ssh-ed25519');assert.match(key.publicKey,/^ssh-ed25519 /)
  assert.throws(()=>describePrivateKey(key.privateKey,'wrong passphrase'))
  assert.equal(describePrivateKey(key.privateKey,passphrase).fingerprint,key.fingerprint)
  await writeFile(join(dir,'id_ed25519'),key.privateKey,{mode:0o600})
  const pub=execFileSync('ssh-keygen',['-y','-P',passphrase,'-f',join(dir,'id_ed25519')],{encoding:'utf8'}).trim()
  assert.equal(pub.split(' ').slice(0,2).join(' '),key.publicKey.split(' ').slice(0,2).join(' '))
  await writeFile(join(dir,'id_ed25519.pub'),key.publicKey)
  assert(execFileSync('ssh-keygen',['-lf',join(dir,'id_ed25519.pub')],{encoding:'utf8'}).includes(key.fingerprint))
  assert.deepEqual(resolveCredential({type:'key',keyId:key.id},[key]),{type:'key',privateKey:key.privateKey,passphrase})
  assert.throws(()=>resolveCredential({type:'key',keyId:randomUUID()},[key]),/не найден/)
 })
})

test('key deletion is blocked in main logic for all server states and inactive profiles; free key deletion persists',async()=>{
 await temporary(async(vault,controller)=>{
  await controller.generateSSHKey({name:'Production'})
  const data=vault.require(),key=data.sshKeys[0],p=data.profiles[0]
  const {server}=fixture();server.credential={type:'key',keyId:key.id};p.servers.push(server)
  await controller.addProfile('Other profile')
  for(const status of ['new','verified','ready','error','partial'] as Server['status'][]){
   server.status=status;await assert.rejects(controller.deleteSSHKey(key.id),/Нельзя удалить/)
   const state=await vault.publicState();assert.equal(state.sshKeys[0].canDelete,false)
   assert.equal(state.sshKeys[0].uses[0].profileId,p.id)
  }
  await vault.save();vault.lock();assert.deepEqual((await vault.publicState()).sshKeys,[])
  await vault.unlock(password);await assert.rejects(controller.deleteSSHKey(key.id),/Нельзя удалить/)
  await controller.generateSSHKey({name:'Unused'})
  const free=vault.require().sshKeys[1];assert.equal((await vault.publicState()).sshKeys[1].canDelete,true)
  await controller.deleteSSHKey(free.id);assert.equal(vault.require().sshKeys.length,1)
  const json=JSON.stringify(await vault.publicState());assert(!json.includes('PRIVATE KEY'));assert(!json.includes('privateKey'));assert(!json.includes('passphrase'))
  vault.lock();await vault.unlock(password);assert.equal(vault.require().sshKeys.length,1)
 })
})

test('legacy archives migrate inline keys once, deduplicate and retain cross-profile associations',async()=>{
 const key=await generateSSHKey('Legacy','legacy key passphrase');const {data,server}=fixture()
 server.credential={type:'key',privateKey:key.privateKey,passphrase:key.passphrase}
 const second={...structuredClone(server),id:randomUUID(),host:'198.51.100.28',name:'Second server'}
 data.profiles.push({id:randomUUID(),name:'Work',servers:[second],configs:[],routes:[]})
 // Simulate a pre-registry archive, which has no sshKeys field.
 delete (data as Partial<typeof data>).sshKeys
 const restored=await openSealed(await seal(data,password),password)
 assert.equal(restored.sshKeys.length,1);const stored=restored.sshKeys[0]
 assert.equal(stored.privateKey,key.privateKey);assert.equal(stored.fingerprint,key.fingerprint)
 assert.equal(keyUses(restored,stored.id).length,2)
 assert(restored.profiles.every(p=>p.servers.every(s=>s.credential.keyId===stored.id&&!s.credential.privateKey)))
 const again=await openSealed(await seal(restored,password),password)
 assert.equal(again.sshKeys[0].id,stored.id)
 const missing=structuredClone(again);missing.sshKeys=[];await assert.rejects(seal(missing,password))
 const corrupt=structuredClone(again);corrupt.sshKeys[0].publicKey=key.publicKey.replace('maNETka','incorrect')
 await assert.rejects(openSealed(await seal(corrupt,password),password),/повреждённое/)
})

test('password hardening journals and protects a key before remote IO; a retry reuses that key',async()=>{
 await temporary(async(vault,controller)=>{
  const {data}=fixture();await vault.replace(data);let server=vault.require().profiles[0].servers[0]
  // Simulate an interrupted SSH operation. No network connection is made.
  controller.withServer=async()=>{throw new Error('connection interrupted')}
  await assert.rejects(controller.secureCredential(server),/interrupted/)
  const id=server.pendingSshKeyId!;assert(id);assert.equal(vault.require().sshKeys.length,1)
  assert.equal(keyUses(vault.require(),id)[0].pending,true)
  assert(!(await readFile(vault.path,'utf8')).includes('PRIVATE KEY'))
  vault.lock();await vault.unlock(password);server=vault.require().profiles[0].servers[0]
  await assert.rejects(controller.deleteSSHKey(id),/Нельзя удалить/)
  await assert.rejects(controller.deleteServer(server.id,server.host,false),/очистите/)
  const scripts:string[]=[]
  controller.withServer=async(_s,fn)=>fn({exec:async(script:string)=>{scripts.push(script);return ''}} as never)
  await controller.secureCredential(server)
  assert.equal(vault.require().sshKeys.length,1);assert.equal(server.credential.keyId,id)
  assert.equal(server.pendingSshKeyId,undefined);assert.equal(scripts.length,2)
  assert(scripts[0].includes('/etc/manetka/owner'));assert(scripts[0].includes('authorized_keys'))
  execFileSync('sh',['-n'],{input:scripts[0]})
  await assert.rejects(controller.deleteSSHKey(id),/Нельзя удалить/)
 })
})

test('adding a server imports a pasted private key into the registry without duplication',async()=>{
 await temporary(async(vault,controller)=>{
  const key=await generateSSHKey('Manual')
  for(const [name,host] of [['A','198.51.100.51'],['B','198.51.100.52']])await controller.addServer({name,host,port:22,username:'root',credential:{type:'key',privateKey:key.privateKey}})
  assert.equal(vault.require().sshKeys.length,1)
  const stored=vault.require().sshKeys[0];assert.equal(keyUses(vault.require(),stored.id).length,2)
  await assert.rejects(controller.deleteSSHKey(stored.id),/Нельзя удалить/)
  await assert.rejects(controller.addServer({name:'Missing key',host:'198.51.100.53',port:22,username:'root',credential:{type:'key',keyId:randomUUID()}}),/не найден/)
 })
})
