import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Vault, seal, openSealed } from '../electron/core/vault'
import { fixture } from './fixtures'
const password='a long unique secret password'

test('AES-GCM round trip; fresh salt/nonce; no plaintext metadata',async()=>{
 const {data}=fixture();const a=await seal(data,password),b=await seal(data,password)
 assert.notEqual(a,b);assert(!a.includes('Private Helsinki'));assert(!a.includes('ssh-password'))
 assert.deepEqual(await openSealed(a,password),data)
})
test('rejects wrong password, changed ciphertext, IV, tag, and unsupported KDF',async()=>{
 const {data}=fixture();const raw=await seal(data,password)
 await assert.rejects(openSealed(raw,'wrong password'))
 for(const field of ['ciphertext','iv','tag']){const value=JSON.parse(raw);value[field]=(value[field][0]==='A'?'B':'A')+value[field].slice(1);await assert.rejects(openSealed(JSON.stringify(value),password))}
 const invalid=JSON.parse(raw);invalid.kdf='scrypt-1';await assert.rejects(openSealed(JSON.stringify(invalid),password))
})
test('atomic persisted vault, owner-only permissions, lock redacts all secrets, unlock restores',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'manetka-vault-'));const path=join(dir,'data','manetka.vault');const vault=new Vault(path)
 try{
  assert.equal(await vault.exists(),false);await vault.create(password);await vault.replace(fixture().data)
  const publicJson=JSON.stringify(await vault.publicState());assert(!publicJson.includes('ssh-password'));assert(!publicJson.includes('private-client-config'));assert(!publicJson.includes('privateKey'))
  assert.equal((await stat(path)).mode&0o777,0o600);assert.equal((await stat(join(dir,'data'))).mode&0o777,0o700)
  assert(!(await readFile(path,'utf8')).includes('Helsinki'))
  vault.lock();assert.throws(()=>vault.require(),/заблокировано/);assert.deepEqual((await vault.publicState()).profiles,[])
  await vault.unlock(password);assert.equal(vault.require().profiles[0].servers.length,1)
  await assert.rejects(vault.create(password),/существует/)
 }finally{vault.lock();await rm(dir,{recursive:true,force:true})}
})
test('archive validation refuses dangling route/config references and shell directives in imported keys',async()=>{
 const {data}=fixture();data.profiles[0].configs[0].serverId='00000000-0000-4000-8000-000000000000';await assert.rejects(seal(data,password))
 const f=fixture();f.server.protocols.wireguard!.privateKey='bad\nPostUp = touch /tmp/pwn';await assert.rejects(seal(f.data,password))
})
