import { test } from 'node:test'
import assert from 'node:assert/strict'
import ssh2 from 'ssh2'
const {Server:SshServer,utils}=ssh2
import { connect, probe, fingerprint } from '../electron/core/ssh'
import { fixture } from './fixtures'

test('SSH pins host key before authentication; raw stderr never reaches UI errors',async()=>{
 const pair=utils.generateKeyPairSync('ed25519')
 let authenticated=0
 const sshServer=new SshServer({hostKeys:[pair.private]},client=>{
  client.on('error',()=>{})
  client.on('authentication',ctx=>{authenticated++;ctx.accept()})
  client.on('ready',()=>client.on('session',accept=>{
   const session=accept();session.on('exec',(accept,reject,info)=>{
    assert.equal(info.command,'bash -se');const stream=accept();stream.on('data',()=>{});stream.on('end',()=>{stream.stderr.write('private-key-that-must-not-leak');stream.exit(1);stream.end()})
   })
  }))
 })
 await new Promise<void>(resolve=>sshServer.listen(0,'127.0.0.1',resolve))
 const address=sshServer.address();assert(address&&typeof address==='object')
 const {server}=fixture();server.host='127.0.0.1';server.port=address.port;server.fingerprint=undefined
 try{
  const fp=await probe(server);assert.match(fp,/^SHA256:/);assert.equal(authenticated,0)
  server.fingerprint='SHA256:'+'A'.repeat(43);await assert.rejects(connect(server),/ключ изменился/);assert.equal(authenticated,0)
  server.fingerprint=fp;const remote=await connect(server);assert.equal(authenticated,1)
  try{await assert.rejects(remote.exec('echo hello'),e=>e instanceof Error&&!e.message.includes('private-key')&&e.message.includes('код 1'))}finally{remote.close()}
 }finally{await new Promise<void>(resolve=>sshServer.close(()=>resolve()))}
})

test('SSH authenticates with a referenced encrypted Ed25519 key from the registry',async()=>{
 const {generateSSHKey}=await import('../electron/core/ssh-keys')
 const key=await generateSSHKey('Loopback deploy','loopback secret passphrase')
 const parsed=utils.parseKey(key.privateKey,key.passphrase);assert(!Array.isArray(parsed)&&!(parsed instanceof Error))
 const host=utils.generateKeyPairSync('ed25519');let verified=0
 const sshServer=new SshServer({hostKeys:[host.private]},client=>{
  client.on('error',()=>{})
  client.on('authentication',ctx=>{
   if(ctx.method!=='publickey'||ctx.key.algo!==key.algorithm||!ctx.key.data.equals(parsed.getPublicSSH()))return ctx.reject(['publickey'])
   if(ctx.signature&&parsed.verify(ctx.blob!,ctx.signature)!==true)return ctx.reject(['publickey'])
   if(ctx.signature)verified++
   ctx.accept()
  })
 })
 await new Promise<void>(resolve=>sshServer.listen(0,'127.0.0.1',resolve))
 const address=sshServer.address();assert(address&&typeof address==='object')
 const {server}=fixture();server.host='127.0.0.1';server.port=address.port;server.credential={type:'key',keyId:key.id}
 try{
  server.fingerprint=await probe(server)
  const remote=await connect(server,[key]);remote.close();assert.equal(verified,1)
  await assert.rejects(connect(server,[]),/не найден/)
 }finally{await new Promise<void>(resolve=>sshServer.close(()=>resolve()))}
})

test('real SSH channel delivers filtered installer messages before the command exits',async()=>{
 const pair=utils.generateKeyPairSync('ed25519');let finishCommand:(()=>void)|undefined
 const sshServer=new SshServer({hostKeys:[pair.private]},client=>{
  client.on('error',()=>{});client.on('authentication',ctx=>ctx.accept())
  client.on('ready',()=>client.on('session',accept=>accept().on('exec',accept=>{
   const stream=accept();stream.on('data',()=>{});stream.on('end',()=>{
    stream.write('Setting up wireguard-tools (1) ...\nPrivateKey = never-stream-me\n')
    stream.stderr.write('##### 43.0%\rprivate stderr must stay private\n')
    finishCommand=()=>{stream.exit(0);stream.end()}
   })
  })))
 })
 await new Promise<void>(resolve=>sshServer.listen(0,'127.0.0.1',resolve))
 const address=sshServer.address();assert(address&&typeof address==='object')
 const {server}=fixture();server.host='127.0.0.1';server.port=address.port
 const events:import('../src/model').Progress[]=[]
 let streamed!:()=>void;const outputSeen=new Promise<void>(resolve=>streamed=resolve)
 try{
  server.fingerprint=await probe(server)
  const remote=await connect(server,[],p=>{events.push(p);if(p.detail==='Загрузка: 43%')streamed()})
  try{
   let finished=false;const job=remote.exec('test installer',120000,{label:'Тестовая установка',output:'install'}).then(value=>{finished=true;return value})
   await outputSeen;assert.equal(finished,false);assert(finishCommand)
   assert(!JSON.stringify(events).includes('never-stream-me'));assert(!JSON.stringify(events).includes('private stderr'))
   finishCommand();await job;assert(events.some(p=>p.event==='command'&&p.state==='done'))
  }finally{remote.close()}
 }finally{await new Promise<void>(resolve=>sshServer.close(()=>resolve()))}
})
