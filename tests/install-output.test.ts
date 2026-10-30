import {test} from 'node:test'
import assert from 'node:assert/strict'
import {InstallerOutput,installerMessage} from '../electron/core/install-output'

test('installer log accepts recognised progress, not arbitrary stdout, configs or secret-bearing errors',()=>{
 assert.equal(installerMessage('Setting up wireguard-tools (1.0.20210914-1) ...'),'Установка: wireguard-tools')
 assert.equal(installerMessage('  ####### 31.5%'),'Загрузка: 31%')
 assert.equal(installerMessage('go: downloading golang.org/x/sys v0.20.0'),'Go: загрузка golang.org/x/sys v0.20.0')
 for(const line of ['passwordhunter2','-----BEGIN OPENSSH PRIVATE KEY-----','PrivateKey = secret','vless://private-client-id@host','{"privateKey":"abc"}','sshd: bad secret private config','https://user:password@example.com','\x1b]0;Setting up secret\x07','Setting up package\x00secret','curl: (22) https://user:password@example.com']){
  const message=installerMessage(line)
  assert(!message||message==='Ошибка загрузки: curl, код 22',line)
 }
 assert.equal(installerMessage('101.2%'),undefined)
})

test('installer stream handles split lines, CR download meters, UTF-8, oversize lines and rate limits',()=>{
 const rows:string[]=[];let now=10000;const parser=new InstallerOutput(line=>rows.push(line),()=>now)
 const bytes=Buffer.from('Setting up wireguard-tools (1) ...\n##### 10.5%\r##### 11.0%\rсекрет\n')
 for(const byte of bytes)parser.push(Buffer.from([byte]))
 assert.deepEqual(rows,['Установка: wireguard-tools','Загрузка: 10%','Загрузка: 11%'])
 parser.push(Buffer.from('x'.repeat(100000)+'Setting up secret\nSetting up iptables (1) ...\n'));assert.equal(rows.at(-1),'Установка: iptables')
 for(let i=0;i<2000;i++)parser.push(Buffer.from(`Setting up package-${i} (1) ...\n`))
 assert(rows.length<=13);assert.equal(rows.at(-1),'Частые сообщения объединены; выполнение продолжается')
 now+=1000;parser.push(Buffer.from('Setting up curl (1) ...'));parser.end();assert.equal(rows.at(-1),'Установка: curl')
 assert(!JSON.stringify(rows).includes('секрет'))
})

import { EventEmitter } from 'node:events'
import { Remote } from '../electron/core/ssh'
import type { Client } from 'ssh2'
import type { Progress } from '../src/model'
class Channel extends EventEmitter {
 stderr=new EventEmitter()
 input=''
 end(script:string){this.input=script}
 close(){this.emit('close',1)}
}
function remoteFixture(){
 const channel=new Channel(),events:Progress[]=[]
 const conn={exec:(_command:string,callback:(error:null,channel:Channel)=>void)=>callback(null,channel),end:()=>{channel.emit('close',null)}}
 return {channel,events,remote:new Remote(conn as unknown as Client,p=>events.push(p))}
}
test('SSH streams filtered stdout/stderr before completion and leaves secret commands unexposed',async()=>{
 const {channel,events,remote}=remoteFixture()
 const job=remote.exec('private shell secret',120000,{label:'Установка пакетов',output:'install'})
 channel.emit('data',Buffer.from('Setting up wireguard-tools (1) ...\nPrivateKey = stdout-secret\n'))
 channel.stderr.emit('data',Buffer.from('#### 20.0%\rsecret-from-stderr\n'))
 assert.equal(events.filter(p=>p.event==='output').length,2)
 assert(!events.some(p=>p.state==='done'));assert(events.some(p=>p.detail==='Загрузка: 20%'))
 channel.emit('close',0);await job
 assert(events.some(p=>p.state==='done'));assert(!JSON.stringify(events).includes('secret'))
 const plain=remoteFixture();const second=plain.remote.exec('cat /private/config')
 plain.channel.emit('data',Buffer.from('Setting up this-could-be-a-secret (1) ...\n'))
 plain.channel.stderr.emit('data',Buffer.from('curl: (22) secret'))
 plain.channel.emit('close',0);assert((await second).includes('this-could-be-a-secret'))
 assert(!plain.events.some(p=>p.event==='output'))
})
test('SSH drains more than the result limit without killing the remote command; failures retain a generic error',async()=>{
 const {channel,events,remote}=remoteFixture();const job=remote.exec('command')
 channel.emit('data',Buffer.alloc(2*1024*1024,65));channel.emit('close',0)
 assert.equal((await job).length,1024*1024);assert.equal(events.at(-1)?.state,'done')
 const failed=remoteFixture();const rejection=assert.rejects(failed.remote.exec('command'),/код 17/)
 failed.channel.stderr.emit('data',Buffer.from('private-secret-error'));failed.channel.emit('close',17);await rejection
 assert.equal(failed.events.at(-1)?.state,'failed');assert(!JSON.stringify(failed.events).includes('private-secret'))
})
test('quiet SSH commands send bounded heartbeat metadata and stop timers on completion',async t=>{
 t.mock.timers.enable({apis:['setInterval','setTimeout','Date'],now:10000})
 const {channel,events,remote}=remoteFixture();const job=remote.exec('quiet command',30000)
 t.mock.timers.tick(10000)
 assert.equal(events.filter(p=>p.event==='heartbeat').length,2)
 assert.equal(events.at(-1)?.silentMs,10000)
 channel.emit('close',0);await job
 const count=events.length;t.mock.timers.tick(60000);assert.equal(events.length,count)
 t.mock.timers.reset()
})
test('SSH timeout clears heartbeat and reports failure rather than success',async t=>{
 t.mock.timers.enable({apis:['setInterval','setTimeout','Date'],now:10000})
 const {events,remote}=remoteFixture();const pending=assert.rejects(remote.exec('quiet command',11000),/Время операции/)
 t.mock.timers.tick(11000);await pending
 assert.equal(events.at(-1)?.state,'failed');const count=events.length
 t.mock.timers.tick(60000);assert.equal(events.length,count);t.mock.timers.reset()
})
