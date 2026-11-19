import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { createSocket } from 'node:dgram'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import type { Route, Server, VpnConfig } from '../src/model'
import { hysteriaConfig, hysteriaLink, hysteriaSecret, makeMaterial, shadowsocksLink, SS_METHOD, userSecret, xrayConfig } from '../electron/core/protocols'
import * as scripts from '../electron/core/scripts'
import { routeInputSchema, vaultDataSchema } from '../electron/core/validation'
import { shimGoMod, shimSource } from '../electron/core/shim'
import { fixture } from './fixtures'

const opts={port:8388,sni:'www.microsoft.com',domain:'',path:'/x'}
const cfg=(server:Server,protocol:VpnConfig['protocol'],extra:Partial<VpnConfig>):VpnConfig=>({id:randomUUID(),name:'d',serverId:server.id,protocol,createdAt:new Date().toISOString(),content:'x',revoked:false,...extra})
const bash=(script:string)=>assert.equal(spawnSync('bash',['-n'],{input:script,encoding:'utf8'}).status,0)

test('Shadowsocks 2022: multi-user Xray inbound and SIP022 link',()=>{
  const {server}=fixture();server.protocols.shadowsocks=makeMaterial('shadowsocks',opts)
  const key=userSecret(),c=cfg(server,'shadowsocks',{secret:key}),revoked=cfg(server,'shadowsocks',{secret:userSecret(),revoked:true})
  assert.equal(Buffer.from(server.protocols.shadowsocks.privateKey!,'base64').length,32)
  const ib=xrayConfig(server,[c,revoked]).inbounds.find(i=>i.protocol==='shadowsocks') as unknown as {settings:{method:string;network:string;clients:{password:string}[]}}
  assert.equal(ib.settings.method,SS_METHOD);assert.equal(ib.settings.network,'tcp,udp');assert.deepEqual(ib.settings.clients.map(x=>x.password),[key])
  const link=shadowsocksLink(server.protocols.shadowsocks,key,'Phone & Co',server.host,8388)
  const url=new URL(link);assert.equal(url.hostname,server.host);assert.equal(url.port,'8388')
  assert.equal(decodeURIComponent(url.username)+':'+decodeURIComponent(url.password),`${SS_METHOD}:${server.protocols.shadowsocks.privateKey}:${key}`.replace(`${SS_METHOD}:`,SS_METHOD+':'))
})
test('Hysteria 2: config lists only active users, blocks private ranges; link carries pin and obfs',()=>{
  const {server}=fixture();server.protocols.hysteria2=makeMaterial('hysteria2',{...opts,port:8444});server.protocols.hysteria2.certPin='a'.repeat(64)
  const a=cfg(server,'hysteria2',{clientId:randomUUID(),secret:hysteriaSecret()}),b=cfg(server,'hysteria2',{clientId:randomUUID(),secret:hysteriaSecret(),revoked:true})
  const yaml=hysteriaConfig(server,[a,b],'/etc/manetka/hysteria')
  assert(yaml.includes(`"${a.clientId}": "${a.secret}"`));assert(!yaml.includes(b.clientId!));assert(yaml.includes('listen: ":8444"'));assert(yaml.includes('reject(10.0.0.0/8)'));assert(yaml.includes('type: salamander'))
  const u=new URL(hysteriaLink(server.protocols.hysteria2,a.clientId!,a.secret!,'Phone',server.host,8444))
  assert.equal(u.protocol,'hysteria2:');assert.equal(u.searchParams.get('pinSHA256'),'a'.repeat(64));assert.equal(u.searchParams.get('obfs-password'),server.protocols.hysteria2.obfs);assert.equal(u.username,a.clientId)
  assert(!hysteriaConfig(server,[],'/d').includes('undefined'))
})
test('firewall: dual-transport ports, DNAT per transport, shim rules on both ends',()=>{
  const {server:exit}=fixture();exit.protocols.shadowsocks=makeMaterial('shadowsocks',opts)
  const entry:Server={...exit,id:randomUUID(),host:'203.0.113.9',protocols:{}}
  const base={id:randomUUID(),name:'r',entryId:entry.id,exitId:exit.id,status:'ready' as const,createdAt:new Date().toISOString()}
  const fwd:Route={...base,protocol:'shadowsocks',port:9000,mode:'forward'}
  const exitFw=scripts.firewallScript(exit,[],[exit,entry]);assert(exitFw.includes('-p tcp --dport 8388')&&exitFw.includes('-p udp --dport 8388'))
  const entryFw=scripts.firewallScript(entry,[fwd],[exit,entry]);assert((entryFw.match(/DNAT/g)??[]).length===2)
  const stun:Route={...base,protocol:'wireguard',port:51820,mode:'stun',shimPort:3478}
  const e2=scripts.firewallScript(entry,[stun],[exit,entry]);assert(!e2.includes('DNAT'));assert(e2.includes('-p udp --dport 51820 -j ACCEPT'))
  const x2=scripts.firewallScript(exit,[stun],[exit,entry]);assert(x2.includes("-p udp -s '203.0.113.9' --dport 3478 -j ACCEPT"))
  for(const s of [entryFw,e2,x2,scripts.cleanupScript(exit)])bash(s)
  for(const unit of [scripts.hysteriaUnit(exit),scripts.shimUnit(entry,'entry',51820,'1.2.3.4:3478')])assert(unit.includes('ExecStart='))
  assert(scripts.cleanupScript(exit).includes('-shim-'))
})
test('route and vault schemas accept shim routes only for WireGuard-family protocols',()=>{
  const base={name:'r',entryId:randomUUID(),exitId:randomUUID(),port:51820}
  assert(routeInputSchema.safeParse({...base,protocol:'wireguard',mode:'stun',shimPort:3478}).success)
  assert(!routeInputSchema.safeParse({...base,protocol:'wireguard',mode:'stun'}).success)
  assert(!routeInputSchema.safeParse({...base,protocol:'hysteria2',mode:'stun',shimPort:3478}).success)
  const {data,server}=fixture();server.protocols.hysteria2=makeMaterial('hysteria2',{...opts,port:8444});server.protocols.hysteria2.certPin='b'.repeat(64)
  server.protocols.shadowsocks=makeMaterial('shadowsocks',opts)
  data.profiles[0].configs.push(cfg(server,'shadowsocks',{secret:userSecret()}),cfg(server,'hysteria2',{clientId:randomUUID(),secret:hysteriaSecret()}))
  assert(vaultDataSchema.safeParse(data).success)
})
test('UDP shim wraps with an 8-byte STUN-like header and unwraps end to end',{skip:spawnSync('go',['version']).status!==0},async()=>{
  const dir=mkdtempSync(join(tmpdir(),'manetka-shim-'));const procs:ReturnType<typeof spawn>[]=[]
  try {
    writeFileSync(join(dir,'main.go'),shimSource);writeFileSync(join(dir,'go.mod'),shimGoMod)
    assert.equal(spawnSync('go',['build','-o','shim','.'],{cwd:dir,env:{...process.env,GOFLAGS:'-mod=mod'}}).status,0)
    const echo=createSocket('udp4');const seen:Buffer[]=[]
    await new Promise<void>(r=>echo.bind(0,'127.0.0.1',r));echo.on('message',(m,i)=>{seen.push(m);echo.send(m,i.port,i.address)})
    const eport=echo.address().port
    const free=async()=>{const s=createSocket('udp4');await new Promise<void>(r=>s.bind(0,'127.0.0.1',r));const p=s.address().port;s.close();return p}
    const [xp,np]=[await free(),await free()]
    // Capture what crosses the inter-server link between the shims.
    const mid=createSocket('udp4');await new Promise<void>(r=>mid.bind(0,'127.0.0.1',r));const wire:Buffer[]=[]
    const mp=mid.address().port
    procs.push(spawn(join(dir,'shim'),['-mode','exit','-listen',`127.0.0.1:${xp}`,'-target',`127.0.0.1:${eport}`]))
    procs.push(spawn(join(dir,'shim'),['-mode','entry','-listen',`127.0.0.1:${np}`,'-target',`127.0.0.1:${mp}`]))
    let exitAddr=0;mid.on('message',(m,i)=>{wire.push(m);const s=createSocket('udp4');s.send(m,xp,'127.0.0.1');s.on('message',r=>{mid.send(r,i.port,i.address);s.close()});exitAddr++})
    await new Promise(r=>setTimeout(r,300))
    const client=createSocket('udp4');const payload=Buffer.alloc(1200,7)
    // The first run of a freshly built binary can be slow to start, so resend until the first reply.
    let timer:NodeJS.Timeout|undefined,limit:NodeJS.Timeout|undefined
    const reply=await new Promise<Buffer>((res,rej)=>{client.once('message',res);timer=setInterval(()=>client.send(payload,np,'127.0.0.1'),400);limit=setTimeout(()=>rej(new Error('no reply')),10000)}).finally(()=>{clearInterval(timer);clearTimeout(limit)})
    await new Promise(r=>setTimeout(r,300));const before=seen.length
    assert.deepEqual(reply,payload);assert.deepEqual(seen[0],payload)
    assert.equal(wire[0].length,payload.length+8);assert.deepEqual([...wire[0].subarray(0,8)],[0,1,1200>>8,1200&255,0x21,0x12,0xa4,0x42]);assert(exitAddr>0)
    // Datagrams without the header are dropped by the exit shim.
    const raw=createSocket('udp4');raw.send(payload,xp,'127.0.0.1');await new Promise(r=>setTimeout(r,300));assert.equal(seen.length,before)
    client.close();raw.close();echo.close();mid.close()
  } finally {for(const p of procs)p.kill();rmSync(dir,{recursive:true,force:true})}
})
