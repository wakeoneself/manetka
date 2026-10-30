import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { PROTOCOLS } from '../src/model'
import { configInputSchema, provisionSchema, serverInputSchema, shellQuote } from '../electron/core/validation'
import { awgParameters, makeMaterial, vlessLink, wgClientConfig, wgServerConfig, x25519, xrayConfig } from '../electron/core/protocols'
import * as scripts from '../electron/core/scripts'
import { fixture } from './fixtures'

test('rejects shell injection, invalid IPv4, credentials and VPN ports',()=>{
 const {server}=fixture()
 const input={name:server.name,host:server.host,port:22,username:'root',credential:server.credential}
 assert(serverInputSchema.safeParse(input).success)
 for(const host of ['1.2.3.4; id','$(id)','-oProxyCommand=id','256.1.1.1','example.com','127.0.0.1\n'])assert(!serverInputSchema.safeParse({...input,host}).success)
 assert(!serverInputSchema.safeParse({...input,username:'root;id'}).success)
 assert(!provisionSchema.safeParse({serverId:server.id,protocol:'wireguard',port:65536,sni:'foo.com',domain:'',path:'/x',harden:true,dedicated:true}).success)
 assert(!configInputSchema.safeParse({name:'Phone',serverId:server.id,protocol:'wireguard',dns:'1.1.1.1\nPostUp = id',mtu:1280,allowedIPs:'0.0.0.0/0'}).success)
 const quoted=shellQuote("hello'$(id)`whoami`");const result=spawnSync('bash',['-c',`printf '%s' ${quoted}`],{encoding:'utf8'});assert.equal(result.stdout,"hello'$(id)`whoami`")
})
test('WireGuard and AmneziaWG server/client configs share parameters and use unique X25519 keypairs',()=>{
 const a=x25519(),b=x25519();assert.notEqual(a.privateKey,b.privateKey);assert.equal(Buffer.from(a.privateKey,'base64').length,32)
 const params=awgParameters();assert.equal(new Set([params.H1,params.H2,params.H3,params.H4]).size,4)
 const settings=makeMaterial('amneziawg',{port:51821,sni:'www.microsoft.com',domain:'',path:'/connect'})
 const serverConfig=wgServerConfig('amneziawg',settings,[]),clientConfig=wgClientConfig('amneziawg',settings,a,'10.78.0.2','192.0.2.14',51821,'1.1.1.1',1280,'0.0.0.0/0, ::/0')
 for(const [key,value] of Object.entries(settings.awg!)){assert(serverConfig.includes(`${key} = ${value}`));assert(clientConfig.includes(`${key} = ${value}`))}
 assert(clientConfig.includes('Endpoint = 192.0.2.14:51821'));assert(clientConfig.includes('::/0'));assert(!serverConfig.includes(a.privateKey))
})
test('Reality uses Vision; XHTTP and WebSocket never advertise Vision; WS binds only loopback',()=>{
 const {server}=fixture();for(const p of PROTOCOLS)server.protocols[p]=makeMaterial(p,{port:p==='vless-ws'?2053:443,sni:'www.microsoft.com',domain:'vpn.example.com',path:'/connect'})
 const configs=PROTOCOLS.filter(p=>p.startsWith('vless')).map(p=>({id:randomUUID(),name:'Phone & Router',serverId:server.id,protocol:p,clientId:randomUUID(),createdAt:new Date().toISOString(),content:'',revoked:false}))
 const cfg=xrayConfig(server,configs)
 for(const inbound of cfg.inbounds){assert.equal(inbound.settings.clients.length,1);if(inbound.tag==='vless-reality')assert.equal((inbound.settings.clients[0] as {flow?:string}).flow,'xtls-rprx-vision');else assert(!('flow' in inbound.settings.clients[0]));if(inbound.tag==='vless-ws')assert.equal(inbound.listen,'127.0.0.1')}
 for(const c of configs){const url=new URL(vlessLink(c.protocol,server.protocols[c.protocol]!,c.clientId!,c.name,'192.0.2.14',443));assert.equal(url.searchParams.get('flow'),c.protocol==='vless-reality'?'xtls-rprx-vision':null);assert.equal(decodeURIComponent(url.hash.slice(1)),c.name)}
})
test('generated shell scripts pass bash parsing; firewall preserves foreign tables and actual SSH port',()=>{
 const {server}=fixture();const scriptsToTest=[scripts.preflight(server),scripts.initialize(server),scripts.firewallScript(server,[],[server]),scripts.firewallRemove,scripts.hardeningScript(server),scripts.disablePasswordLoginScript(server),scripts.cleanupScript(server)]
 for(const script of scriptsToTest){const result=spawnSync('bash',['-n'],{input:script,encoding:'utf8'});assert.equal(result.status,0,result.stderr)}
 const firewall=scripts.firewallScript(server,[],[server]);assert(firewall.includes('--dport 2222'));assert(!/iptables\s+-F\s+INPUT/.test(firewall));assert(!firewall.includes('flush ruleset'));assert(firewall.includes('MN_INPUT -j DROP'));assert(firewall.includes('ip6tables'))
 const cleanup=scripts.cleanupScript(server);assert(cleanup.includes(server.ownerId));assert(!cleanup.includes('rm -rf /root'));assert(!cleanup.includes('shred /dev'))
})

test('SSH password check drains large output under pipefail and still rejects invalid settings and producer errors',()=>{
 const dir=mkdtempSync(join(tmpdir(),'manetka-sshd-check-'));const path=join(dir,'sshd-output')
 const tail='hostkeyalgorithms ssh-ed25519,ssh-rsa\n'.repeat(200000)
 const check=scripts.passwordAuthenticationCheck.replace('/usr/sbin/sshd -T','cat "$SSHD_OUTPUT"')
 const run=(script:string)=>spawnSync('bash',['-se'],{input:'set -euo pipefail\n'+script+'\nprintf passed',encoding:'utf8',env:{...process.env,SSHD_OUTPUT:path}})
 try{
  writeFileSync(path,'passwordauthentication no\n'+tail)
  const old=run('cat "$SSHD_OUTPUT" | grep -q "^passwordauthentication no$"');assert.equal(old.status,141)
  const fixed=run(check);assert.equal(fixed.status,0,fixed.stderr);assert.equal(fixed.stdout,'passed')
  for(const setting of ['passwordauthentication yes','passwordauthentication nobody','unrelated no']){
   writeFileSync(path,setting+'\n'+tail);assert.equal(run(check).status,1)
  }
  // Matching output does not conceal an actual failure in sshd itself.
  const failedProducer=scripts.passwordAuthenticationCheck.replace('/usr/sbin/sshd -T',"(printf 'passwordauthentication no\\n'; exit 42)")
  assert.equal(run(failedProducer).status,42)
 }finally{rmSync(dir,{recursive:true,force:true})}
})
