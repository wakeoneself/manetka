import { generateKeyPairSync, randomBytes, randomInt } from 'node:crypto'
import type { Protocol, ProtocolSettings, Server, VpnConfig } from '../../src/model'

export function x25519(): {privateKey:string;publicKey:string} {
  const pair=generateKeyPairSync('x25519')
  const privateJwk=pair.privateKey.export({format:'jwk'}), publicJwk=pair.publicKey.export({format:'jwk'})
  return {privateKey:Buffer.from(privateJwk.d!,'base64url').toString('base64'),publicKey:Buffer.from(publicJwk.x!,'base64url').toString('base64')}
}
export function awgParameters() { return {Jc:randomInt(4,9),Jmin:40,Jmax:70,S1:randomInt(80,120),S2:randomInt(40,80),H1:randomInt(1e6,1e8),H2:randomInt(1e8,2e8),H3:randomInt(2e8,3e8),H4:randomInt(3e8,4e8)} }
export function makeMaterial(protocol:Protocol,opts:{port:number;sni:string;domain:string;path:string}):ProtocolSettings {
  const pair=x25519()
  return {port:opts.port,sni:opts.sni,domain:opts.domain,path:opts.path,mtu:1280,dns:'1.1.1.1, 1.0.0.1',privateKey:protocol.startsWith('vless')?Buffer.from(pair.privateKey,'base64').toString('base64url'):pair.privateKey,publicKey:protocol.startsWith('vless')?Buffer.from(pair.publicKey,'base64').toString('base64url'):pair.publicKey,...(protocol==='amneziawg'?{awg:awgParameters()}:{}),shortId:randomBytes(8).toString('hex')}
}
export const iface=(protocol:Protocol) => protocol==='wireguard'?'mnwg0':'mnawg0'
export const subnet=(protocol:Protocol) => protocol==='wireguard'?'10.77.0':'10.78.0'
export function wgServerConfig(protocol:Protocol,settings:ProtocolSettings,configs:VpnConfig[]):string {
  return ['[Interface]',`PrivateKey = ${settings.privateKey}`,`Address = ${subnet(protocol)}.1/24`,`ListenPort = ${settings.port}`,`MTU = ${settings.mtu}`,...Object.entries(settings.awg??{}).map(([k,v])=>`${k} = ${v}`),'',...configs.filter(c=>c.protocol===protocol&&!c.revoked).flatMap(c=>['[Peer]',`PublicKey = ${c.publicKey}`,`AllowedIPs = ${c.address}/32`,''])].join('\n')
}
export function wgClientConfig(protocol:Protocol,settings:ProtocolSettings,pair:{privateKey:string},address:string,host:string,port:number,dns:string,mtu:number,allowed:string):string {
  // IPv6 is routed into the tunnel and intentionally dropped on this IPv4-only server,
  // preventing native IPv6 bypass for the default full-tunnel profile.
  return ['[Interface]',`PrivateKey = ${pair.privateKey}`,`Address = ${address}/32, fd77:77::${Number(address.split('.').at(-1)).toString(16)}/128`,`DNS = ${dns}`,`MTU = ${mtu}`,...Object.entries(settings.awg??{}).map(([k,v])=>`${k} = ${v}`),'','[Peer]',`PublicKey = ${settings.publicKey}`,`Endpoint = ${host}:${port}`,`AllowedIPs = ${allowed}`,'PersistentKeepalive = 25',''].join('\n')
}
export function xrayConfig(server:Server,configs:VpnConfig[]) {
  const inbounds=Object.entries(server.protocols).filter(([p])=>p.startsWith('vless')).map(([p,s])=>({
    tag:p,listen:p==='vless-ws'?'127.0.0.1':'0.0.0.0',port:p==='vless-ws'?18080:s.port,protocol:'vless',
    settings:{decryption:'none',clients:configs.filter(c=>c.protocol===p&&!c.revoked).map(c=>({id:c.clientId,...(p==='vless-reality'?{flow:'xtls-rprx-vision'}:{})}))},
    streamSettings:{network:p==='vless-xhttp'?'xhttp':p==='vless-ws'?'ws':'tcp',security:p==='vless-ws'?'none':'reality',...(p==='vless-ws'?{wsSettings:{path:s.path}}:{realitySettings:{show:false,target:`${s.sni}:443`,xver:0,serverNames:[s.sni],privateKey:s.privateKey,shortIds:[s.shortId]},...(p==='vless-xhttp'?{xhttpSettings:{path:s.path,mode:'auto'}}:{})})}
  }))
  return {log:{loglevel:'warning',access:'none'},inbounds,outbounds:[{protocol:'freedom',tag:'direct'},{protocol:'blackhole',tag:'block'}],routing:{rules:[{type:'field',ip:['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','169.254.0.0/16','100.64.0.0/10','::1/128','fc00::/7','fe80::/10'],outboundTag:'block'}]}}
}
export function vlessLink(protocol:Protocol,settings:ProtocolSettings,clientId:string,name:string,host:string,port:number):string {
  const params=new URLSearchParams({encryption:'none',type:protocol==='vless-xhttp'?'xhttp':protocol==='vless-ws'?'ws':'tcp',security:protocol==='vless-ws'?'tls':'reality',sni:protocol==='vless-ws'?settings.domain:settings.sni,fp:'chrome'})
  if(protocol==='vless-ws'){params.set('host',settings.domain);params.set('path',settings.path)}
  else {params.set('pbk',settings.publicKey!);params.set('sid',settings.shortId!);if(protocol==='vless-reality')params.set('flow','xtls-rprx-vision');else{params.set('path',settings.path);params.set('mode','auto')}}
  return `vless://${clientId}@${host}:${port}?${params}#${encodeURIComponent(name)}`
}
