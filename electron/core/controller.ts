import { randomUUID } from 'node:crypto'
import type { ConfigInput, Profile, Progress, Protocol, ProvisionInput, RouteInput, Server, ServerInput, SSHKeyInput, VpnConfig } from '../../src/model'
import { protocolInfo } from '../../src/model'
import { Vault } from './vault'
import { configInputSchema, fingerprintSchema, idSchema, nameSchema, provisionSchema, routeInputSchema, serverInputSchema, sshKeyInputSchema, shellQuote as q } from './validation'
import { probe, withRemote, type Remote } from './ssh'
import { describePrivateKey, generateSSHKey, keyUses } from './ssh-keys'
import { applyConfigs, inspect, provision, updateFirewall, validatePorts } from './provision'
import { cleanupScript, initialize, ownerCheck, preflight } from './scripts'
import { resourceNamespace } from './resource-namespace'
import { makeMaterial, subnet, vlessLink, wgClientConfig, x25519 } from './protocols'

export class Controller {
  busy?: string
  readonly log:(p:Progress)=>void
  constructor(readonly vault:Vault,send:(p:Progress)=>void) {this.log=p=>send({...p,at:p.at??new Date().toISOString()})}
  profile():Profile {const d=this.vault.require();return d.profiles.find(p=>p.id===d.activeProfileId)!}
  server(id:string):Server {idSchema.parse(id);const s=this.profile().servers.find(s=>s.id===id);if(!s)throw new Error('Сервер не найден');return s}
  config(id:string):VpnConfig {idSchema.parse(id);const c=this.profile().configs.find(c=>c.id===id);if(!c)throw new Error('Конфиг не найден');return c}
  sshKey(id:string) {idSchema.parse(id);const key=this.vault.require().sshKeys.find(k=>k.id===id);if(!key)throw new Error('SSH-ключ не найден');return key}
  withServer<T>(server:Server,fn:(remote:Remote)=>Promise<T>) {return withRemote(server,fn,this.vault.require().sshKeys,this.log)}
  async generateSSHKey(raw:SSHKeyInput) {
    const input=sshKeyInputSchema.parse(raw)
    const key=await generateSSHKey(input.name,input.passphrase)
    this.vault.require().sshKeys.push(key)
    await this.audit('Сгенерирован SSH-ключ')
  }
  async deleteSSHKey(id:string) {
    this.sshKey(id)
    if(keyUses(this.vault.require(),id).length)throw new Error('Нельзя удалить SSH-ключ, связанный с сервером. Сначала удалите связанные серверы. Отсутствие связи не снимает защиту.')
    const data=this.vault.require();const previous=data.sshKeys
    data.sshKeys=previous.filter(k=>k.id!==id)
    try {await this.audit('Удалён свободный SSH-ключ')} catch(e) {data.sshKeys=previous;throw e}
  }
  async audit(action:string) {const d=this.vault.require();d.audit.unshift({id:randomUUID(),at:new Date().toISOString(),action});d.audit=d.audit.slice(0,500);await this.vault.save()}
  async transaction<T>(name:string,fn:()=>Promise<T>):Promise<T> {
    if(this.busy)throw new Error('Дождитесь завершения текущей операции')
    this.busy=name
    const tracked=['provision','repairServer','createRoute','deleteRoute','createConfig','revokeConfig','checkServer','deleteServer'].includes(name)
    if(tracked)this.log({event:'operation',step:'Начало',detail:'Подготовка операции и SSH-подключения',kind:'info',state:'running'})
    try{const value=await fn();if(tracked)this.log({event:'operation',step:'Завершено',detail:'Операция завершена',kind:'ok',state:'done'});return value}
    catch(error){if(tracked)this.log({event:'operation',step:'Операция прервана',detail:'Проверьте сообщение об ошибке перед повтором',kind:'error',state:'failed'});throw error}
    finally{this.busy=undefined}
  }
  async addProfile(name:string) {name=nameSchema.parse(name);const d=this.vault.require();const id=randomUUID();d.profiles.push({id,name,servers:[],configs:[],routes:[]});d.activeProfileId=id;await this.audit('Создан профиль');}
  async switchProfile(id:string) {idSchema.parse(id);const d=this.vault.require();if(!d.profiles.some(p=>p.id===id))throw new Error('Профиль не найден');d.activeProfileId=id;await this.vault.save()}
  async addServer(raw:ServerInput) {
    const input=serverInputSchema.parse(raw)
    if(this.vault.require().profiles.some(p=>p.servers.some(s=>s.host===input.host)))throw new Error('Этот IP уже добавлен в одном из профилей. Один VPS управляется одной записью.')
    if(input.credential.type==='key') {
      if(input.credential.keyId)this.sshKey(input.credential.keyId)
      else {
        const details=describePrivateKey(input.credential.privateKey!,input.credential.passphrase)
        const keys=this.vault.require().sshKeys
        let key=keys.find(k=>k.fingerprint===details.fingerprint)
        if(!key){key={id:randomUUID(),name:`${input.name.slice(0,72)} · SSH`,...details,privateKey:input.credential.privateKey!,...(input.credential.passphrase?{passphrase:input.credential.passphrase}:{}),createdAt:new Date().toISOString()};keys.push(key)}
        input.credential={type:'key',keyId:key.id}
      }
    }
    this.profile().servers.push({...input,id:randomUUID(),status:'new',protocols:{},managed:false,ownerId:randomUUID(),resourceNamespace:'manetka'})
    await this.audit('Добавлен сервер')
  }
  async probeServer(id:string) {return {fingerprint:await probe(this.server(id))}}
  async trustServer(id:string,value:string) {
    const s=this.server(id);const fp=fingerprintSchema.parse(value)
    // A pinned key cannot be replaced silently by a new candidate.
    if(s.fingerprint&&s.fingerprint!==fp)throw new Error('SSH-ключ отличается от сохранённого. Добавьте сервер заново после проверки у провайдера.')
    const observed=await probe(s)
    if(observed!==fp)throw new Error('Fingerprint не совпадает с текущим ключом сервера')
    s.fingerprint=fp;await this.audit('Подтверждён SSH-ключ')
  }
  async checkServer(id:string) {
    const s=this.server(id)
    try{await inspect(s,this.vault.require().sshKeys,this.log);await this.audit('Проверено состояние сервера')}catch(e){s.status='error';await this.vault.save();throw e}
  }
  async secureCredential(server:Server) {
    if(server.credential.type==='key')return
    this.log({step:'SSH-ключ',detail:'Сохранение ключа и проверка нового SSH-входа',kind:'info'})
    let key=server.pendingSshKeyId?this.sshKey(server.pendingSshKeyId):undefined
    if(!key){key=await generateSSHKey(`${server.name.slice(0,72)} · SSH`);this.vault.require().sshKeys.push(key);server.pendingSshKeyId=key.id;await this.audit('Сохранён SSH-ключ перед установкой на сервер')}
    const ns=resourceNamespace(server)
    const line=key.publicKey+' '+ns+'-'+server.ownerId
    await this.withServer(server,r=>r.exec(`${ownerCheck(server)}\ninstall -d -m 711 /etc/${ns}\nif [ ! -f /etc/${ns}/owner ]; then printf '%s' ${q(server.ownerId)} > /etc/${ns}/owner; fi\ntest ! -L /root/.ssh\ninstall -d -m 700 /root/.ssh\ntest ! -L /root/.ssh/authorized_keys\ntouch /root/.ssh/authorized_keys\nchmod 600 /root/.ssh/authorized_keys\ngrep -qF -- ${q(line)} /root/.ssh/authorized_keys || printf '%s\\n' ${q(line)} >> /root/.ssh/authorized_keys`))
    const next={...server,credential:{type:'key' as const,keyId:key.id}}
    // Verify a fresh key login before persisting the replacement and disabling passwords.
    await this.withServer(next,r=>r.exec('true',120000,{label:'Проверка нового SSH-входа'}))
    server.credential=next.credential
    delete server.pendingSshKeyId
    await this.audit('Создан и проверен отдельный SSH-ключ maNETka')
  }
  async provision(raw:ProvisionInput) {
    const input=provisionSchema.parse(raw);const s=this.server(input.serverId);const profile=this.profile()
    if(!s.fingerprint||!s.os)throw new Error('Сначала проверьте SSH-доступ и систему')
    if(s.protocols[input.protocol])throw new Error('Этот протокол уже добавлен. При незавершённой установке используйте восстановление.')
    const transport=protocolInfo[input.protocol].transport
    if(Object.entries(s.protocols).some(([p,c])=>c.port===input.port&&protocolInfo[p as Protocol].transport===transport)||profile.routes.some(r=>r.entryId===s.id&&r.port===input.port&&protocolInfo[r.protocol].transport===transport))throw new Error('Порт занят другим протоколом или мостом')
    if(input.protocol==='vless-ws'&&s.protocols['vless-reality']?.port===443)throw new Error('Для WebSocket порт 443 нужен Caddy. Перенесите REALITY на другой сервер.')
    if(s.protocols['vless-ws']&&transport==='tcp'&&[80,443,18080].includes(input.port))throw new Error('Порт зарезервирован TLS-службой')
    await this.withServer(s,r=>validatePorts(r,s,[{port:input.port,transport}]))
    s.protocols[input.protocol]=makeMaterial(input.protocol,input);s.status='partial';s.hardened=input.harden
    // Persist keys and intent before touching the VPS. A crash leaves a recoverable record.
    await this.audit('Начата установка '+protocolInfo[input.protocol].name)
    try{if(input.harden)await this.secureCredential(s);await provision(s,profile,input.protocol,input.harden,this.log,this.vault.require().sshKeys);s.managed=true;s.status='ready';s.checkedAt=new Date().toISOString();await this.audit('Установлен '+protocolInfo[input.protocol].name)}catch(e){s.status='partial';await this.vault.save();throw e}
  }
  async repairServer(id:string) {
    const s=this.server(id);if(!Object.keys(s.protocols).length)throw new Error('Нет протоколов для восстановления')
    await inspect({...s,protocols:{}},this.vault.require().sshKeys,this.log)
    if(s.hardened)await this.secureCredential(s)
    for(const p of Object.keys(s.protocols) as Protocol[])await provision(s,this.profile(),p,!!s.hardened,this.log,this.vault.require().sshKeys)
    s.managed=true;s.status='ready';await this.audit('Восстановлены настройки сервера')
  }
  async createConfig(raw:ConfigInput) {
    const input=configInputSchema.parse(raw);const s=this.server(input.serverId);const profile=this.profile();const settings=s.protocols[input.protocol]
    if(s.status!=='ready'||!settings)throw new Error('Этот протокол ещё не готов на сервере')
    const route=input.routeId?profile.routes.find(r=>r.id===input.routeId):undefined
    if(input.routeId&&(!route||route.exitId!==s.id||route.protocol!==input.protocol||route.status!=='ready'))throw new Error('Маршрут не поддерживает выбранный протокол')
    const entry=route?this.server(route.entryId):s;const port=route?route.port:settings.port
    if(input.protocol==='vless-ws'&&route)throw new Error('Для TLS/CDN используйте прямой домен: L4-мост для WebSocket пока не поддержан')
    const c:VpnConfig={id:randomUUID(),name:input.name,serverId:s.id,protocol:input.protocol,routeId:route?.id,createdAt:new Date().toISOString(),content:'',revoked:false}
    if(input.protocol.startsWith('vless')){c.clientId=randomUUID();c.content=vlessLink(input.protocol,settings,c.clientId,c.name,input.protocol==='vless-ws'?settings.domain:entry.host,port)}
    else {
      const used=new Set(profile.configs.filter(c=>c.serverId===s.id&&c.protocol===input.protocol&&!c.revoked).map(c=>c.address))
      let last=2;while(used.has(`${subnet(input.protocol)}.${last}`))last++
      if(last>254)throw new Error('Достигнут лимит 253 активных устройств на протокол')
      const pair=x25519();c.publicKey=pair.publicKey;c.address=`${subnet(input.protocol)}.${last}`;c.content=wgClientConfig(input.protocol,settings,pair,c.address,entry.host,port,input.dns,input.mtu,input.allowedIPs)
    }
    profile.configs.push(c);s.status='partial';await this.audit('Начато создание конфига')
    try{await this.withServer(s,async r=>{await r.exec(ownerCheck(s));await applyConfigs(r,s,profile,input.protocol)});s.status='ready';await this.audit('Создан конфиг')}catch(e){await this.vault.save();throw e}
  }
  async revokeConfig(id:string) {
    const c=this.config(id);if(c.revoked)return;const s=this.server(c.serverId)
    // Revoke remotely before declaring success locally. On failure retain material for retry.
    const proposed=structuredClone(this.profile());proposed.configs.find(v=>v.id===id)!.revoked=true
    await this.withServer(s,async r=>{await r.exec(ownerCheck(s));await applyConfigs(r,s,proposed,c.protocol)})
    c.revoked=true;c.content='';c.publicKey=undefined;c.clientId=undefined;await this.audit('Отозван конфиг')
  }
  async createRoute(raw:RouteInput) {
    const input=routeInputSchema.parse(raw);const entry=this.server(input.entryId);const exit=this.server(input.exitId);const profile=this.profile()
    if(!entry.fingerprint||!entry.os||exit.status!=='ready'||!exit.protocols[input.protocol])throw new Error('Проверьте входной сервер и настройте протокол на выходном')
    if(input.protocol==='vless-ws')throw new Error('WebSocket/TLS через L4-мост пока не поддержан')
    if(input.port===entry.port||profile.routes.some(r=>r.entryId===entry.id&&r.port===input.port)||Object.values(entry.protocols).some(p=>p?.port===input.port))throw new Error('Входной порт занят')
    await this.withServer(entry,r=>validatePorts(r,entry,[{port:input.port,transport:protocolInfo[input.protocol].transport}]))
    const route={...input,id:randomUUID(),status:'partial' as const,createdAt:new Date().toISOString()};profile.routes.push(route);entry.status='partial';await this.audit('Начата настройка моста')
    await this.withServer(entry,async r=>{await r.exec(preflight(entry));await r.exec(initialize(entry),300000,{label:'Установка системных пакетов',output:'install'});await updateFirewall(r,entry,profile,this.log,this.vault.require().sshKeys)})
    const stored=profile.routes.find(r=>r.id===route.id)!;stored.status='ready';entry.managed=true;entry.status=Object.keys(entry.protocols).length?'ready':'verified';await this.audit('Создан TCP/UDP-мост')
  }
  async deleteRoute(id:string) {
    idSchema.parse(id);const profile=this.profile();const route=profile.routes.find(r=>r.id===id);if(!route)throw new Error('Маршрут не найден')
    if(profile.configs.some(c=>c.routeId===id&&!c.revoked))throw new Error('Сначала отзовите конфиги этого маршрута')
    const next=structuredClone(profile);next.routes=next.routes.filter(r=>r.id!==id)
    await this.withServer(this.server(route.entryId),async r=>{await r.exec(ownerCheck(this.server(route.entryId)));await updateFirewall(r,this.server(route.entryId),next,this.log,this.vault.require().sshKeys)})
    profile.routes=next.routes;profile.configs=profile.configs.filter(c=>c.routeId!==id);await this.audit('Удалён мост')
  }
  async deleteServer(id:string,confirmation:string,cleanup:boolean) {
    const s=this.server(id);const profile=this.profile()
    if(confirmation!==s.host)throw new Error('Для подтверждения повторите IP сервера')
    if(profile.routes.some(r=>r.entryId===id||r.exitId===id))throw new Error('Сначала удалите связанные маршруты')
    if(!cleanup&&(s.managed||s.pendingSshKeyId))throw new Error('Сначала очистите установленный VPN на сервере')
    if(cleanup)await this.withServer(s,r=>r.exec(cleanupScript(s),120000))
    profile.servers=profile.servers.filter(s=>s.id!==id);profile.configs=profile.configs.filter(c=>c.serverId!==id);await this.audit(cleanup?'Удалены службы и ключи maNETka на сервере':'Удалена локальная запись сервера')
  }

}
