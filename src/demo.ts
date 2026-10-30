import type { PublicState, PublicServer, Protocol, PublicSSHKey } from './model'
const settings=(protocol:Protocol,port:number)=>({[protocol]:{port,sni:'www.microsoft.com',domain:'',path:'/connect',mtu:1280,dns:'1.1.1.1, 1.0.0.1'}})
const server=(id:string,name:string,host:string,status:PublicServer['status'],protocols:PublicServer['protocols']):PublicServer=>({id,name,host,status,protocols,port:22,username:'root',authType:'key',sshKeyId:id==='hel'?'key-hel':id==='fra'?'key-fra':'key-msk',managed:status==='ready',ownerId:id,os:'Ubuntu 24.04.3 LTS',arch:'x86_64',checkedAt:'2026-10-23T10:42:00.000Z',hardened:true,fingerprint:'SHA256:YzCjm0MmhdC5K+ZXUIt8CNuR3F7e5IYHYSJUNe7bhWE'})
export const demoState:PublicState={exists:true,locked:false,autoLockMinutes:5,activeProfileId:'demo',sshKeys:[],audit:[{id:'a1',at:'2026-10-23T10:42:00.000Z',action:'Создан конфиг'},{id:'a2',at:'2026-10-23T10:39:00.000Z',action:'Проверено состояние сервера'},{id:'a3',at:'2026-10-22T18:17:00.000Z',action:'Создана зашифрованная резервная копия'}],profiles:[{id:'demo',name:'Личный',servers:[
  server('hel','Хельсинки','198.51.100.27','ready',{...settings('amneziawg',51821),...settings('wireguard',51820),...settings('vless-reality',443)}),
  server('msk','Москва','192.0.2.14','verified',{}),
  server('fra','Франкфурт','203.0.113.86','ready',{...settings('vless-reality',443),...settings('vless-xhttp',8443)}),
  server('ams','Амстердам','203.0.113.42','new',{}),
],routes:[{id:'r1',name:'Москва → Хельсинки',entryId:'msk',exitId:'hel',protocol:'amneziawg',port:51821,status:'ready',createdAt:'2026-10-22T12:12:00.000Z'},{id:'r2',name:'Москва → Франкфурт',entryId:'msk',exitId:'fra',protocol:'vless-reality',port:443,status:'ready',createdAt:'2026-10-22T13:12:00.000Z'}],configs:[
  {id:'c1',name:'MacBook Pro',serverId:'hel',protocol:'amneziawg',routeId:'r1',createdAt:'2026-10-23T10:42:00.000Z',address:'10.78.0.2',revoked:false},
  {id:'c2',name:'iPhone',serverId:'hel',protocol:'amneziawg',routeId:'r1',createdAt:'2026-10-22T12:15:00.000Z',address:'10.78.0.3',revoked:false},
  {id:'c3',name:'Домашний роутер',serverId:'hel',protocol:'wireguard',createdAt:'2026-10-21T16:29:00.000Z',address:'10.77.0.2',revoked:false},
  {id:'c4',name:'MacBook Air',serverId:'fra',protocol:'vless-reality',routeId:'r2',createdAt:'2026-10-20T14:12:00.000Z',revoked:false},
  {id:'c5',name:'Запасной',serverId:'fra',protocol:'vless-xhttp',createdAt:'2026-10-19T18:54:00.000Z',revoked:true},
]}]}

const profile=demoState.profiles[0]
demoState.sshKeys=[['key-hel','Хельсинки · SSH','hel'],['key-fra','Франкфурт · SSH','fra'],['key-msk','Москва · SSH','msk'],['key-spare','Резервный','']].map(([id,name,serverId],i)=>({id,name,algorithm:'ssh-ed25519',fingerprint:'SHA256:'+['Q','T','V','W'][i].repeat(43),publicKey:'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHjsnhl6PSiAl2mwkuxupcGYEDlL7T6KkQ8w9uhxdvb8 maNETka',createdAt:'2026-10-23T10:17:00.000Z',encrypted:i===3,uses:serverId?profile.servers.filter(s=>s.sshKeyId===id).map(s=>({serverId:s.id,serverName:s.name,host:s.host,profileId:profile.id,profileName:profile.name,pending:false})):[],canDelete:!serverId}))
