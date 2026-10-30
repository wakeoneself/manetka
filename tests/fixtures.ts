import { randomUUID } from 'node:crypto'
import type { Server, VaultData } from '../src/model'
import { makeMaterial } from '../electron/core/protocols'
export function fixture(){
 const profileId=randomUUID()
 const server:Server={id:randomUUID(),name:'Private Helsinki',host:'198.51.100.27',port:2222,username:'root',credential:{type:'password',password:'ssh-password-never-public'},status:'ready',protocols:{wireguard:makeMaterial('wireguard',{port:51820,sni:'www.microsoft.com',domain:'',path:'/connect'})},managed:true,resourceNamespace:'manetka',ownerId:randomUUID()}
 const data:VaultData={version:1,installationId:randomUUID(),activeProfileId:profileId,sshKeys:[],autoLockMinutes:5,audit:[],profiles:[{id:profileId,name:'Личный',servers:[server],configs:[{id:randomUUID(),name:'Phone',serverId:server.id,protocol:'wireguard',createdAt:new Date().toISOString(),content:'private-client-config-never-public',revoked:false}],routes:[]}]}
 return {data,server}
}
