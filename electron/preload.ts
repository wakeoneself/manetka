import { contextBridge, ipcRenderer } from 'electron'
import type { Api, Progress } from '../src/model'

const call = async (method:string,...args:unknown[]) => {
  const result=await ipcRenderer.invoke('manetka:call',method,args)
  if(!result.ok)throw new Error(result.error)
  return result.value
}
const methods=['state','createVault','openVault','selectVault','closeVault','forgetVault','showVaultInFolder','unlock','lock','addProfile','switchProfile','addServer','generateSSHKey','deleteSSHKey','exportSSHKey','copyPublicSSHKey','probeServer','trustServer','checkServer','provision','repairServer','createConfig','revealConfig','exportConfig','revokeConfig','createRoute','deleteRoute','deleteServer','saveVaultCopy','setAutoLock']
const api=Object.fromEntries(methods.map(method=>[method,(...args:unknown[])=>call(method,...args)])) as unknown as Api
api.activity=()=>ipcRenderer.send('manetka:activity')
api.onProgress=callback=>{const handler=(_:unknown,p:Progress)=>callback(p);ipcRenderer.on('manetka:progress',handler);return()=>ipcRenderer.removeListener('manetka:progress',handler)}
api.onVaultChanged=callback=>{const handler=(_:unknown,state:Parameters<typeof callback>[0])=>callback(state);ipcRenderer.on('manetka:vault-changed',handler);return()=>ipcRenderer.removeListener('manetka:vault-changed',handler)}
api.onLocked=callback=>{const handler=()=>callback();ipcRenderer.on('manetka:locked',handler);return()=>ipcRenderer.removeListener('manetka:locked',handler)}
contextBridge.exposeInMainWorld('manetka',api)
