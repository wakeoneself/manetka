import { app, BrowserWindow, clipboard, dialog, ipcMain, Menu, powerMonitor, protocol, session, shell } from 'electron'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { dirname, extname, join, resolve, sep } from 'node:path'
import { readFile, writeFile, stat, chmod } from 'node:fs/promises'
import { z, ZodError } from 'zod'
import { Vault } from './core/vault'
import { VaultLibrary } from './core/vault-library'
import { Controller } from './core/controller'
import { idSchema, passwordSchema, nameSchema } from './core/validation'
import type { ConfigInput, ProvisionInput, RouteInput, ServerInput, SSHKeyInput } from '../src/model'

const root=dirname(fileURLToPath(import.meta.url))
// Use the new application identity; import only recent paths from the old directory.
const legacyUserData=join(app.getPath('appData'),'monetka')
app.setPath('userData',join(app.getPath('appData'),'manetka'))
app.setName('maNETka')
const isDev=process.env.MANETKA_DEV==='1'&&!app.isPackaged
if(!app.isPackaged&&process.env.MANETKA_E2E_DATA)app.setPath('userData',resolve(process.env.MANETKA_E2E_DATA))
const appUrl=isDev?'http://127.0.0.1:5173/':'manetka://app/index.html'
protocol.registerSchemesAsPrivileged([{scheme:'manetka',privileges:{standard:true,secure:true,supportFetchAPI:true}}])
let win:BrowserWindow
let vault:Vault
let controller:Controller
let library:VaultLibrary
const unlockLimits=new Map<string,{failures:number;nextUnlock:number}>()
let pendingFile=process.argv.find(p=>/\.(manetka|monetka|vault)$/i.test(p)&&!p.startsWith('-'))
let ensureWindow:(()=>void)|undefined
let lastActivity=Date.now(), lockPending=false
function safeSend(channel:string,payload?:unknown){if(win&&!win.isDestroyed()&&!win.webContents.isDestroyed())win.webContents.send(channel,payload)}
function sendLocked(){safeSend('manetka:locked')}
function lock(){if(controller?.busy){lockPending=true;sendLocked();return}vault?.lock();sendLocked()}
function allowed(event:Electron.IpcMainInvokeEvent|Electron.IpcMainEvent) {
  if(!win||win.isDestroyed()||event.sender!==win.webContents||event.senderFrame!==win.webContents.mainFrame)return false
  const url=event.senderFrame?.url??''
  return isDev?new URL(url).origin==='http://127.0.0.1:5173':url.split('#')[0]===appUrl
}
const safeError=(e:unknown) => e instanceof ZodError ? 'Проверьте введённые данные: '+e.issues[0]?.message : e instanceof Error ? e.message.slice(0,350) : 'Операция не выполнена'

function bindVault(){
  vault=library.current??new Vault(join(app.getPath('userData'),'.no-selection'))
  controller=new Controller(vault,p=>{if(vault.unlocked&&!lockPending)safeSend('manetka:progress',p)})
}
async function selectionChanged(){bindVault();if(lockPending){vault.lock();lockPending=false}lastActivity=Date.now();const state=await library.publicState();safeSend('manetka:vault-changed',state);return state}
async function pickOpenVault(){
  ensureWindow?.()
  const file=await dialog.showOpenDialog(win,{title:'Открыть хранилище maNETka',filters:[{name:'Хранилище maNETka',extensions:['manetka','monetka','vault']}],properties:['openFile']})
  if(file.canceled)return null
  await library.open(file.filePaths[0]);return selectionChanged()
}
async function pickCreateVault(password:string,name='Личное'){
  passwordSchema.parse(password);name=nameSchema.parse(name)
  const filename=name.replace(/[^\p{L}\p{N} _-]/gu,'_')+'.manetka'
  const file=await dialog.showSaveDialog(win,{title:'Создать хранилище maNETka',defaultPath:join(library.directory,filename),filters:[{name:'Хранилище maNETka',extensions:['manetka']}],buttonLabel:'Создать'})
  if(file.canceled||!file.filePath)return null
  await library.create(file.filePath,password);return selectionChanged()
}
async function revealVault(id?:string){
  if(id||library.current){const path=library.pathFor(id);if(!(await stat(path)).isFile())throw new Error('Файл не найден');shell.showItemInFolder(path)}
  else {const error=await shell.openPath(library.directory);if(error)throw new Error('Не удалось открыть папку хранилищ')}
  return true
}
function finishDeferredLock(){if(lockPending&&!controller.busy){lockPending=false;vault.lock();sendLocked()}}
async function menuExecute(method:string){
  try{await execute(method,[])}catch(error){finishDeferredLock();await dialog.showMessageBox({type:'error',message:'Операция с хранилищем не выполнена',detail:safeError(error)})}finally{finishDeferredLock()}
}
async function execute(method:string,args:unknown[]) {
  if(method==='state')return library.publicState(controller.busy)
  if(method==='lock'){lock();return}
  if(['openVault','selectVault','closeVault','forgetVault','showVaultInFolder','createVault','saveVaultCopy'].includes(method))return controller.transaction(method,async()=>{
    if(method==='openVault')return pickOpenVault()
    if(method==='saveVaultCopy'){
      if(!library.current)throw new Error('Сначала выберите хранилище')
      const info=await library.info(),current=info.files.find(f=>f.id===info.selectedId)!
      const file=await dialog.showSaveDialog(win,{title:'Сохранить копию хранилища',defaultPath:join(library.directory,current.name+' — копия.manetka'),filters:[{name:'Хранилище maNETka',extensions:['manetka']}]})
      if(file.canceled||!file.filePath)return false
      if(extname(file.filePath).toLowerCase()!=='.manetka')throw new Error('Используйте расширение .manetka')
      await library.current.copyTo(file.filePath);return true
    }
    if(method==='createVault')return pickCreateVault(z.string().parse(args[0]),args[1]===undefined?'Личное':z.string().parse(args[1]))
    if(method==='showVaultInFolder')return revealVault(args[0]===undefined?undefined:z.string().parse(args[0]))
    if(method==='selectVault')await library.select(z.string().parse(args[0]))
    if(method==='closeVault')await library.close()
    if(method==='forgetVault')await library.forget(z.string().parse(args[0]))
    return selectionChanged()
  })
  if(method==='unlock')return controller.transaction(method,async()=>{
    if(!library.current)throw new Error('Сначала выберите файл хранилища')
    const password=z.string().max(1024).parse(args[0]),limit=unlockLimits.get(vault.path)??{failures:0,nextUnlock:0}
    if(Date.now()<limit.nextUnlock)throw new Error('Подождите перед следующей попыткой')
    try{await vault.unlock(password);unlockLimits.delete(vault.path);lastActivity=Date.now();return library.publicState()}
    catch(error){limit.failures++;limit.nextUnlock=Date.now()+Math.min(30000,500*2**Math.min(limit.failures,6));unlockLimits.set(vault.path,limit);throw error}
  })
  return controller.transaction(method,async()=>{
    vault.require()
    switch(method) {
      case 'addProfile': await controller.addProfile(z.string().parse(args[0]));break
      case 'switchProfile': await controller.switchProfile(z.string().parse(args[0]));break
      case 'addServer': await controller.addServer(args[0] as ServerInput);break
      case 'generateSSHKey': await controller.generateSSHKey(args[0] as SSHKeyInput);break
      case 'deleteSSHKey': await controller.deleteSSHKey(z.string().parse(args[0]));break
      case 'copyPublicSSHKey': clipboard.writeText(controller.sshKey(z.string().parse(args[0])).publicKey);return true
      case 'exportSSHKey': {
        const key=controller.sshKey(z.string().parse(args[0]));const kind=z.enum(['public','private']).parse(args[1])
        if(kind==='private'){const confirm=await dialog.showMessageBox(win,{type:'warning',message:'Экспортировать приватный SSH-ключ?',detail:'Этот файл предоставляет доступ к серверам. Он будет сохранён отдельно от зашифрованного хранилища. '+(key.passphrase?'Ключ защищён дополнительным паролем.':'У ключа нет дополнительного пароля.'),buttons:['Отмена','Экспортировать'],defaultId:0,cancelId:0});if(confirm.response!==1)return false}
        const name=key.name.replace(/[^\p{L}\p{N} _-]/gu,'_')+(kind==='public'?'.pub':'')
        const file=await dialog.showSaveDialog(win,{title:kind==='public'?'Публичный SSH-ключ':'Приватный SSH-ключ',defaultPath:name})
        if(file.canceled||!file.filePath)return false
        await writeFile(file.filePath,kind==='public'?key.publicKey+'\n':key.privateKey,{mode:0o600});await chmod(file.filePath,0o600);await controller.audit(kind==='public'?'Экспортирован публичный SSH-ключ':'Экспортирован приватный SSH-ключ');return true
      }
      case 'probeServer': return controller.probeServer(z.string().parse(args[0]))
      case 'trustServer': await controller.trustServer(z.string().parse(args[0]),z.string().parse(args[1]));break
      case 'checkServer': await controller.checkServer(z.string().parse(args[0]));break
      case 'provision': await controller.provision(args[0] as ProvisionInput);break
      case 'repairServer': await controller.repairServer(z.string().parse(args[0]));break
      case 'createConfig': await controller.createConfig(args[0] as ConfigInput);break
      case 'createRoute': await controller.createRoute(args[0] as RouteInput);break
      case 'deleteRoute': await controller.deleteRoute(z.string().parse(args[0]));break
      case 'revokeConfig': await controller.revokeConfig(z.string().parse(args[0]));break
      case 'deleteServer': await controller.deleteServer(z.string().parse(args[0]),z.string().parse(args[1]),z.boolean().parse(args[2]));break
      case 'setAutoLock': vault.require().autoLockMinutes=z.number().int().min(1).max(60).parse(args[0]);await vault.save();break
      case 'revealConfig': {const c=controller.config(idSchema.parse(args[0]));if(c.revoked)throw new Error('Конфиг отозван');return c.content}
      case 'exportConfig': {
        const c=controller.config(idSchema.parse(args[0]));if(c.revoked)throw new Error('Конфиг отозван')
        const ext=c.protocol.startsWith('vless')?'txt':'conf'
        const file=await dialog.showSaveDialog(win,{title:'Сохранить конфиг с приватным ключом',defaultPath:c.name.replace(/[^\p{L}\p{N} _-]/gu,'_')+'.'+ext,filters:[{name:'VPN config',extensions:[ext]}]})
        if(file.canceled||!file.filePath)return false
        await writeFile(file.filePath,c.content,{mode:0o600});return true
      }
      default: throw new Error('Неизвестная операция')
    }
    return library.publicState()
  })
}
app.on('open-file',(event,path)=>{event.preventDefault();if(!library){pendingFile=path;return}void externalOpen(path)})
async function externalOpen(path:string){
  if(!library||!controller){pendingFile=path;return}
  try{await controller.transaction('openVault',async()=>{await library.open(path);await selectionChanged()});ensureWindow?.()}
  catch(error){finishDeferredLock();await dialog.showMessageBox({type:'error',message:'Не удалось открыть хранилище',detail:safeError(error)})}
}
if(!app.requestSingleInstanceLock())app.quit()
else {
  app.on('second-instance',(_event,argv)=>{const file=argv.find(p=>/\.(manetka|monetka|vault)$/i.test(p)&&!p.startsWith('-'));if(file)void externalOpen(resolve(file));if(win&&!win.isDestroyed()){if(win.isMinimized())win.restore();win.focus()}})
  app.whenReady().then(async()=>{
    // Local bundles must never survive an application update in Chromium's HTTP cache.
    await session.defaultSession.clearCache()
    library=new VaultLibrary(app.getPath('userData'),!app.isPackaged&&process.env.MANETKA_E2E_DATA?undefined:legacyUserData);await library.init()
    if(pendingFile){try{await library.open(pendingFile)}catch(error){library.warning='Не удалось открыть выбранный файл: '+safeError(error)}pendingFile=undefined}
    bindVault()
    Menu.setApplicationMenu(Menu.buildFromTemplate([
      {label:'maNETka',submenu:[{role:'about'},{type:'separator'},{label:'Заблокировать хранилище',accelerator:'CmdOrCtrl+L',click:lock},{type:'separator'},{role:'hide'},{role:'quit'}]},
      {label:'Файл',submenu:[{label:'Открыть хранилище…',accelerator:'CmdOrCtrl+O',click:()=>{void menuExecute('openVault')}},{label:'Выбрать хранилище',click:()=>{void menuExecute('closeVault')}},{label:'Показать файл в папке',click:()=>{void menuExecute('showVaultInFolder')}}]},
      {label:'Правка',submenu:[{role:'undo'},{role:'redo'},{type:'separator'},{role:'cut'},{role:'copy'},{role:'paste'},{role:'selectAll'}]},
      {label:'Окно',submenu:[{role:'minimize'},{role:'zoom'},{role:'close'}]},
    ]))
    session.defaultSession.setPermissionRequestHandler((_web,_permission,callback)=>callback(false))
    session.defaultSession.setPermissionCheckHandler(()=>false)
    if(!isDev){
      protocol.handle('manetka',async request=>{
        try{
          const url=new URL(request.url);const dist=resolve(root,'../dist');const file=resolve(dist,'.'+decodeURIComponent(url.pathname))
          if(request.method!=='GET'||url.hostname!=='app'||!file.startsWith(dist+sep))return new Response('Forbidden',{status:403})
          const types:Record<string,string>={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.woff2':'font/woff2'}
          const bytes=await readFile(file)
          return new Response(bytes,{headers:{'Content-Type':types[extname(file)]??'application/octet-stream','X-Content-Type-Options':'nosniff','Cache-Control':'no-store'}})
        }catch{return new Response('Not found',{status:404})}
      })
      session.defaultSession.webRequest.onBeforeRequest((details,callback)=>callback({cancel:!details.url.startsWith('manetka://app/')&&!details.url.startsWith('data:')}))
    }
    const createWindow=()=>{
      win=new BrowserWindow({width:1320,height:860,minWidth:1024,minHeight:700,title:'maNETka',backgroundColor:'#141516',titleBarStyle:'hiddenInset',trafficLightPosition:{x:22,y:20},show:false,
        webPreferences:{preload:join(root,'preload.cjs'),nodeIntegration:false,contextIsolation:true,sandbox:true,webSecurity:true,allowRunningInsecureContent:false,webviewTag:false,devTools:isDev}})
      win.webContents.setWindowOpenHandler(()=>({action:'deny'}))
      win.webContents.on('will-navigate',e=>e.preventDefault())
      win.webContents.on('will-attach-webview',e=>e.preventDefault())
      win.on('closed',()=>{lock();})
      win.once('ready-to-show',()=>win.show());void win.loadURL(appUrl)
    }
    ipcMain.handle('manetka:call',async(event,method:unknown,args:unknown)=>{
      if(!allowed(event))return {ok:false,error:'Недоверенный источник IPC'}
      try {
        if(typeof method!=='string'||!Array.isArray(args)||args.length>3||Buffer.byteLength(JSON.stringify(args))>1024*1024)throw new Error('Недопустимый запрос')
        const value=await execute(method,args);lastActivity=Date.now();return {ok:true,value}
      }catch(e){return {ok:false,error:safeError(e)}}finally{finishDeferredLock()}
    })
    ipcMain.on('manetka:activity',e=>{if(allowed(e))lastActivity=Date.now()})
    setInterval(()=>{if(vault.unlocked&&!controller.busy&&Date.now()-lastActivity>vault.require().autoLockMinutes*60000)lock()},15000).unref()
    powerMonitor.on('suspend',lock);powerMonitor.on('lock-screen',lock)
    createWindow()
    ensureWindow=()=>{if(BrowserWindow.getAllWindows().length===0)createWindow();else{win.show();win.focus()}}
    app.on('activate',ensureWindow)
  })
  app.on('before-quit',()=>vault?.lock())
  app.on('window-all-closed',()=>{if(process.platform!=='darwin')app.quit()})
}
