import {chromium} from 'playwright-core'
import {preview} from 'vite'
import {mkdir} from 'node:fs/promises'
import assert from 'node:assert/strict'
const out='design/shots/vault-files';await mkdir(out,{recursive:true})
const server=await preview({preview:{host:'127.0.0.1',port:4173,strictPort:true}})
const browser=await chromium.launch({executablePath:'/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',headless:true})
const page=await browser.newPage({viewport:{width:1320,height:860},deviceScaleFactor:2})
await page.addInitScript(()=>{
 const state={exists:true,locked:true,profiles:[],sshKeys:[],autoLockMinutes:5,audit:[],vaults:{selectedId:'first',directory:'/Users/example/Library/Application Support/manetka/vaults',files:[{id:'first',name:'Личное',path:'/Users/example/Documents/maNETka/Личное.manetka',missing:false},{id:'work',name:'Рабочие серверы',path:'/Volumes/Private/VPN/Рабочие серверы.manetka',missing:false},{id:'lost',name:'Резервное',path:'/Volumes/Backup/Резервное.manetka',missing:true}]}}
 const changed=new Set()
 const change=()=>{changed.forEach(cb=>cb(structuredClone(state)));return structuredClone(state)}
 window.manetka={state:async()=>structuredClone(state),activity(){},onProgress(){return()=>{}},onLocked(){return()=>{}},onVaultChanged(cb){changed.add(cb);return()=>changed.delete(cb)},selectVault:async id=>{state.vaults.selectedId=id;state.exists=!state.vaults.files.find(f=>f.id===id).missing;return change()},forgetVault:async id=>{state.vaults.files=state.vaults.files.filter(f=>f.id!==id);if(state.vaults.selectedId===id){state.vaults.selectedId=undefined;state.exists=false}return change()},showVaultInFolder:async()=>true,openVault:async()=>null,saveVaultCopy:async()=>true}
})
const errors=[];page.on('pageerror',e=>errors.push(e.message))
async function shot(name){await page.evaluate(()=>document.fonts.ready);await page.screenshot({path:`${out}/${name}.png`});assert.deepEqual(await page.evaluate(()=>[...document.querySelectorAll('button,input,h1,h2')].filter(e=>{const r=e.getBoundingClientRect();return r.width>0&&r.height>0&&(r.right>innerWidth+1||r.bottom>innerHeight+1)}).map(e=>e.textContent||e.getAttribute('aria-label'))),[])}
try{
 await page.goto('http://127.0.0.1:4173/')
 await page.getByRole('heading',{name:'Открыть хранилище',exact:true}).waitFor()
 assert.equal(await page.locator('.vault-file-button').count(),3)
 await shot('01-unlock')
 await page.getByRole('button',{name:'Забыли пароль?',exact:true}).click()
 await page.getByRole('heading',{name:'Забыли пароль?',exact:true}).waitFor()
 await shot('02-forgot')
 await page.getByRole('button',{name:'Создать новое хранилище',exact:true}).click()
 await page.getByRole('heading',{name:'Создать хранилище',exact:true}).waitFor()
 assert.equal(await page.locator('input[type=password]').count(),2)
 await page.getByLabel('Название хранилища').fill('Новый VPS')
 await shot('03-create')
 await page.locator('.vault-file-button').filter({hasText:'Рабочие серверы'}).click()
 await page.getByRole('heading',{name:'Открыть хранилище',exact:true}).waitFor()
 assert.equal(await page.locator('input[type=password]').count(),1)
 await page.locator('.vault-file-button').filter({hasText:'Резервное'}).click()
 await page.getByRole('heading',{name:'Файл не найден',exact:true}).waitFor()
 assert.equal(await page.locator('input[type=password]').count(),0)
 await shot('04-missing')
 await page.getByRole('button',{name:'Убрать из списка Резервное',exact:true}).click()
 await page.getByRole('heading',{name:'Выберите хранилище',exact:true}).waitFor()
 await shot('05-chooser')
 await page.setViewportSize({width:1024,height:700})
 await page.getByRole('button',{name:'Новое хранилище',exact:true}).click()
 await shot('06-compact')
 await page.evaluate(()=>document.documentElement.dataset.theme='light')
 await shot('07-light')
 assert(!/ZIP|KDBX/.test(await page.locator('#root').innerText()));assert.deepEqual(errors,[])
 console.log('Vault files UI passed: picker, paths, forgot/new, missing file, forget entry, dark/light, 1024×700.')
}finally{await browser.close();await new Promise(resolve=>server.httpServer.close(resolve))}
