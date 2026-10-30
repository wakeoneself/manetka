import { chromium } from 'playwright-core'
import { preview } from 'vite'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import assert from 'node:assert/strict'
const round=process.argv.find(a=>/^r[1-4]$/.test(a))??'r1'
const out=`design/shots/${round}`
await mkdir(out,{recursive:true})
const server=await preview({preview:{host:'127.0.0.1',port:4173,strictPort:true}})
const browser=await chromium.launch({executablePath:'/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',headless:true})
const page=await browser.newPage({viewport:{width:1320,height:860},deviceScaleFactor:2})
const errors=[];page.on('pageerror',e=>errors.push(e.message))
const frames=[]
async function shot(name){
 await page.evaluate(()=>document.fonts.ready)
 await page.screenshot({path:`${out}/${name}.png`})
 frames.push({name,html:await page.locator('#root').innerHTML()})
 const overflow=await page.evaluate(()=>[...document.querySelectorAll('h1,h2,h3,button,input,label,td,th')].filter(e=>{
  const r=e.getBoundingClientRect();return r.width>0&&r.height>0&&r.right>innerWidth+1
 }).map(e=>e.textContent?.trim().slice(0,60)))
 assert.deepEqual(overflow,[],`overflow ${name}`)
}
try{
 await page.goto('http://127.0.0.1:4173/?demo=1')
 await page.getByRole('heading',{name:'Серверы',exact:true}).waitFor()
 await shot('01-servers')
 await page.getByRole('button',{name:'Хельсинки 198.51.100.27'}).click()
 await shot('02-server-detail')
 await page.getByRole('button',{name:/^Конфиги/}).click()
 await shot('03-configs')
 await page.getByRole('button',{name:/^Маршруты/}).click()
 await shot('04-routes')
 await page.getByRole('button',{name:'Хранилище',exact:true}).click()
 await shot('05-storage')
 await page.getByRole('button',{name:/^Серверы/}).click()
 await page.getByRole('button',{name:'Добавить сервер',exact:true}).click()
 await shot('06-add-server')
 await page.getByRole('button',{name:'Закрыть',exact:true}).click()
 await page.getByRole('button',{name:/^Конфиги/}).click()
 await page.getByRole('button',{name:'Создать конфиг',exact:true}).click()
 await page.getByLabel('Название устройства').fill('MacBook Pro')
 await page.getByLabel('Подключение',{exact:true}).selectOption('r1')
 await shot('07-create-config')
 await page.getByRole('button',{name:'Закрыть',exact:true}).click()
 await page.getByRole('button',{name:/^Серверы/}).click()
 await page.getByRole('button',{name:'Светлая тема',exact:true}).click()
 await shot('08-light')
 await page.getByRole('button',{name:'Тёмная тема',exact:true}).click()
 // Usability checks: filtering and keyboard dismissal.
 await page.getByRole('textbox',{name:'Найти сервер'}).fill('Франкфурт')
 assert.equal(await page.locator('tbody tr').count(),1)
 await page.getByRole('button',{name:'Очистить поиск'}).click()
 await page.getByRole('button',{name:'Добавить сервер',exact:true}).click()
 await page.keyboard.press('Escape');assert.equal(await page.getByRole('dialog').count(),0)
 await page.getByRole('button',{name:'Выйти',exact:true}).click()
 await page.getByRole('heading',{name:'Создать хранилище'}).waitFor()
 await page.screenshot({path:`${out}/09-gate.png`})
 assert.equal(await page.locator('input[type=password]').count(),2)
 await page.setViewportSize({width:1024,height:700})
 await page.getByRole('button',{name:'Посмотреть демо'}).click()
 await page.getByRole('button',{name:'Добавить сервер',exact:true}).click()
 const dialogBox=await page.getByRole('dialog').boundingBox();assert(dialogBox.y>=0);assert(dialogBox.y+dialogBox.height<=700)
 assert.deepEqual(errors,[])
 const css=await readFile('dist/'+(await readFile('dist/index.html','utf8')).match(/href="\.\/(assets\/[^"]+\.css)"/)[1],'utf8')
 await writeFile(`design/mockup-${round}.html`,`<!doctype html><html lang="ru"><meta charset="utf-8"><style>${css}\nbody{padding:30px;background:#454746}.screen{width:1320px;height:860px;overflow:hidden;position:relative;display:block;margin:0 0 32px}.screen .app{height:100%}.screen .overlay{position:absolute}.screen .gate{min-height:100%}</style><body>${frames.map(f=>`<section class="screen" data-name="${f.name}" data-dense>${f.html}</section>`).join('')}</body></html>`)
 const thumbs=await browser.newPage({viewport:{width:1380,height:1000},deviceScaleFactor:1})
 await thumbs.setContent(`<html><body style="margin:0;padding:20px;background:#363738;display:grid;grid-template-columns:1fr 1fr;gap:20px;font:12px system-ui;color:#ddd">${frames.map(f=>`<figure style="margin:0"><img src="http://127.0.0.1:4173/nope" data-local="${f.name}" style="width:650px;display:block"><figcaption style="padding:10px">${f.name}</figcaption></figure>`).join('')}</body></html>`)
 for(const f of frames){const bytes=await readFile(`${out}/${f.name}.png`);await thumbs.locator(`[data-local="${f.name}"]`).evaluate((img,b64)=>{img.src='data:image/png;base64,'+b64},bytes.toString('base64'))}
 await thumbs.locator('img').evaluateAll(imgs=>Promise.all(imgs.map(i=>i.decode())))
 await thumbs.screenshot({path:`${out}/sheet.png`,fullPage:true})
 console.log(`UI passed: 8 frames, filter, keyboard dismissal, theme, viewport 1024×700. ${out}/sheet.png`)
}finally{await browser.close();await new Promise(resolve=>server.httpServer.close(resolve))}
