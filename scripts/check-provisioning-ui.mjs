import {chromium} from 'playwright-core'
import {preview} from 'vite'
import {mkdir} from 'node:fs/promises'
import assert from 'node:assert/strict'
import {demoState} from '../src/demo.ts'
const out='design/shots/provisioning';await mkdir(out,{recursive:true})
const server=await preview({preview:{host:'127.0.0.1',port:4173,strictPort:true}})
const browser=await chromium.launch({executablePath:'/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',headless:true})
const page=await browser.newPage({viewport:{width:1320,height:860},deviceScaleFactor:2})
await page.addInitScript(data=>{
 const listeners=new Set();let resolveJob,rejectJob,input
 const state=structuredClone(data)
 const emit=p=>listeners.forEach(cb=>cb({at:new Date().toISOString(),...p}))
 const start=raw=>{input=raw;emit({event:'operation',state:'running',step:'Начало',detail:'Подготовка SSH-подключения',kind:'info',at:new Date(Date.now()-65000).toISOString()});return new Promise((resolve,reject)=>{resolveJob=resolve;rejectJob=reject})}
 window.manetka={state:async()=>structuredClone(state),activity(){},onLocked(){return()=>{}},onProgress:cb=>{listeners.add(cb);return()=>listeners.delete(cb)},provision:start,repairServer:()=>start(input)}
 window.__progressTest={emit,finish:success=>{
  const s=state.profiles[0].servers.find(s=>s.id===input.serverId)
  s.protocols[input.protocol]={port:input.port,sni:input.sni,domain:input.domain,path:input.path,mtu:1280,dns:'1.1.1.1'};s.status=success?'ready':'partial'
  emit({event:'operation',state:success?'done':'failed',kind:success?'ok':'error',step:success?'Завершено':'Операция прервана',detail:success?'Операция завершена':'Проверьте сообщение об ошибке'})
  if(success)resolveJob(structuredClone(state));else rejectJob(new Error('Тестовая ошибка подключения; сохранено состояние для восстановления'))
 }}
},demoState)
const errors=[];page.on('pageerror',e=>errors.push(e.message))
async function emit(p){await page.evaluate(p=>window.__progressTest.emit(p),p)}
async function shot(name){await page.evaluate(()=>document.fonts.ready);await page.screenshot({path:`${out}/${name}.png`});const box=await page.getByRole('dialog').boundingBox();assert(box.y>=0);assert(box.y+box.height<=(await page.viewportSize()).height+1);assert.deepEqual(await page.evaluate(()=>[...document.querySelectorAll('.modal h2,.modal h3,.modal button,.console-lines')].filter(e=>{const r=e.getBoundingClientRect();return r.right>innerWidth+1}).map(e=>e.textContent)),[])}
try{
 await page.goto('http://127.0.0.1:4173/')
 await page.getByRole('button',{name:'Москва 192.0.2.14'}).click()
 await page.getByRole('button',{name:'Добавить протокол',exact:true}).click()
 await page.locator('.protocol-options label').filter({hasText:'AmneziaWG'}).click()
 await page.getByRole('checkbox',{name:/Это выделенный VPN-сервер/}).check()
 await page.getByRole('button',{name:'Применить настройки',exact:true}).click()
 await page.getByRole('heading',{name:'Настройка VPN',exact:true}).waitFor()
 const stages=[['Проверка','Проверяем систему и владельца'],['SSH-ключ','Ключ сохранён; новый вход проверен'],['Подготовка','Установка системных пакетов'],['AmneziaWG','Сборка закреплённых исходников']]
 for(const [step,detail] of stages)await emit({step,detail,kind:'info'})
 await emit({event:'command',commandId:'build',state:'running',step:'Сборка AmneziaWG',detail:'Команда отправлена на сервер',kind:'info'})
 for(let i=0;i<65;i++)await emit({event:'output',commandId:'build',step:'Сборка AmneziaWG',detail:i===0?'Загрузка: 43%':`Установка: ${['ca-certificates','curl','iptables','iproute2','wireguard-tools','libmnl-dev','make','gcc'][i%8]}`,kind:'info',stream:'stdout'})
 await emit({event:'heartbeat',commandId:'build',step:'Сборка AmneziaWG',detail:'Ожидаем завершения команды',silentMs:22000,kind:'info'})
 await page.getByText('Команда выполняется · без вывода 22 с',{exact:true}).waitFor()
 assert(await page.getByRole('button',{name:'Закрыть',exact:true}).first().isDisabled())
 const log=page.getByRole('log',{name:'Журнал сервера',exact:true})
 assert(await log.evaluate(e=>e.scrollTop>0))
 await log.evaluate(e=>{e.scrollTop=0;e.dispatchEvent(new Event('scroll'))})
 await emit({event:'output',step:'Сборка AmneziaWG',detail:'Компиляция AmneziaWG',kind:'info'})
 await page.getByRole('button',{name:'К новым сообщениям',exact:true}).waitFor()
 assert.equal(await log.evaluate(e=>e.scrollTop),0)
 await page.getByRole('button',{name:'К новым сообщениям',exact:true}).click()
 assert(await log.evaluate(e=>e.scrollTop+e.clientHeight>=e.scrollHeight-2))
 await shot('01-running')
 await page.getByRole('button',{name:'Журнал сервера',exact:true}).click();assert.equal(await log.count(),0)
 await page.getByRole('button',{name:'Журнал сервера',exact:true}).click();await log.waitFor()
 await page.setViewportSize({width:1024,height:700});await shot('02-compact')
 await page.evaluate(()=>document.documentElement.dataset.theme='light');await shot('03-light')
 await page.evaluate(()=>document.documentElement.dataset.theme='dark')
 await page.evaluate(()=>window.__progressTest.finish(false))
 await page.getByRole('heading',{name:'Настройка прервана',exact:true}).waitFor()
 await page.getByRole('button',{name:'Восстановить настройки',exact:true}).last().waitFor()
 await shot('04-failed')
 await page.getByRole('button',{name:'Восстановить настройки',exact:true}).last().click()
 await emit({step:'VPN',detail:'Проверка конфигурации и запуск systemd-службы',kind:'info'})
 await page.evaluate(()=>window.__progressTest.finish(true))
 await page.getByRole('heading',{name:'VPN настроен',exact:true}).waitFor()
 await page.getByRole('button',{name:'Создать конфиг',exact:true}).waitFor()
 await shot('05-completed')
 await page.getByRole('button',{name:'Готово',exact:true}).click()
 assert.equal(await page.getByRole('dialog').count(),0);assert.deepEqual(errors,[])
 console.log('Provisioning UI passed: real-time log, timer, silent heartbeat, scroll/follow, collapse, failed/retry/completed, dark/light, 1024×700.')
}finally{await browser.close();await new Promise(resolve=>server.httpServer.close(resolve))}
