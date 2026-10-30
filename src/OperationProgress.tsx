import { useEffect, useMemo, useRef, useState } from 'react'
import { ArrowDown, Check, ChevronDown, CircleAlert, Loader2, Terminal } from 'lucide-react'
import type { Progress } from './model'

export function appendProgress(items:Progress[],event:Progress):Progress[]{
  const previous=event.event==='heartbeat'?items.filter(p=>p.event!=='heartbeat'||p.commandId!==event.commandId):items
  const next=[...previous,event]
  return next.length>1600?next.filter((p,i)=>p.event!=='output'||i>next.length-1000):next
}
const duration=(ms:number)=>{const seconds=Math.max(0,Math.floor(ms/1000));return `${Math.floor(seconds/60).toString().padStart(2,'0')}:${(seconds%60).toString().padStart(2,'0')}`}
const timestamp=(at?:string)=>at?new Date(at).toLocaleTimeString('ru-RU',{hour12:false}):'—'
export function OperationProgress({items,busy}:{items:Progress[];busy:boolean}){
  const [now,setNow]=useState(Date.now()),[following,setFollowing]=useState(true),[expanded,setExpanded]=useState(true)
  const consoleRef=useRef<HTMLDivElement>(null),started=useRef(Date.now())
  useEffect(()=>{if(!busy)return;setNow(Date.now());const timer=setInterval(()=>setNow(Date.now()),1000);return()=>clearInterval(timer)},[busy])
  const data=useMemo(()=>{
    const stages=items.filter(p=>!p.event||p.event==='stage')
    const operation=items.filter(p=>p.event==='operation')
    const latest=operation.at(-1),failed=latest?.state==='failed'||items.at(-1)?.kind==='error'
    const commands=new Map<string,Progress>()
    items.filter(p=>p.event==='command'&&p.commandId).forEach(p=>commands.set(p.commandId!,p))
    const running=[...commands.values()].reverse().find(p=>p.state==='running')
    const heartbeat=items.filter(p=>p.event==='heartbeat'&&p.commandId===running?.commandId).at(-1)
    const rows=items.filter(p=>p.event!=='heartbeat').slice(-300)
    return {stages,operation,latest,failed,running,heartbeat,rows}
  },[items])
  if(!items.length&&!busy)return null
  const initial=data.operation.find(p=>p.state==='running')?.at??items[0]?.at
  const start=initial?Date.parse(initial):started.current
  const end=!busy?(data.latest?.at??items.at(-1)?.at):undefined
  const elapsed=(end?Date.parse(end):now)-start
  const phase=data.stages.at(-1)
  const title=busy?(phase?.step??'Подключение к серверу'):data.failed?'Настройка прервана':'Выполнено'
  const silent=data.heartbeat?.silentMs??0
  return <section className="operation-progress" aria-label="Ход выполнения">
    <div className="operation-heading"><div className={`operation-state ${data.failed?'failed':!busy?'complete':''}`}>{busy?<Loader2 size={19} className="spin"/>:data.failed?<CircleAlert size={19}/>:<Check size={19}/>}<div aria-live="polite"><h3>{title}</h3><p>{busy?(data.running?.step??phase?.detail??'Подготовка операции'):data.failed?'Сохранённое состояние можно восстановить':'Все команды завершены'}</p></div></div><time aria-label="Время выполнения">{duration(elapsed)}</time></div>
    {busy&&<div className="operation-activity"><span className="activity-pulse"/><span>{silent>=10000?`Команда выполняется · без вывода ${Math.floor(silent/1000)} с`:'Ожидаем завершения текущей команды'}</span><span className="operation-meter" aria-hidden="true"><i/></span></div>}
    <div className={`operation-columns ${expanded?'':'collapsed'}`}>
      <ol className="operation-steps" aria-label="Этапы настройки">{data.stages.slice(-9).map((p,i,list)=>{
        const active=i===list.length-1&&busy,failed=i===list.length-1&&data.failed
        return <li className={active?'active':failed?'failed':'done'} key={`${p.at}-${i}`}><span>{active?<Loader2 size={14} className="spin"/>:failed?<CircleAlert size={14}/>:<Check size={14}/>}</span><div><b>{p.step}</b><small>{p.detail}</small></div></li>
      })}{!data.stages.length&&<li className="active"><Loader2 size={14} className={busy?'spin':''}/><div><b>SSH-подключение</b><small>Проверяем доступ к серверу</small></div></li>}</ol>
      <div className="operation-console"><button type="button" className="console-toggle" aria-expanded={expanded} onClick={()=>setExpanded(v=>!v)}><span><Terminal size={13}/>Журнал сервера</span><ChevronDown size={13}/></button>{expanded&&<><div className="console-lines" ref={consoleRef} role="log" aria-label="Журнал сервера" aria-live="off" tabIndex={0} onScroll={e=>{const el=e.currentTarget;setFollowing(el.scrollHeight-el.scrollTop-el.clientHeight<28)}}>{data.rows.map((p,i)=><div className={`console-line ${p.kind} ${p.event??'stage'}`} key={`${p.commandId}-${p.at}-${i}`}><time>{timestamp(p.at)}</time><span>{p.event==='command'?`${p.state==='running'?'›':p.state==='failed'?'×':'✓'} ${p.step}`:p.event==='output'?p.detail:p.event==='operation'?p.detail:`${p.step}: ${p.detail}`}</span></div>)}</div>{!following&&<button type="button" className="console-follow" onClick={()=>{setFollowing(true);const el=consoleRef.current;if(el)el.scrollTop=el.scrollHeight}}><ArrowDown size={12}/>К новым сообщениям</button>}<ConsoleScroll target={consoleRef} count={items.at(-1)?.at??String(items.length)} following={following}/><p className="console-note">Вывод установки отфильтрован. Пароли, ключи и содержимое конфигов скрыты.</p></>}</div>
    </div>
  </section>
}
function ConsoleScroll({target,count,following}:{target:React.RefObject<HTMLDivElement|null>;count:string;following:boolean}){
 useEffect(()=>{const el=target.current;if(!el||!following)return;const follow=()=>{el.scrollTop=el.scrollHeight};follow();const observer=new ResizeObserver(follow);observer.observe(el);return()=>observer.disconnect()},[count,following,target])
 return null
}
