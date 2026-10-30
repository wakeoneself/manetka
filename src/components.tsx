import { cloneElement, isValidElement, useEffect, useId, useRef, type ReactNode, type ReactElement } from 'react'
import { ArrowRight, Check, Circle, Laptop, Server, X } from 'lucide-react'
import type { PublicServer } from './model'
import logoMark from './assets/logo.svg'

export function LogoMark({size=26}:{size?:number}) {return <img className="logo-mark" src={logoMark} width={size} height={size} alt="" aria-hidden="true"/>}
export function Wordmark() {return <b className="wordmark" aria-label="maNETka"><span>ma</span><strong>NET</strong><span>ka</span></b>}

export function Button({children,variant='',className='',...props}:React.ButtonHTMLAttributes<HTMLButtonElement>&{variant?:string}) {return <button {...props} className={`button ${variant} ${className}`}>{children}</button>}
export function Field({label,hint,children}:{label:string;hint?:string;children:ReactNode}) {const id=useId();const control=isValidElement(children)&&typeof children.type==='string'&&['input','select','textarea'].includes(children.type)?cloneElement(children as ReactElement<{id?:string;'aria-labelledby'?:string}>,{id,'aria-labelledby':id+'-label'}):children;return <div className="field"><label id={id+'-label'} htmlFor={id}>{label}</label>{control}{hint&&<small>{hint}</small>}</div>}
export function Status({status}:{status:PublicServer['status']}) {const names={new:'Не проверен',verified:'SSH проверен',ready:'Готов',error:'Нет связи',partial:'Нужна проверка'};return <span className={`status ${status}`}><i/>{names[status]}</span>}
export function Empty({title,children,action}:{title:string;children:ReactNode;action?:ReactNode}) {return <div className="empty"><Server size={30} strokeWidth={1.3}/><h2>{title}</h2><p>{children}</p>{action}</div>}
export function Modal({title,subtitle,children,onClose,busy=false,wide=false}:{title:string;subtitle?:string;children:ReactNode;onClose:()=>void;busy?:boolean;wide?:boolean}) {
  const ref=useRef<HTMLDivElement>(null);const titleId=useId();const closeRef=useRef(onClose);const busyRef=useRef(busy);closeRef.current=onClose;busyRef.current=busy
  useEffect(()=>{
    const previous=document.activeElement as HTMLElement|null
    const dialog=ref.current!
    const first=dialog.querySelector<HTMLElement>('input,select,textarea,button:not(.close)')
    first?.focus()
    const onKey=(e:KeyboardEvent)=>{
      if(e.key==='Escape'&&!busyRef.current){e.preventDefault();closeRef.current()}
      if(e.key==='Tab'){
        const items=[...dialog.querySelectorAll<HTMLElement>('button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled),a[href]')].filter(e=>e.offsetParent!==null)
        const a=items[0],z=items.at(-1)
        if(e.shiftKey&&document.activeElement===a){e.preventDefault();z?.focus()}
        if(!e.shiftKey&&document.activeElement===z){e.preventDefault();a?.focus()}
      }
    }
    document.addEventListener('keydown',onKey)
    return()=>{document.removeEventListener('keydown',onKey);previous?.focus()}
  },[])
  return <div className="overlay" onMouseDown={e=>{if(e.target===e.currentTarget&&!busy)onClose()}}><div ref={ref} className={`modal ${wide?'wide':''}`} role="dialog" aria-modal="true" aria-labelledby={titleId}><div className="modal-head"><div><h2 id={titleId}>{title}</h2>{subtitle&&<p>{subtitle}</p>}</div><button className="icon-button close" title="Закрыть" aria-label="Закрыть" disabled={busy} onClick={onClose}><X size={18}/></button></div>{children}</div></div>
}
export function Connection({entry,exit,port,compact=false}:{entry?:{name:string;host:string};exit?:{name:string;host:string};port?:number;compact?:boolean}) {
  return <div className={`connection ${compact?'compact':''}`} aria-label={entry?`Устройство → ${entry.name} → ${exit?.name??'Сервер'}`:`Устройство → ${exit?.name??'Сервер'}`}>
    <div className="connection-node"><span><Laptop size={22}/></span><b>Устройство</b><small>Личный конфиг</small></div>
    <div className="connection-line"><span>VPN</span><ArrowRight size={14}/></div>
    {entry&&<><div className="connection-node"><span><Server size={22}/></span><b>{entry.name}</b><small>{entry.host}{port?`:${port}`:''}</small></div><div className="connection-line"><span>Мост</span><ArrowRight size={14}/></div></>}
    <div className="connection-node"><span><Server size={22}/></span><b>{exit?.name??'Выходной сервер'}</b><small>{exit?.host??'Выберите сервер'}</small></div>
  </div>
}
export function Step({number,done,title,children}:{number:number;done?:boolean;title:string;children:ReactNode}) {return <div className="instruction-step"><span>{done?<Check size={15}/>:number}</span><div><h3>{title}</h3><p>{children}</p></div></div>}
