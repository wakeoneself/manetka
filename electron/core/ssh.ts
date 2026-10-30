import ssh2 from 'ssh2'
import type { Client as SshClient } from 'ssh2'
const { Client } = ssh2
import { createHash, randomUUID } from 'node:crypto'
import { resolveCredential } from './ssh-keys'
import { InstallerOutput } from './install-output'
import type { Progress, Server, SSHKey } from '../../src/model'

export const fingerprint = (key: Buffer) => 'SHA256:' + createHash('sha256').update(key).digest('base64').replace(/=+$/,'')
export async function probe(server: Server): Promise<string> {
  return new Promise((resolve,reject) => {
    const conn = new Client(); let seen = false
    conn.on('error',e => { if (!seen) reject(new Error('Не удалось получить SSH-ключ: ' + e.message)) })
    conn.connect({host:server.host,port:server.port,username:server.username,readyTimeout:15000,hostVerifier:(key:Buffer) => {
      seen=true; const value=fingerprint(key); conn.end(); resolve(value); return false
    }})
  })
}
export async function connect(server: Server, keys: SSHKey[] = [], log?: (event:Progress)=>void): Promise<Remote> {
  if (!server.fingerprint) throw new Error('Сначала подтвердите SSH-ключ сервера')
  const credential=resolveCredential(server.credential,keys),commandId=randomUUID(),started=Date.now()
  const emit=(p:Progress)=>log?.({...p,at:new Date().toISOString(),commandId,elapsedMs:Date.now()-started})
  emit({event:'command',step:'SSH-подключение',detail:'Проверка ключа сервера и аутентификация',kind:'info',state:'running'})
  return new Promise((resolve,reject) => {
    const conn = new Client(); let mismatch=false,settled=false
    const heartbeat=setInterval(()=>emit({event:'heartbeat',step:'SSH-подключение',detail:'Ожидаем установления SSH-соединения',kind:'info'}),5000)
    const finish=(success:boolean)=>{if(settled)return false;settled=true;clearInterval(heartbeat);emit({event:'command',step:'SSH-подключение',detail:success?'Соединение установлено':'Соединение не установлено',kind:success?'ok':'error',state:success?'done':'failed'});return true}
    conn.on('error',e=>{if(finish(false))reject(new Error(mismatch ? 'SSH-ключ изменился. Сверьте fingerprint с панелью провайдера.' : 'Ошибка SSH: '+e.message))})
    conn.on('close',()=>{if(finish(false))reject(new Error('SSH-соединение закрыто до завершения аутентификации'))})
    conn.on('ready',()=>{if(finish(true))resolve(new Remote(conn,log))})
    try{conn.connect({host:server.host,port:server.port,username:server.username,readyTimeout:20000,keepaliveInterval:10000,keepaliveCountMax:3,
      hostVerifier:(key:Buffer)=>{ mismatch=fingerprint(key)!==server.fingerprint; return !mismatch },
      ...(credential.type==='key' ? {privateKey:credential.privateKey,passphrase:credential.passphrase} : {password:credential.password})})}
    catch{if(finish(false))reject(new Error('Не удалось начать SSH-подключение'));conn.end()}
  })
}
export class Remote {
  constructor(private conn: SshClient,private log?: (event:Progress)=>void) {}
  close() { this.conn.end() }
  async exec(script: string, timeoutMs=120000, display: {label?:string;output?:'install'}={}): Promise<string> {
    const commandId=randomUUID(),started=Date.now(),label=display.label??'Выполнение команды'
    let lastOutput=started
    const emit=(event:Progress)=>this.log?.({...event,at:new Date().toISOString(),commandId,elapsedMs:Date.now()-started})
    emit({event:'command',step:label,detail:'Команда отправлена на сервер',kind:'info',state:'running'})
    return new Promise((resolve,reject)=> {
      let done=false
      const heartbeat=setInterval(()=>emit({event:'heartbeat',step:label,detail:'Ожидаем завершения команды',kind:'info',silentMs:Date.now()-lastOutput}),5000)
      const finish=(error?:Error)=>{
        if(done)return false
        done=true;clearTimeout(timer);clearInterval(heartbeat)
        emit({event:'command',step:label,detail:error?'Команда не завершена': 'Команда выполнена',kind:error?'error':'ok',state:error?'failed':'done'})
        if(error)reject(error)
        return true
      }
      const timer=setTimeout(()=>{if(finish(new Error('Время операции истекло. Проверьте состояние сервера перед повтором.')))this.conn.end()},timeoutMs)
      try {this.conn.exec('bash -se', (error,stream)=> {
        if(error){finish(new Error('Не удалось запустить команду по SSH'));return}
        if(done){stream.close();return}
        let output='';let size=0
        const parser=(source:'stdout'|'stderr')=>display.output==='install'?new InstallerOutput(detail=>emit({event:'output',step:label,detail,kind:'info',stream:source})):undefined
        const stdout=parser('stdout'),stderr=parser('stderr')
        // Only explicit installer commands expose normalised messages. Configs and raw stderr stay in main.
        stream.on('data',(chunk:Buffer)=>{
          if(done)return
          lastOutput=Date.now();stdout?.push(chunk)
          // Retain a bounded result without closing the channel or causing remote SIGPIPE.
          const remaining=1024*1024-size
          if(remaining>0){const part=chunk.subarray(0,remaining);size+=part.length;output+=part.toString()}
        })
        stream.stderr.on('data',(chunk:Buffer)=>{if(done)return;lastOutput=Date.now();stderr?.push(chunk)})
        stream.on('error',()=>finish(new Error('SSH-соединение прервано')))
        stream.on('close',(code:number)=>{
          if(done)return
          stdout?.end();stderr?.end()
          if(code!==0)finish(new Error(`Сервер отклонил операцию (код ${code ?? 'неизвестен'}). Частичные изменения возможны.`))
          else if(finish())resolve(output.trim())
        })
        stream.end('set -euo pipefail\numask 077\n'+script+'\n')
      })}catch{finish(new Error('Не удалось запустить команду по SSH'))}
    })
  }
  async write(path: string, content: string | Buffer, mode=0o600) {
    if (!/^\/(?:etc\/(?:manetka|monetka)|etc\/systemd\/system|etc\/ssh\/sshd_config.d|etc\/sysctl.d|usr\/local\/lib\/(?:manetka|monetka)|run\/(?:manetka|monetka))\/[a-zA-Z0-9/_.-]+$/.test(path) || path.includes('..')) throw new Error('Недопустимый удалённый путь')
    const commandId=randomUUID(),started=Date.now()
    const emit=(state:'running'|'done'|'failed')=>this.log?.({event:'command',commandId,step:'Запись файла настроек',detail:state==='done'?'Файл сохранён атомарно':state==='failed'?'Файл не сохранён':'Передача по SFTP',state,kind:state==='failed'?'error':state==='done'?'ok':'info',at:new Date().toISOString(),elapsedMs:Date.now()-started})
    emit('running')
    try{await new Promise<void>((resolve,reject)=>this.conn.sftp((err,sftp)=>{
      if(err){reject(new Error('SFTP недоступен'));return}
      const temp=path+'.'+randomUUID()+'.tmp'
      sftp.writeFile(temp,content,{mode,flag:'wx'},e=>{
        if(e){sftp.end();reject(new Error('Не удалось записать файл на сервер'));return}
        sftp.ext_openssh_rename(temp,path,e2=>{sftp.end();if(e2)reject(new Error('Не удалось атомарно заменить файл на сервере (нужен OpenSSH SFTP)'));else resolve()})
      })
    }));emit('done')}catch(error){emit('failed');throw error}
  }
}
export async function withRemote<T>(server:Server,fn:(remote:Remote)=>Promise<T>,keys:SSHKey[]=[],log?:(event:Progress)=>void):Promise<T> {const remote=await connect(server,keys,log);try{return await fn(remote)}finally{remote.close()}}
