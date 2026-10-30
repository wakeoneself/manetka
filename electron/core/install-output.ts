import { StringDecoder } from 'node:string_decoder'

/** Only recognised installer messages cross IPC. No raw shell or configuration output. */
export function installerMessage(raw: string): string | undefined {
  const line=raw.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'').trim()
  if (!line || /[^\x20-\x7e]/.test(line)) return
  let m=line.match(/^(Selecting previously unselected package|Unpacking|Setting up|Processing triggers for) ([a-z0-9][a-z0-9+.:~-]{0,100})(?:[\s.(]|$)/)
  if(m){const action:{[key:string]:string}={'Selecting previously unselected package':'Выбран пакет','Unpacking':'Распаковка','Setting up':'Установка','Processing triggers for':'Обработка пакета'};return `${action[m[1]]}: ${m[2]}`}
  if(/^Reading package lists/.test(line))return 'APT: чтение списка пакетов'
  if(/^Building dependency tree/.test(line))return 'APT: проверка зависимостей'
  if(/^Reading state information/.test(line))return 'APT: проверка установленных пакетов'
  if(/^(?:Get|Hit):\d+\s/.test(line))return 'APT: получены данные репозитория'
  if(/^Fetched [\d.,]+ [kMGT]?B\b/.test(line))return 'APT: загрузка пакетов завершена'
  if(/^\d+ upgraded, \d+ newly installed,/.test(line))return 'APT: план обновления пакетов подготовлен'
  m=line.match(/^[ #=.-]*?(\d{1,3}(?:\.\d{1,2})?)%\s*$/)
  if(m&&Number(m[1])<=100)return `Загрузка: ${Math.floor(Number(m[1]))}%`
  if(/^[# =o-]{8,}$/.test(line))return 'Загрузка продолжается'
  m=line.match(/^go: downloading ([A-Za-z0-9][A-Za-z0-9._~!/+@-]{1,180}) (v[0-9][A-Za-z0-9.+_-]{0,80})$/)
  if(m)return `Go: загрузка ${m[1]} ${m[2]}`
  if(/^(?:cc|gcc|g\+\+|clang|clang\+\+|CC|LD|LINK|AR)\s/.test(line))return 'Компиляция AmneziaWG'
  if(/^make(?:\[\d+\])?: (?:Entering|Leaving) directory /.test(line))return 'Сборка AmneziaWG'
  if(/^make(?:\[\d+\])?: \*\*\*/.test(line))return 'Сборщик сообщил об ошибке'
  m=line.match(/^curl: \((\d{1,3})\)/)
  if(m)return `Ошибка загрузки: curl, код ${m[1]}`
  if(/^E: Could not get lock /.test(line))return 'APT: блокировка занята другим процессом'
  if(/^(?:E:|dpkg: error)/.test(line))return 'Пакетный менеджер сообщил об ошибке'
}

export class InstallerOutput {
  private decoder=new StringDecoder('utf8')
  private line=''
  private oversized=false
  private previous=''
  private windowStart=0
  private count=0
  private suppressed=false
  constructor(private emit:(message:string)=>void,private now=()=>Date.now()){}
  push(chunk:Buffer){this.consume(this.decoder.write(chunk))}
  end(){this.consume(this.decoder.end());this.flush()}
  private consume(text:string){
    for(const char of text){
      if(char==='\r'||char==='\n'){this.flush();continue}
      if(this.oversized)continue
      this.line+=char
      if(this.line.length>4096){this.line='';this.oversized=true}
    }
  }
  private flush(){
    const line=this.line;this.line=''
    if(this.oversized){this.oversized=false;return}
    const message=installerMessage(line)
    if(!message||message===this.previous)return
    const now=this.now()
    if(now-this.windowStart>=1000){this.windowStart=now;this.count=0;this.suppressed=false}
    if(this.count>=12){if(!this.suppressed){this.suppressed=true;this.emit('Частые сообщения объединены; выполнение продолжается')}return}
    this.count++;this.previous=message;this.emit(message)
  }
}
