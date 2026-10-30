import { randomUUID } from 'node:crypto'
import { resolve4 } from 'node:dns/promises'
import type { Profile, Protocol, Progress, Server, SSHKey } from '../../src/model'
import { protocolInfo } from '../../src/model'
import downloads from './downloads.json'
import { withRemote, type Remote, connect } from './ssh'
import { shellQuote as q } from './validation'
import { iface, wgServerConfig, xrayConfig } from './protocols'
import * as scripts from './scripts'
import { resourceNamespace } from './resource-namespace'

type Log=(p:Progress)=>void
type Download={url:string;sha256:string}
function fetchScript(item:Download,target:string) { return `curl --progress-bar --proto '=https' --tlsv1.2 -fL --retry 2 --connect-timeout 20 --max-time 300 ${q(item.url)} -o ${q(target)}\nprintf '%s  %s\\n' ${q(item.sha256)} ${q(target)} | sha256sum --check --status` }
const archOf=(server:Server) => { if(['aarch64','arm64'].includes(server.arch??''))return 'arm64' as const;if(['x86_64','amd64'].includes(server.arch??''))return 'amd64' as const;throw new Error('Поддерживаются серверы x86_64 и ARM64') }
export async function inspect(server:Server,keys:SSHKey[]=[],log?:Log):Promise<void> {
  const ns=resourceNamespace(server)
  await withRemote(server,async remote=>{
    const output=await remote.exec(scripts.preflight(server),120000,{label:'Проверка системы и владельца'})
    const [os,arch]=output.split('\n'); server.os=os;server.arch=arch;archOf(server)
    for (const protocol of Object.keys(server.protocols)) await remote.exec(`systemctl is-active --quiet ${ns}-${protocol.startsWith('vless')?'xray':protocol}.service`)
    server.status=Object.keys(server.protocols).length?'ready':'verified';server.checkedAt=new Date().toISOString()
  },keys,log)
}
export async function validatePorts(remote:Remote,server:Server,ports:{port:number;transport:'tcp'|'udp'}[],ignore:number[]=[]) {
  const output=await remote.exec("ss -H -lntu | awk '{print $1, $5}'",120000,{label:'Проверка свободных портов'})
  for(const {port,transport} of ports) {
    if(port===server.port)throw new Error('VPN-порт совпадает с SSH-портом')
    if(ignore.includes(port))continue
    if(output.split('\n').some(line=>line.startsWith(transport)&&line.trim().endsWith(':'+port)))throw new Error(`Порт ${port}/${transport} уже занят. Выберите другой.`)
  }
}
async function installProtocol(remote:Remote,server:Server,protocol:Protocol,log:Log) {
  const ns=resourceNamespace(server)
  const arch=archOf(server)
  if(protocol==='wireguard') {
    await remote.exec('export DEBIAN_FRONTEND=noninteractive\napt-get -o DPkg::Lock::Timeout=180 install -y -qq wireguard-tools',300000,{label:'Установка WireGuard',output:'install'})
  } else if(protocol==='amneziawg') {
    log({step:'AmneziaWG',detail:'Сборка закреплённых исходников. Это может занять несколько минут.',kind:'info'})
    await remote.exec(`export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=180 install -y -qq build-essential libmnl-dev
${fetchScript(downloads.go[arch],`/run/${ns}/go.tar.gz`)}
install -d -m 700 /usr/local/lib/${ns}/toolchain
tar -xzf /run/${ns}/go.tar.gz -C /usr/local/lib/${ns}/toolchain
${fetchScript(downloads['awg-go'],`/run/${ns}/awg-go.tar.gz`)}
${fetchScript(downloads['awg-tools'],`/run/${ns}/awg-tools.tar.gz`)}
install -d -m 700 /run/${ns}/awg-go /run/${ns}/awg-tools
tar -xzf /run/${ns}/awg-go.tar.gz --strip-components=1 -C /run/${ns}/awg-go
tar -xzf /run/${ns}/awg-tools.tar.gz --strip-components=1 -C /run/${ns}/awg-tools
export PATH=/usr/local/lib/${ns}/toolchain/go/bin:$PATH
export GOTOOLCHAIN=local
export GOSUMDB=sum.golang.org
cd /run/${ns}/awg-go
go build -trimpath -o /usr/local/lib/${ns}/amneziawg-go .
cd /run/${ns}/awg-tools/src
make -j2
make install PREFIX=/usr/local/lib/${ns}/awg-tools SYSCONFDIR=/etc/${ns}/awg WITH_WGQUICK=yes WITH_BASHCOMPLETION=no WITH_SYSTEMDUNITS=no
rm -rf /usr/local/lib/${ns}/toolchain /run/${ns}/awg-go /run/${ns}/awg-tools
`,1200000,{label:'Сборка AmneziaWG',output:'install'})
  } else {
    log({step:'Xray',detail:'Загрузка официального релиза с проверкой SHA-256.',kind:'info'})
    await remote.exec(`${fetchScript(downloads.xray[arch],`/run/${ns}/xray.zip`)}
unzip -oq /run/${ns}/xray.zip xray -d /usr/local/lib/${ns}
chmod 755 /usr/local/lib/${ns}/xray
id ${ns}-xray >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ${ns}-xray
chmod 711 /etc/${ns}
`,400000,{label:'Загрузка компонентов',output:'install'})
    await remote.write(`/etc/systemd/system/${ns}-xray.service`,scripts.xrayUnit(server),0o644)
    if(protocol==='vless-ws') {
      await remote.exec(`${fetchScript(downloads.caddy[arch],`/run/${ns}/caddy.tar.gz`)}
tar -xzf /run/${ns}/caddy.tar.gz -C /usr/local/lib/${ns} caddy
chmod 755 /usr/local/lib/${ns}/caddy
id ${ns}-caddy >/dev/null 2>&1 || useradd --system --home-dir /var/lib/${ns}-caddy --shell /usr/sbin/nologin ${ns}-caddy
`,400000,{label:'Загрузка компонентов',output:'install'})
      await remote.write(`/etc/systemd/system/${ns}-caddy.service`,scripts.caddyUnit(server),0o644)
      const s=server.protocols[protocol]!
      await remote.write(`/etc/${ns}/Caddyfile`,`{\n admin off\n}\n${s.domain}:${s.port} {\n @vpn path ${s.path}\n reverse_proxy @vpn 127.0.0.1:18080\n respond 404\n}\n`,0o644)
    }
  }
}
export async function applyConfigs(remote:Remote,server:Server,profile:Profile,only?:Protocol) {
  const ns=resourceNamespace(server)
  if(!only||only.startsWith('vless')) {
    if(Object.keys(server.protocols).some(p=>p.startsWith('vless'))) {
      await remote.write(`/etc/${ns}/xray.json`,JSON.stringify(xrayConfig(server,profile.configs.filter(c=>c.serverId===server.id)),null,2))
      await remote.exec(`chown root:${ns}-xray /etc/${ns}/xray.json\nchmod 640 /etc/${ns}/xray.json\n/usr/local/lib/${ns}/xray run -test -config /etc/${ns}/xray.json\nsystemctl daemon-reload\nsystemctl enable ${ns}-xray.service\nsystemctl restart ${ns}-xray.service\nsleep 1\nsystemctl is-active --quiet ${ns}-xray.service`,120000,{label:'Проверка Xray и запуск службы'})
    }
  }
  for(const protocol of ['wireguard','amneziawg'] as const) {
    if(!server.protocols[protocol]||(only&&only!==protocol))continue
    await remote.write(`/etc/${ns}/${iface(protocol)}.conf`,wgServerConfig(protocol,server.protocols[protocol]!,profile.configs.filter(c=>c.serverId===server.id)))
    await remote.write(`/etc/systemd/system/${ns}-${protocol}.service`,scripts.tunnelUnit(protocol,server),0o644)
    await remote.exec(`systemctl daemon-reload\nsystemctl enable ${ns}-${protocol}.service\nsystemctl restart ${ns}-${protocol}.service\nsystemctl is-active --quiet ${ns}-${protocol}.service`,120000,{label:'Запуск VPN-службы'})
  }
}
export async function updateFirewall(remote:Remote,server:Server,profile:Profile,log:Log,keys:SSHKey[]=[]) {
  const ns=resourceNamespace(server)
  // Snapshot the previous firewall script to restore it if the second SSH session fails.
  await remote.exec(`if [ -f /etc/${ns}/firewall.sh ]; then cp /etc/${ns}/firewall.sh /etc/${ns}/firewall-before.sh; else printf '%s\\n' 'bash /etc/${ns}/firewall-remove.sh' > /etc/${ns}/firewall-before.sh; fi`)
  await remote.write(`/etc/${ns}/firewall-remove.sh`,scripts.firewallRemove,0o700)
  await remote.write(`/etc/${ns}/firewall.sh`,scripts.firewallScript(server,profile.routes,profile.servers),0o700)
  await remote.write(`/etc/systemd/system/${ns}-firewall.service`,scripts.firewallUnit(server),0o644)
  const rollback=`${ns}-rollback-`+randomUUID()
  await remote.exec(`systemd-run --unit=${q(rollback)} --on-active=120s /bin/bash -c 'cp /etc/${ns}/firewall-before.sh /etc/${ns}/firewall.sh; bash /etc/${ns}/firewall.sh'\nsystemctl daemon-reload\nsystemctl enable ${ns}-firewall.service\nbash /etc/${ns}/firewall.sh`,120000,{label:'Применение правил firewall'})
  log({step:'SSH-доступ',detail:'Повторное подключение после настройки firewall.',kind:'info'})
  const second=await connect(server,keys,log)
  try {await second.exec(`true\nsystemctl stop ${q(rollback+'.timer')}\nrm -f /etc/${ns}/firewall-before.sh`)}finally{second.close()}
}
export async function provision(server:Server,profile:Profile,protocol:Protocol,harden:boolean,log:Log,keys:SSHKey[]=[]) {
  const ns=resourceNamespace(server)
  if(protocol==='vless-ws') {
    const addresses=await resolve4(server.protocols[protocol]!.domain)
    if(!addresses.includes(server.host))throw new Error('DNS домена должен указывать на IP этого сервера. CDN proxy выключите на время получения TLS.')
  }
  await withRemote(server,async remote=>{
    log({step:'Проверка',detail:'Проверяем систему, владельца и свободные порты.',kind:'info'})
    await remote.exec(scripts.preflight(server),120000,{label:'Проверка системы и владельца'})
    const s=server.protocols[protocol]!
    const p=protocolInfo[protocol]
    // Retry is allowed only for already owned resources; app-level conflicts are checked before journaling.
    const owned=(await remote.exec(`if [ -f /etc/${ns}/owner ]; then printf owned; fi`))==='owned'
    await validatePorts(remote,server,[{port:s.port,transport:p.transport}],owned?[s.port]:[])
    log({step:'Подготовка',detail:'Установка пакетов из подписанных репозиториев ОС.',kind:'info'})
    await remote.exec(scripts.initialize(server),300000,{label:'Установка системных пакетов',output:'install'})
    await installProtocol(remote,server,protocol,log)
    log({step:'Firewall',detail:'Оставляем SSH, VPN и необходимые системные соединения. IPv6-транзит закрыт.',kind:'info'})
    await updateFirewall(remote,server,profile,log,keys)
    await remote.write(`/etc/sysctl.d/70-${ns}.conf`,'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.accept_redirects=0\nnet.ipv4.conf.default.accept_redirects=0\nnet.ipv4.conf.all.send_redirects=0\nnet.ipv4.conf.all.accept_source_route=0\n',0o644)
    await remote.exec(`sysctl -p /etc/sysctl.d/70-${ns}.conf >/dev/null`)
    if(harden) {
      log({step:'Усиление SSH',detail:'Проверка настроек SSH и входа по сохранённому ключу.',kind:'info'})
      await remote.exec(scripts.hardeningScript(server),120000,{label:'Безопасные настройки SSH'})
      if(server.credential.type==='key') {
        await remote.exec(scripts.disablePasswordLoginScript(server),120000,{label:'Проверка запрета парольного входа'})
        const second=await connect(server,keys,log);second.close()
      }
    }
    log({step:'VPN',detail:'Проверка конфигурации и запуск systemd-службы.',kind:'info'})
    await applyConfigs(remote,server,profile,protocol)
    if(protocol==='vless-ws') await remote.exec(`/usr/local/lib/${ns}/caddy validate --config /etc/${ns}/Caddyfile --adapter caddyfile\nsystemctl enable ${ns}-caddy.service\nsystemctl restart ${ns}-caddy.service\nsleep 2\nsystemctl is-active --quiet ${ns}-caddy.service`)
    await remote.exec(`rm -f /run/${ns}/*.zip /run/${ns}/*.tar.gz`)
    log({step:'Готово',detail:'Служба запущена. Можно создать первый конфиг. Подключение клиента проверяется отдельно.',kind:'ok'})
  },keys,log)
}
