import { createHash, randomUUID } from 'node:crypto'
import { resolve4 } from 'node:dns/promises'
import type { Profile, Protocol, Progress, Server, SSHKey } from '../../src/model'
import { isXray, protocolInfo, serviceOf, transportsOf } from '../../src/model'
import downloads from './downloads.json'
import { withRemote, type Remote, connect } from './ssh'
import { shellQuote as q } from './validation'
import { hysteriaConfig, iface, wgServerConfig, xrayConfig } from './protocols'
import { shimGoMod, shimSource } from './shim'
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
    for (const protocol of Object.keys(server.protocols)) await remote.exec(`systemctl is-active --quiet ${ns}-${serviceOf(protocol as Protocol)}.service`)
    if(server.protocols['vless-ws'])await remote.exec(`systemctl is-active --quiet ${ns}-caddy.service`)
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
    await remote.exec(`test -c /dev/net/tun || { echo 'Нет /dev/net/tun: AmneziaWG требует TUN (включите его в панели VPS или используйте WireGuard)' >&2; exit 1; }`,30000,{label:'Проверка TUN-устройства'})
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
# Keep the build cache on disk (not tmpfs) and independent of the SSH user's HOME.
export GOCACHE=/usr/local/lib/${ns}/gobuild/cache GOPATH=/usr/local/lib/${ns}/gobuild/path
cd /run/${ns}/awg-go
# Build next to the target and rename: a running tunnel keeps the old binary without ETXTBSY.
go build -trimpath -o /usr/local/lib/${ns}/amneziawg-go.new .
mv -f /usr/local/lib/${ns}/amneziawg-go.new /usr/local/lib/${ns}/amneziawg-go
cd /run/${ns}/awg-tools/src
make -j2
make install PREFIX=/usr/local/lib/${ns}/awg-tools SYSCONFDIR=/etc/${ns}/awg WITH_WGQUICK=yes WITH_BASHCOMPLETION=no WITH_SYSTEMDUNITS=no
chmod -R u+w /usr/local/lib/${ns}/gobuild /usr/local/lib/${ns}/toolchain 2>/dev/null || true
rm -rf /usr/local/lib/${ns}/toolchain /usr/local/lib/${ns}/gobuild /run/${ns}/awg-go /run/${ns}/awg-tools
`,1200000,{label:'Сборка AmneziaWG',output:'install'})
  } else if(protocol==='hysteria2') {
    log({step:'Hysteria 2',detail:'Загрузка официального релиза с проверкой SHA-256.',kind:'info'})
    const s=server.protocols[protocol]!
    const out=await remote.exec(`${fetchScript(downloads.hysteria[arch],`/run/${ns}/hysteria`)}
install -m 755 /run/${ns}/hysteria /usr/local/lib/${ns}/hysteria.new
mv -f /usr/local/lib/${ns}/hysteria.new /usr/local/lib/${ns}/hysteria
id ${ns}-hysteria >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ${ns}-hysteria
chmod 711 /etc/${ns}
install -d -m 750 -o root -g ${ns}-hysteria /etc/${ns}/hysteria
if [ ! -f /etc/${ns}/hysteria/server.key ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 -subj ${q('/CN='+s.sni)} -keyout /etc/${ns}/hysteria/server.key -out /etc/${ns}/hysteria/server.crt 2>/dev/null
fi
chown root:${ns}-hysteria /etc/${ns}/hysteria/server.key /etc/${ns}/hysteria/server.crt
chmod 640 /etc/${ns}/hysteria/server.key /etc/${ns}/hysteria/server.crt
openssl x509 -in /etc/${ns}/hysteria/server.crt -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr A-F a-f
`,400000,{label:'Установка Hysteria 2'})
    const pin=out.split('\n').at(-1)!.trim()
    if(!/^[a-f0-9]{64}$/.test(pin))throw new Error('Не удалось получить отпечаток сертификата Hysteria 2')
    s.certPin=pin
    await remote.write(`/etc/systemd/system/${ns}-hysteria2.service`,scripts.hysteriaUnit(server),0o644)
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
  if(!only||isXray(only)) {
    if(Object.keys(server.protocols).some(p=>isXray(p as Protocol))) {
      await remote.write(`/etc/${ns}/xray.json`,JSON.stringify(xrayConfig(server,profile.configs.filter(c=>c.serverId===server.id)),null,2))
      await remote.exec(`chown root:${ns}-xray /etc/${ns}/xray.json\nchmod 640 /etc/${ns}/xray.json\n/usr/local/lib/${ns}/xray run -test -config /etc/${ns}/xray.json\nsystemctl daemon-reload\nsystemctl enable ${ns}-xray.service\nsystemctl restart ${ns}-xray.service\nsleep 1\nsystemctl is-active --quiet ${ns}-xray.service`,120000,{label:'Проверка Xray и запуск службы'})
    }
  }
  if(server.protocols.hysteria2&&(!only||only==='hysteria2')) {
    await remote.write(`/etc/${ns}/hysteria.yaml`,hysteriaConfig(server,profile.configs.filter(c=>c.serverId===server.id),`/etc/${ns}/hysteria`))
    await remote.exec(`chown root:${ns}-hysteria /etc/${ns}/hysteria.yaml\nchmod 640 /etc/${ns}/hysteria.yaml\nsystemctl daemon-reload\nsystemctl enable ${ns}-hysteria2.service\nsystemctl restart ${ns}-hysteria2.service\nsleep 1\nsystemctl is-active --quiet ${ns}-hysteria2.service`,120000,{label:'Запуск Hysteria 2'})
  }
  for(const protocol of ['wireguard','amneziawg'] as const) {
    if(!server.protocols[protocol]||(only&&only!==protocol))continue
    await remote.write(`/etc/${ns}/${iface(protocol)}.conf`,wgServerConfig(protocol,server.protocols[protocol]!,profile.configs.filter(c=>c.serverId===server.id)))
    await remote.write(`/etc/systemd/system/${ns}-${protocol}.service`,scripts.tunnelUnit(protocol,server),0o644)
    // A running tunnel is updated in place (peers added/removed without dropping other clients);
    // a failed live sync or a stopped service falls back to a full restart.
    const unit=`${ns}-${protocol}.service`,name=iface(protocol),conf=`/etc/${ns}/${name}.conf`
    const [quick,tool]=protocol==='wireguard'?['/usr/bin/wg-quick','wg']:[`/usr/local/lib/${ns}/awg-tools/bin/awg-quick`,`/usr/local/lib/${ns}/awg-tools/bin/awg`]
    await remote.exec(`systemctl daemon-reload\nsystemctl enable ${unit}\nif systemctl is-active --quiet ${unit} && ${quick} strip ${conf} | ${tool} syncconf ${name} /dev/stdin; then :; else systemctl restart ${unit}; fi\nsystemctl is-active --quiet ${unit}`,120000,{label:'Запуск VPN-службы'})
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
    await validatePorts(remote,server,transportsOf(protocol).map(transport=>({port:s.port,transport})),owned?[s.port]:[])
    log({step:'Подготовка',detail:'Установка пакетов из подписанных репозиториев ОС.',kind:'info'})
    await remote.exec(scripts.initialize(server),300000,{label:'Установка системных пакетов',output:'install'})
    await installProtocol(remote,server,protocol,log)
    log({step:'Firewall',detail:'Оставляем SSH, VPN и необходимые системные соединения. IPv6-транзит закрыт.',kind:'info'})
    await updateFirewall(remote,server,profile,log,keys)
    await remote.write(`/etc/sysctl.d/70-${ns}.conf`,'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.accept_redirects=0\nnet.ipv4.conf.default.accept_redirects=0\nnet.ipv4.conf.all.send_redirects=0\nnet.ipv4.conf.all.accept_source_route=0\nnet.core.rmem_max=16777216\nnet.core.wmem_max=16777216\n',0o644)
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

const shimHash=createHash('sha256').update(shimSource+shimGoMod).digest('hex')
export async function installShim(remote:Remote,server:Server) {
  const ns=resourceNamespace(server),arch=archOf(server)
  await remote.exec(`install -d -m 755 /usr/local/lib/${ns}/shim-src`)
  await remote.write(`/usr/local/lib/${ns}/shim-src/main.go`,shimSource,0o644)
  await remote.write(`/usr/local/lib/${ns}/shim-src/go.mod`,shimGoMod,0o644)
  await remote.exec(`if [ -x /usr/local/lib/${ns}/shim ] && [ "$(cat /usr/local/lib/${ns}/shim.sha 2>/dev/null || true)" = ${q(shimHash)} ]; then
  echo up-to-date
else
${fetchScript(downloads.go[arch],`/run/${ns}/go.tar.gz`)}
install -d -m 700 /usr/local/lib/${ns}/toolchain
tar -xzf /run/${ns}/go.tar.gz -C /usr/local/lib/${ns}/toolchain
export PATH=/usr/local/lib/${ns}/toolchain/go/bin:$PATH GOTOOLCHAIN=local CGO_ENABLED=0
export GOCACHE=/usr/local/lib/${ns}/gobuild/cache GOPATH=/usr/local/lib/${ns}/gobuild/path
cd /usr/local/lib/${ns}/shim-src
go build -trimpath -o /usr/local/lib/${ns}/shim.new .
mv -f /usr/local/lib/${ns}/shim.new /usr/local/lib/${ns}/shim
printf '%s' ${q(shimHash)} > /usr/local/lib/${ns}/shim.sha
chmod -R u+w /usr/local/lib/${ns}/gobuild /usr/local/lib/${ns}/toolchain 2>/dev/null || true
rm -rf /usr/local/lib/${ns}/toolchain /usr/local/lib/${ns}/gobuild /run/${ns}/go.tar.gz
fi
`,900000,{label:'Сборка UDP-шима',output:'install'})
}
export async function startShim(remote:Remote,server:Server,unit:string,mode:'entry'|'exit',listen:number,target:string) {
  await installShim(remote,server)
  await remote.write(`/etc/systemd/system/${unit}.service`,scripts.shimUnit(server,mode,listen,target),0o644)
  await remote.exec(`systemctl daemon-reload\nsystemctl enable ${q(unit+'.service')}\nsystemctl restart ${q(unit+'.service')}\nsleep 1\nsystemctl is-active --quiet ${q(unit+'.service')}`,120000,{label:'Запуск UDP-шима'})
}
export async function removeShim(remote:Remote,unit:string) {
  await remote.exec(`systemctl disable --now ${q(unit+'.service')} 2>/dev/null || true\nrm -f ${q('/etc/systemd/system/'+unit+'.service')}\nsystemctl daemon-reload`,60000,{label:'Остановка UDP-шима'})
}
