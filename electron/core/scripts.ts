import type { Protocol, Server, Route } from '../../src/model'
import { protocolInfo } from '../../src/model'
import { shellQuote as q } from './validation'
import { resourceNamespace } from './resource-namespace'

export function ownerCheck(server:Server) { const ns=resourceNamespace(server); return `test "$(id -u)" = 0\ntest ! -e /etc/${ns==='manetka'?'monetka':'manetka'}\ntest ! -L /etc/${ns}\nif [ -f /etc/${ns}/owner ]; then test "$(cat /etc/${ns}/owner)" = ${q(server.ownerId)}; else test ! -d /etc/${ns}; fi` }
export function preflight(server:Server) {const ns=resourceNamespace(server);return `${ownerCheck(server)}
if [ ! -f /etc/${ns}/owner ]; then
  ! getent passwd ${ns}-xray >/dev/null
  ! getent passwd ${ns}-caddy >/dev/null
  test ! -e /etc/systemd/system/${ns}-xray.service
fi
. /etc/os-release
case "$ID:$VERSION_ID" in ubuntu:22.04|ubuntu:24.04|debian:12|debian:13) ;; *) exit 42;; esac
command -v systemctl >/dev/null
test -d /run/systemd/system
printf '%s\\n%s\\n' "$PRETTY_NAME" "$(uname -m)"
`}
export function initialize(server:Server) {const ns=resourceNamespace(server);return `${ownerCheck(server)}
install -d -m 711 /etc/${ns}
install -d -m 755 /usr/local/lib/${ns}
install -d -m 700 /run/${ns}
if [ ! -f /etc/${ns}/owner ]; then printf '%s' ${q(server.ownerId)} > /etc/${ns}/owner; fi
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=180 update -qq
apt-get -o DPkg::Lock::Timeout=180 install -y -qq ca-certificates curl unzip iptables iproute2
if [ ! -f /etc/${ns}/ip-forward-before ]; then cat /proc/sys/net/ipv4/ip_forward > /etc/${ns}/ip-forward-before; fi
`}
export function tunnelUnit(protocol:Protocol,server:Server):string {
  const ns=resourceNamespace(server)
  const cmd=protocol==='wireguard'?'/usr/bin/wg-quick':`/usr/local/lib/${ns}/awg-tools/bin/awg-quick`
  const name=protocol==='wireguard'?'mnwg0':'mnawg0'
  return `[Unit]\nDescription=maNETka ${protocol}\nAfter=network-online.target ${ns}-firewall.service\nWants=network-online.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\nEnvironment=PATH=/usr/local/lib/${ns}/awg-tools/bin:/usr/local/lib/${ns}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nEnvironment=WG_QUICK_USERSPACE_IMPLEMENTATION=/usr/local/lib/${ns}/amneziawg-go\nExecStart=${cmd} up /etc/${ns}/${name}.conf\nExecStop=${cmd} down /etc/${ns}/${name}.conf\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n`
}
export function xrayUnit(server:Server):string {const ns=resourceNamespace(server);return `[Unit]\nDescription=maNETka Xray\nAfter=network-online.target ${ns}-firewall.service\nWants=network-online.target\n[Service]\nUser=${ns}-xray\nGroup=${ns}-xray\nExecStart=/usr/local/lib/${ns}/xray run -config /etc/${ns}/xray.json\nRestart=on-failure\nRestartSec=3\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nProtectSystem=strict\nProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n`}
export function caddyUnit(server:Server):string {const ns=resourceNamespace(server);return `[Unit]\nDescription=maNETka Caddy TLS\nAfter=network-online.target\n[Service]\nUser=${ns}-caddy\nGroup=${ns}-caddy\nStateDirectory=${ns}-caddy\nEnvironment=HOME=/var/lib/${ns}-caddy\nExecStart=/usr/local/lib/${ns}/caddy run --config /etc/${ns}/Caddyfile --adapter caddyfile\nRestart=on-failure\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n`}
export function firewallUnit(server:Server):string {const ns=resourceNamespace(server);return `[Unit]\nDescription=maNETka firewall\nAfter=network-pre.target\nBefore=${ns}-wireguard.service ${ns}-amneziawg.service ${ns}-xray.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/bash /etc/${ns}/firewall.sh\nExecStop=/bin/bash /etc/${ns}/firewall-remove.sh\n[Install]\nWantedBy=multi-user.target\n`}
export const firewallRemove=`set -eu
for bin in iptables ip6tables; do
  for pair in 'filter INPUT MN_INPUT' 'filter FORWARD MN_FORWARD' 'nat PREROUTING MN_RELAY' 'nat POSTROUTING MN_NAT'; do
    set -- $pair
    while $bin -w -t "$1" -C "$2" -j "$3" 2>/dev/null; do $bin -w -t "$1" -D "$2" -j "$3"; done
    $bin -w -t "$1" -F "$3" 2>/dev/null || true
    $bin -w -t "$1" -X "$3" 2>/dev/null || true
  done
done
`
export function firewallScript(server:Server,routes:Route[],allServers:Server[]):string {
  const inputRules=Object.entries(server.protocols).map(([p,s])=>`iptables -w -A MN_INPUT -p ${protocolInfo[p as Protocol].transport} --dport ${s.port} -j ACCEPT`).join('\n')
  const ownRoutes=routes.filter(r=>r.entryId===server.id)
  const relayRules=ownRoutes.map(r=>{const exit=allServers.find(s=>s.id===r.exitId);const cfg=exit?.protocols[r.protocol];if(!exit||!cfg)throw new Error('Нет выходного сервера');const t=protocolInfo[r.protocol].transport;return `iptables -w -t nat -A MN_RELAY -p ${t} --dport ${r.port} -j DNAT --to-destination ${q(exit.host+':'+cfg.port)}\niptables -w -t nat -A MN_NAT -p ${t} -d ${q(exit.host)} --dport ${cfg.port} -j MASQUERADE\niptables -w -A MN_FORWARD -p ${t} -d ${q(exit.host)} --dport ${cfg.port} -j ACCEPT`}).join('\n')
  const tunnels=Object.keys(server.protocols).filter(p=>p==='wireguard'||p==='amneziawg').map(p=>{const iface=p==='wireguard'?'mnwg0':'mnawg0';const net=p==='wireguard'?'10.77.0.0/24':'10.78.0.0/24';return `iptables -w -A MN_FORWARD -i ${iface} -s ${net} -j ACCEPT\niptables -w -t nat -A MN_NAT -s ${net} -o "$wan" -j MASQUERADE`}).join('\n')
  return `set -euo pipefail
wan=$(ip -4 route show default | awk 'NR==1 {print $5}')
test -n "$wan"
for bin in iptables ip6tables; do
  for pair in 'filter MN_INPUT' 'filter MN_FORWARD' 'nat MN_RELAY' 'nat MN_NAT'; do
    set -- $pair
    $bin -w -t "$1" -N "$2" 2>/dev/null || true
    $bin -w -t "$1" -F "$2"
  done
  $bin -w -A MN_INPUT -i lo -j ACCEPT
  $bin -w -A MN_INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  $bin -w -A MN_INPUT -p tcp --dport ${server.port} -j ACCEPT
  $bin -w -A MN_FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
done
iptables -w -A MN_INPUT -p icmp -j ACCEPT
ip6tables -w -A MN_INPUT -p ipv6-icmp -j ACCEPT
${inputRules}
${server.protocols['vless-ws']?'iptables -w -A MN_INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT':''}
${tunnels}
${relayRules}
for bin in iptables ip6tables; do
  $bin -w -A MN_INPUT -j DROP
  $bin -w -A MN_FORWARD -j DROP
  for pair in 'filter INPUT MN_INPUT' 'filter FORWARD MN_FORWARD' 'nat PREROUTING MN_RELAY' 'nat POSTROUTING MN_NAT'; do
    set -- $pair
    $bin -w -t "$1" -C "$2" -j "$3" 2>/dev/null || $bin -w -t "$1" -I "$2" 1 -j "$3"
  done
done
sysctl -w net.ipv4.ip_forward=1 >/dev/null
`
}
// Consume all of sshd's output: grep -q may close the pipe early and cause
// sshd to exit with SIGPIPE (141), which pipefail correctly propagates.
export const passwordAuthenticationCheck="/usr/sbin/sshd -T | grep -Fx -- 'passwordauthentication no' >/dev/null"
export function disablePasswordLoginScript(server:Server):string {const ns=resourceNamespace(server);return `printf '%s\\n' 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config.d/00-${ns}.conf
/usr/sbin/sshd -t
${passwordAuthenticationCheck}
systemctl reload ssh`}

export function hardeningScript(server:Server):string {const ns=resourceNamespace(server);return `set -euo pipefail
install -d -m 755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/00-${ns}.conf <<'EOF'
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
MaxAuthTries 3
LoginGraceTime 30
EOF
/usr/sbin/sshd -t
systemctl reload ssh
`}
export function cleanupScript(server:Server):string {const ns=resourceNamespace(server);return `${ownerCheck(server)}
test -f /etc/${ns}/owner
for unit in ${ns}-wireguard ${ns}-amneziawg ${ns}-xray ${ns}-caddy ${ns}-firewall; do
  systemctl disable --now "$unit.service" 2>/dev/null || true
done
if [ -f /etc/${ns}/firewall-remove.sh ]; then bash /etc/${ns}/firewall-remove.sh; fi
if [ -f /etc/${ns}/ip-forward-before ]; then sysctl -w "net.ipv4.ip_forward=$(cat /etc/${ns}/ip-forward-before)" >/dev/null; fi
rm -f /etc/ssh/sshd_config.d/00-${ns}.conf /etc/sysctl.d/70-${ns}.conf
/usr/sbin/sshd -t && systemctl reload ssh
rm -f /etc/systemd/system/${ns}-{wireguard,amneziawg,xray,caddy,firewall}.service
rm -rf -- /etc/${ns} /usr/local/lib/${ns} /var/lib/${ns}-caddy /run/${ns}
userdel ${ns}-xray 2>/dev/null || true
userdel ${ns}-caddy 2>/dev/null || true
if [ -f /root/.ssh/authorized_keys ]; then sed -i '/ ${ns}-${server.ownerId}$/d' /root/.ssh/authorized_keys; fi
systemctl daemon-reload
`}
