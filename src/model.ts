export const PROTOCOLS = ['wireguard', 'amneziawg', 'vless-reality', 'vless-xhttp', 'vless-ws'] as const
export type Protocol = typeof PROTOCOLS[number]
export const protocolInfo: Record<Protocol, { name: string; short: string; description: string; port: number; transport: 'tcp' | 'udp' }> = {
  wireguard: { name: 'WireGuard', short: 'WireGuard', description: 'Быстрый VPN для сетей без блокировок.', port: 51820, transport: 'udp' },
  amneziawg: { name: 'AmneziaWG', short: 'AmneziaWG', description: 'VPN с маскировкой UDP-трафика. Нужен клиент AmneziaWG.', port: 51821, transport: 'udp' },
  'vless-reality': { name: 'VLESS + REALITY', short: 'VLESS · REALITY', description: 'Маскировка под TLS. Отдельный домен не нужен.', port: 443, transport: 'tcp' },
  'vless-xhttp': { name: 'VLESS + XHTTP', short: 'VLESS · XHTTP', description: 'XHTTP поверх REALITY для совместимых Xray-клиентов.', port: 8443, transport: 'tcp' },
  'vless-ws': { name: 'VLESS + WebSocket', short: 'VLESS · WS / TLS', description: 'WebSocket с TLS через Caddy. Нужен домен с DNS на сервер.', port: 2053, transport: 'tcp' },
}
export type Credential = { type: 'password' | 'key'; password?: string; privateKey?: string; passphrase?: string; keyId?: string }
export type SSHKey = { id: string; name: string; algorithm: string; publicKey: string; fingerprint: string; privateKey: string; passphrase?: string; createdAt: string }
export type SSHKeyUse = { serverId: string; serverName: string; host: string; profileId: string; profileName: string; pending: boolean }
export type PublicSSHKey = Omit<SSHKey, 'privateKey' | 'passphrase'> & { encrypted: boolean; uses: SSHKeyUse[]; canDelete: boolean }
export type SSHKeyInput = { name: string; passphrase?: string }
export type ProtocolSettings = { port: number; sni: string; domain: string; path: string; mtu: number; dns: string; awg?: Record<string, number>; privateKey?: string; publicKey?: string; shortId?: string }
export type Server = { id: string; name: string; host: string; port: number; username: string; credential: Credential; pendingSshKeyId?: string; fingerprint?: string; status: 'new' | 'verified' | 'ready' | 'error' | 'partial'; os?: string; arch?: string; checkedAt?: string; protocols: Partial<Record<Protocol, ProtocolSettings>>; managed: boolean; ownerId: string; hardened?: boolean; resourceNamespace?: 'manetka' | 'monetka' }
export type VpnConfig = { id: string; name: string; serverId: string; protocol: Protocol; routeId?: string; createdAt: string; content: string; publicKey?: string; address?: string; clientId?: string; revoked: boolean }
export type Route = { id: string; name: string; entryId: string; exitId: string; protocol: Protocol; port: number; status: 'ready' | 'partial'; createdAt: string }
export type Profile = { id: string; name: string; servers: Server[]; configs: VpnConfig[]; routes: Route[] }
export type VaultData = { version: 1; installationId: string; activeProfileId: string; sshKeys: SSHKey[]; profiles: Profile[]; autoLockMinutes: number; audit: { id: string; at: string; action: string }[] }
export type PublicServer = Omit<Server, 'credential' | 'protocols'> & { authType: Credential['type']; sshKeyId?: string; protocols: Partial<Record<Protocol, Omit<ProtocolSettings, 'privateKey'>>> }
export type PublicConfig = Omit<VpnConfig, 'content' | 'publicKey' | 'clientId'>
export type PublicProfile = Omit<Profile, 'servers' | 'configs'> & { servers: PublicServer[]; configs: PublicConfig[] }
export type VaultFile = {id:string;name:string;path:string;missing:boolean;lastUsedAt?:string}
export type VaultLibraryState = {selectedId?:string;files:VaultFile[];directory:string;warning?:string}
export type PublicState = { exists: boolean; locked: boolean; vaults?:VaultLibraryState; profiles: PublicProfile[]; sshKeys: PublicSSHKey[]; activeProfileId?: string; autoLockMinutes: number; audit: VaultData['audit']; busy?: string }
export type ServerInput = { name: string; host: string; port: number; username: string; credential: Credential; fingerprint?: string }
export type ProvisionInput = { serverId: string; protocol: Protocol; port: number; sni: string; domain: string; path: string; harden: boolean; dedicated: boolean }
export type ConfigInput = { name: string; serverId: string; protocol: Protocol; routeId?: string; dns: string; mtu: number; allowedIPs: string }
export type RouteInput = { name: string; entryId: string; exitId: string; protocol: Protocol; port: number }
export type Progress = { step: string; detail: string; kind: 'info' | 'ok' | 'error'; event?: 'stage' | 'command' | 'output' | 'heartbeat' | 'operation'; at?: string; commandId?: string; state?: 'running' | 'done' | 'failed'; elapsedMs?: number; silentMs?: number; stream?: 'stdout' | 'stderr' }
export type Api = {
  state(): Promise<PublicState>;
  createVault(password: string,name?:string): Promise<PublicState|null>;
  openVault():Promise<PublicState|null>;
  selectVault(id:string):Promise<PublicState>;
  closeVault():Promise<PublicState>;
  forgetVault(id:string):Promise<PublicState>;
  showVaultInFolder(id?:string):Promise<boolean>;
  onVaultChanged(callback:(state:PublicState)=>void):()=>void;
  unlock(password: string): Promise<PublicState>;
  lock(): Promise<void>;
  activity(): void;
  addProfile(name: string): Promise<PublicState>;
  switchProfile(id: string): Promise<PublicState>;
  addServer(input: ServerInput): Promise<PublicState>;
  generateSSHKey(input: SSHKeyInput): Promise<PublicState>;
  deleteSSHKey(id: string): Promise<PublicState>;
  copyPublicSSHKey(id: string): Promise<boolean>
  exportSSHKey(id: string, kind: 'public' | 'private'): Promise<boolean>;
  probeServer(id: string): Promise<{ fingerprint: string }>;
  trustServer(id: string, fingerprint: string): Promise<PublicState>;
  checkServer(id: string): Promise<PublicState>;
  provision(input: ProvisionInput): Promise<PublicState>;
  repairServer(id: string): Promise<PublicState>;
  createConfig(input: ConfigInput): Promise<PublicState>;
  revealConfig(id: string): Promise<string>;
  exportConfig(id: string): Promise<boolean>;
  revokeConfig(id: string): Promise<PublicState>;
  createRoute(input: RouteInput): Promise<PublicState>;
  deleteRoute(id: string): Promise<PublicState>;
  deleteServer(id: string, confirmation: string, cleanup: boolean): Promise<PublicState>;
  saveVaultCopy():Promise<boolean>;
  setAutoLock(minutes: number): Promise<PublicState>;
  onProgress(callback: (progress: Progress) => void): () => void;
  onLocked(callback: () => void): () => void;
}
declare global { interface Window { manetka?: Api } }
