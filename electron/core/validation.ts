import { z } from 'zod'
import { isIP } from 'node:net'
import { PROTOCOLS } from '../../src/model'

export const idSchema = z.uuid()
export const nameSchema = z.string().trim().min(1).max(80).refine(s => !/[\x00-\x1f\x7f]/.test(s), 'Недопустимые символы в названии')
export const portSchema = z.number().int().min(1).max(65535)
export const hostSchema = z.string().max(253).refine(s => isIP(s) === 4, 'Введите IPv4-адрес сервера')
export const domainSchema = z.string().max(253).regex(/^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/)
export const fingerprintSchema = z.string().regex(/^SHA256:[A-Za-z0-9+/]{43}$/)
export const protocolSchema = z.enum(PROTOCOLS)
export const passwordSchema = z.string().min(12, 'Минимум 12 символов').max(1024)
export const credentialSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('password'), password: z.string().min(1).max(4096) }).strict(),
  z.object({ type: z.literal('key'), keyId: idSchema.optional(), privateKey: z.string().min(50).max(32768).optional(), passphrase: z.string().max(4096).optional() }).strict().refine(v => v.keyId ? !v.privateKey && v.passphrase === undefined : !!v.privateKey, 'Выберите сохранённый ключ или укажите приватный ключ'),
])
export const sshKeyInputSchema = z.object({ name: nameSchema, passphrase: z.string().min(12).max(1024).optional() }).strict()
const sshKeySchema = z.object({id:idSchema,name:nameSchema,algorithm:z.string().min(1).max(80),publicKey:z.string().min(20).max(32768).refine(s=>!/[\r\n]/.test(s)),fingerprint:fingerprintSchema,privateKey:z.string().min(50).max(32768),passphrase:z.string().max(4096).optional(),createdAt:z.iso.datetime()}).strict()
export const serverInputSchema = z.object({ name: nameSchema, host: hostSchema, port: portSchema, username: z.literal('root'), credential: credentialSchema, fingerprint: fingerprintSchema.optional() }).strict()
export const provisionSchema = z.object({ serverId: idSchema, protocol: protocolSchema, port: portSchema, sni: domainSchema, domain: z.union([z.literal(''), domainSchema]), path: z.string().regex(/^\/[a-zA-Z0-9/_-]{1,100}$/), harden: z.boolean(), dedicated: z.literal(true) }).strict().refine(v => v.protocol !== 'vless-ws' || v.domain.length > 0, 'Для WebSocket нужен домен')
const cidr = (s: string) => { const [ip, prefix, extra] = s.split('/'); return !extra && isIP(ip) > 0 && /^\d+$/.test(prefix ?? '') && Number(prefix) <= (isIP(ip) === 4 ? 32 : 128) }
export const configInputSchema = z.object({ name: nameSchema, serverId: idSchema, protocol: protocolSchema, routeId: idSchema.optional(), dns: z.string().max(200).refine(s => s.split(',').every(p => isIP(p.trim()) > 0), 'DNS: IP-адреса через запятую'), mtu: z.number().int().min(1280).max(1500), allowedIPs: z.string().max(1000).refine(s => s.split(',').every(p => cidr(p.trim())), 'Неверная подсеть AllowedIPs') }).strict()
export const routeInputSchema = z.object({ name: nameSchema, entryId: idSchema, exitId: idSchema, protocol: protocolSchema, port: portSchema }).strict().refine(v => v.entryId !== v.exitId, 'Для моста нужны два разных сервера')
export function shellQuote(value: string): string { if (value.includes('\0')) throw new Error('NUL запрещён'); return "'" + value.replaceAll("'", "'\\''") + "'" }

const keySchema = z.string().regex(/^(?:[A-Za-z0-9+/]{43}=|[A-Za-z0-9_-]{43})$/)
const awgSchema = z.object({Jc:z.number().int().min(1).max(128),Jmin:z.number().int().min(0).max(1280),Jmax:z.number().int().min(0).max(1280),S1:z.number().int().min(0).max(1000),S2:z.number().int().min(0).max(1000),H1:z.number().int().min(5).max(4294967295),H2:z.number().int().min(5).max(4294967295),H3:z.number().int().min(5).max(4294967295),H4:z.number().int().min(5).max(4294967295)}).strict().refine(v=>v.Jmin<=v.Jmax&&new Set([v.H1,v.H2,v.H3,v.H4]).size===4,'Некорректные параметры AWG')
const settingsSchema = z.object({ port: portSchema, sni: domainSchema, domain: z.union([z.literal(''), domainSchema]), path: z.string().regex(/^\/[a-zA-Z0-9/_-]{1,100}$/), mtu: z.number().int().min(1280).max(1500), dns: z.string().max(200).refine(s=>s.split(',').every(p=>isIP(p.trim())>0)), awg: awgSchema.optional(), privateKey: keySchema.optional(), publicKey: keySchema.optional(), shortId: z.string().regex(/^[a-f0-9]{16}$/).optional() }).strict()
const serverSchema = serverInputSchema.extend({ id: idSchema, status: z.enum(['new','verified','ready','error','partial']), os: z.string().max(200).optional(), arch: z.string().max(40).optional(), checkedAt: z.iso.datetime().optional(), protocols: z.partialRecord(protocolSchema, settingsSchema), managed: z.boolean(), ownerId: idSchema, pendingSshKeyId: idSchema.optional(), hardened: z.boolean().optional(), resourceNamespace: z.enum(['manetka','monetka']).optional() }).strict()
const configSchema = z.object({ id: idSchema, name: nameSchema, serverId: idSchema, protocol: protocolSchema, routeId: idSchema.optional(), createdAt: z.iso.datetime(), content: z.string().max(65536), publicKey: keySchema.optional(), address: hostSchema.optional(), clientId: idSchema.optional(), revoked: z.boolean() }).strict()
const storedRouteSchema = z.object({ id: idSchema, name: nameSchema, entryId: idSchema, exitId: idSchema, protocol: protocolSchema, port: portSchema, status: z.enum(['ready','partial']), createdAt: z.iso.datetime() }).strict()
export const vaultDataSchema = z.object({ version: z.literal(1), installationId: idSchema, activeProfileId: idSchema, sshKeys: z.array(sshKeySchema).max(1000).default([]), autoLockMinutes: z.number().int().min(1).max(60), profiles: z.array(z.object({ id: idSchema, name: nameSchema, servers: z.array(serverSchema).max(200), configs: z.array(configSchema).max(5000), routes: z.array(storedRouteSchema).max(500) }).strict()).min(1).max(50), audit: z.array(z.object({ id: idSchema, at: z.iso.datetime(), action: z.string().max(200) }).strict()).max(500) }).strict().superRefine((data, ctx) => {
  const ids = new Set<string>()
  const keyIds = new Set(data.sshKeys.map(k=>k.id))
  const fingerprints = new Set<string>()
  for (const key of data.sshKeys) {
    if (ids.has(key.id) || fingerprints.has(key.fingerprint)) ctx.addIssue({code:'custom',message:'Повторяющийся SSH-ключ'})
    ids.add(key.id);fingerprints.add(key.fingerprint)
  }
  for (const p of data.profiles) {
    for (const item of [p, ...p.servers, ...p.configs, ...p.routes]) { if (ids.has(item.id)) ctx.addIssue({code:'custom',message:'Повторяющийся ID'}); ids.add(item.id) }
    for (const server of p.servers) {
      if ((server.credential.type === 'key' && server.credential.keyId && !keyIds.has(server.credential.keyId)) || (server.pendingSshKeyId && !keyIds.has(server.pendingSshKeyId))) ctx.addIssue({code:'custom',message:'SSH-ключ сервера не найден'})
    }
    const servers = new Map(p.servers.map(s => [s.id,s]))
    const routes = new Map(p.routes.map(r => [r.id,r]))
    for (const r of p.routes) if (r.entryId === r.exitId || !servers.has(r.entryId) || !servers.get(r.exitId)?.protocols[r.protocol]) ctx.addIssue({code:'custom',message:'Повреждён маршрут'})
    for (const c of p.configs) if (!servers.has(c.serverId) || (c.routeId && (routes.get(c.routeId)?.exitId !== c.serverId || routes.get(c.routeId)?.protocol !== c.protocol))) ctx.addIssue({code:'custom',message:'Повреждён конфиг'})
  }
  if (!data.profiles.some(p => p.id === data.activeProfileId)) ctx.addIssue({code:'custom',message:'Нет активного профиля'})
})
