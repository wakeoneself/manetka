import { createHash, randomUUID } from 'node:crypto'
import ssh2 from 'ssh2'
import type { Credential, SSHKey, SSHKeyUse, VaultData } from '../../src/model'

export function describePrivateKey(privateKey: string, passphrase?: string) {
  const parsed = ssh2.utils.parseKey(privateKey, passphrase)
  const key = Array.isArray(parsed) ? (parsed.length === 1 ? parsed[0] : undefined) : parsed
  if (!key || key instanceof Error || !key.isPrivateKey()) throw new Error('Не удалось прочитать приватный SSH-ключ. Проверьте формат и пароль ключа.')
  const blob = key.getPublicSSH()
  return {
    algorithm: key.type,
    publicKey: `${key.type} ${blob.toString('base64')} maNETka`,
    fingerprint: 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, ''),
  }
}

export async function generateSSHKey(name: string, passphrase?: string): Promise<SSHKey> {
  const pair = await new Promise<{ private: string; public: string }>((resolve, reject) => {
    ssh2.utils.generateKeyPair('ed25519', { comment: 'maNETka', ...(passphrase ? { cipher: 'aes256-ctr', passphrase, rounds: 32 } : {}) }, (error, pair) => error ? reject(new Error('Не удалось сгенерировать SSH-ключ')) : resolve(pair))
  })
  return { id: randomUUID(), name, ...describePrivateKey(pair.private, passphrase), privateKey: pair.private, ...(passphrase ? { passphrase } : {}), createdAt: new Date().toISOString() }
}

export function resolveCredential(credential: Credential, keys: SSHKey[]): Credential {
  if (credential.type !== 'key' || !credential.keyId) return credential
  const key = keys.find(k => k.id === credential.keyId)
  if (!key) throw new Error('SSH-ключ сервера не найден в хранилище')
  return { type: 'key', privateKey: key.privateKey, passphrase: key.passphrase }
}

export function keyUses(data: VaultData, keyId: string): SSHKeyUse[] {
  const key = data.sshKeys.find(k => k.id === keyId)
  const uses: SSHKeyUse[] = []
  for (const profile of data.profiles) for (const server of profile.servers) {
    let matches = server.credential.type === 'key' && server.credential.keyId === keyId
    // Also protect equivalent legacy inline credentials until migration has been persisted.
    if (!matches && key && server.credential.type === 'key' && server.credential.privateKey) {
      try { matches = describePrivateKey(server.credential.privateKey, server.credential.passphrase).fingerprint === key.fingerprint } catch { /* invalid legacy credential remains untouched */ }
    }
    const pending = server.pendingSshKeyId === keyId
    if (matches || pending) uses.push({ serverId: server.id, serverName: server.name, host: server.host, profileId: profile.id, profileName: profile.name, pending: pending && !matches })
  }
  return uses
}

/** Additive migration: no remote actions, key rotation or removal of valid credentials. */
export function migrateSSHKeys(data: VaultData): boolean {
  let changed = false
  data.sshKeys ??= []
  for (const profile of data.profiles) for (const server of profile.servers) {
    const credential = server.credential
    if (credential.type !== 'key' || credential.keyId || !credential.privateKey) continue
    try {
      const details = describePrivateKey(credential.privateKey, credential.passphrase)
      let stored = data.sshKeys.find(k => k.fingerprint === details.fingerprint)
      if (!stored) {
        stored = { id: randomUUID(), name: `${server.name.slice(0, 72)} · SSH`, ...details, privateKey: credential.privateKey, ...(credential.passphrase ? { passphrase: credential.passphrase } : {}), createdAt: server.checkedAt ?? new Date().toISOString() }
        data.sshKeys.push(stored)
      }
      server.credential = { type: 'key', keyId: stored.id }
      changed = true
    } catch { /* Preserve unreadable legacy input; never lock the user out of their vault. */ }
  }
  return changed
}

export function validateStoredSSHKeys(keys: SSHKey[]) {
  for (const key of keys) {
    const actual = describePrivateKey(key.privateKey, key.passphrase)
    if (actual.fingerprint !== key.fingerprint || actual.publicKey !== key.publicKey || actual.algorithm !== key.algorithm) throw new Error('Повреждены данные SSH-ключа')
  }
}
