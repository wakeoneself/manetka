import { useState, type FormEvent } from 'react'
import { ArrowDownToLine, Check, Copy, KeyRound, Loader2, LockKeyhole, Plus, Trash2 } from 'lucide-react'
import { Button, Field, Modal } from './components'
import type { Api, PublicSSHKey } from './model'

type Run = <T>(fn: (api: Api) => Promise<T>, success?: string) => Promise<T | undefined>
type DialogProps = { busy: boolean; error: string; close: () => void; run: Run }
const date = (value: string) => new Intl.DateTimeFormat('ru-RU', { day: 'numeric', month: 'short', year: 'numeric' }).format(new Date(value))

export function SSHKeysView({ keys, busy, onCreate, onOpen, onDelete }: { keys: PublicSSHKey[]; busy: boolean; onCreate: () => void; onOpen: (id: string) => void; onDelete: (id: string) => void }) {
  return <>
    <header className="page-header"><div><h1>SSH-ключи</h1><p>Ключи серверов в этом хранилище</p></div><Button variant="primary" disabled={busy} onClick={onCreate}><Plus size={16}/>Сгенерировать ключ</Button></header>
    {keys.length ? <div className="table-wrap"><table className="ssh-key-table"><thead><tr><th>Название</th><th>Fingerprint</th><th>Использование</th><th/></tr></thead><tbody>{keys.map(key => <tr key={key.id}>
      <td><button className="table-name" onClick={() => onOpen(key.id)}><KeyRound size={18}/><span><b>{key.name}</b><small>{key.algorithm === 'ssh-ed25519' ? 'Ed25519' : key.algorithm} · {date(key.createdAt)}</small></span></button></td>
      <td><span className="key-fingerprint mono" title={key.fingerprint}>{key.fingerprint}</span></td>
      <td><div className="key-usage">{key.uses.length ? <><span><LockKeyhole size={12}/>Используется</span><small title={key.uses.map(u => `${u.profileName}: ${u.serverName} (${u.host})`).join('\n')}>{key.uses.map(u => u.serverName).join(', ')}</small></> : <span className="muted">Свободен</span>}</div></td>
      <td><button className="icon-button" disabled={busy || !key.canDelete} onClick={() => onDelete(key.id)} title={key.canDelete ? 'Удалить свободный ключ' : 'Ключ связан с сервером и защищён от удаления'} aria-label={`Удалить ключ ${key.name}`}><Trash2 size={15}/></button></td>
    </tr>)}</tbody></table></div> : <div className="empty"><KeyRound size={30} strokeWidth={1.3}/><h2>SSH-ключей пока нет</h2><p>Сгенерируйте ключ здесь или при добавлении сервера.</p><Button onClick={onCreate}>Сгенерировать ключ</Button></div>}
    <div className="footnote"><LockKeyhole size={14}/><span>Приватные ключи зашифрованы в хранилище. Связанные с серверами ключи нельзя удалить, даже если сервер недоступен.</span></div>
  </>
}

export function PublicKeyPanel({ sshKey, installationHint = false, onCopy }: { sshKey: PublicSSHKey; installationHint?: boolean; onCopy: () => Promise<boolean | undefined> }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try { const success = await onCopy(); if (!success) return; setCopied(true); setTimeout(() => setCopied(false), 2000) } catch { setCopied(false) }
  }
  return <div className="public-key-panel"><div className="section-heading"><h3>Публичный ключ</h3><Button type="button" onClick={copy}>{copied ? <Check size={13}/> : <Copy size={13}/>} {copied ? 'Скопировано' : 'Копировать'}</Button></div><pre>{sshKey.publicKey}</pre>{installationHint && <p>До проверки доступа добавьте этот публичный ключ в панели провайдера или в <code>~/.ssh/authorized_keys</code> пользователя root. Генерация ключа сама по себе не настраивает сервер.</p>}</div>
}

export function GenerateSSHKeyDialog({ busy, error, close, run, onCreated }: DialogProps & { onCreated: (id: string) => void }) {
  const [name, setName] = useState(''), [passphrase, setPassphrase] = useState(''), [confirm, setConfirm] = useState('')
  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (passphrase !== confirm) return
    const result = await run(a => a.generateSSHKey({ name, ...(passphrase ? { passphrase } : {}) }), 'SSH-ключ сгенерирован')
    if (result) { setPassphrase(''); setConfirm(''); onCreated(result.sshKeys.at(-1)!.id) }
  }
  return <Modal title="Сгенерировать SSH-ключ" subtitle="Ed25519 · генерация на этом компьютере" busy={busy} onClose={close}><form onSubmit={submit}>
    <Field label="Название ключа"><input required maxLength={80} value={name} placeholder="Например, Хельсинки · SSH" onChange={e => setName(e.target.value)}/></Field>
    <details className="advanced"><summary>Дополнительный пароль ключа</summary><Field label="Пароль ключа" hint="Необязательно. Само хранилище уже зашифровано. Пароль ключа сохраняется внутри него."><input type="password" autoComplete="new-password" minLength={12} maxLength={1024} value={passphrase} onChange={e => setPassphrase(e.target.value)}/></Field><Field label="Повторите пароль ключа"><input type="password" autoComplete="new-password" value={confirm} onChange={e => setConfirm(e.target.value)}/></Field></details>
    <p className="modal-copy">Публичную часть можно добавить на сервер. Приватная часть останется в зашифрованном хранилище и попадёт в резервную копию.</p>
    {error && <div className="inline-error" role="alert">{error}</div>}{confirm && passphrase !== confirm && <p className="inline-error">Пароли ключа не совпадают</p>}
    <div className="modal-footer"><Button type="button" disabled={busy} onClick={close}>Отмена</Button><Button type="submit" variant="primary" disabled={busy || passphrase !== confirm || !!(passphrase && passphrase.length < 12)}>{busy ? <Loader2 className="spin" size={15}/> : <KeyRound size={15}/>}Сгенерировать</Button></div>
  </form></Modal>
}

export function SSHKeyDetailDialog({ sshKey: key, busy, error, close, run, onDelete }: DialogProps & { sshKey: PublicSSHKey; onDelete: () => void }) {
  return <Modal title={key.name} subtitle={key.algorithm === 'ssh-ed25519' ? 'Ed25519' : key.algorithm} busy={busy} onClose={close}>
    <dl className="ssh-key-facts"><div><dt>Создан</dt><dd>{date(key.createdAt)}</dd></div><div><dt>Пароль ключа</dt><dd>{key.encrypted ? 'Задан' : 'Не задан'}</dd></div></dl>
    <div className="fingerprint"><span>SHA-256 fingerprint</span><code>{key.fingerprint}</code></div>
    <PublicKeyPanel sshKey={key} onCopy={() => run(a => a.copyPublicSSHKey(key.id))}/>
    <div className="ssh-key-servers"><h3>Связанные серверы</h3>{key.uses.length ? key.uses.map(use => <div key={use.serverId}><span><LockKeyhole size={12}/>{use.serverName}{use.pending ? ' · установка не завершена' : ''}</span><small>{use.profileName} · {use.host}</small></div>) : <p className="muted">Ключ пока не связан с сервером.</p>}</div>
    {!key.canDelete && <p className="warning-copy">Этот ключ защищён от удаления. Проверка учитывает все профили и серверы с потерянной связью.</p>}
    {error && <div className="inline-error" role="alert">{error}</div>}
    <div className="modal-footer"><button className="text-button danger" disabled={busy || !key.canDelete} onClick={onDelete} title={!key.canDelete ? 'Ключ используется сервером' : undefined}><Trash2 size={14}/>Удалить ключ</button><Button disabled={busy} onClick={() => void run(a => a.exportSSHKey(key.id, 'public'), 'Публичный ключ сохранён')}><ArrowDownToLine size={14}/>Сохранить .pub</Button></div>
    <details className="advanced key-export"><summary>Экспорт приватного ключа</summary><p className="warning-copy">Файл предоставляет доступ к связанным серверам. Храните его отдельно от публичной части.</p><Button disabled={busy} onClick={() => void run(a => a.exportSSHKey(key.id, 'private'), 'Приватный ключ экспортирован')}>Экспортировать приватный ключ</Button></details>
  </Modal>
}

export function DeleteSSHKeyDialog({ sshKey: key, busy, error, close, run }: DialogProps & { sshKey: PublicSSHKey }) {
  return <Modal title="Удалить SSH-ключ?" subtitle={key.name} busy={busy} onClose={close}><p className="modal-copy">{key.canDelete ? 'Ключ не связан ни с одним сервером в хранилище. Его приватная часть будет удалена из приложения. Убедитесь, что он не используется вне maNETka.' : 'Ключ связан с сервером и защищён от удаления. Сначала удалите связанные серверы.'}</p>{error && <div className="inline-error" role="alert">{error}</div>}<div className="modal-footer"><Button disabled={busy} onClick={close}>Отмена</Button><Button variant="destructive" disabled={busy || !key.canDelete} onClick={() => void run(a => a.deleteSSHKey(key.id), 'SSH-ключ удалён').then(value => { if (value) close() })}>Удалить ключ</Button></div></Modal>
}
