import { spawn } from 'node:child_process'
import { createServer } from 'vite'
import './build-electron.mjs'
const server = await createServer()
await server.listen()
const child = spawn((await import('electron')).default, ['.'], { stdio: 'inherit', env: { ...process.env, MANETKA_DEV: '1' } })
child.on('exit', async code => { await server.close(); process.exit(code ?? 0) })
process.on('SIGINT', () => child.kill())
