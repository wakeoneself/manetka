import { build } from 'esbuild'
await build({ entryPoints: ['electron/main.ts'], outdir: 'dist-electron', bundle: true, platform: 'node', format: 'esm', target: 'node22', external: ['electron', 'ssh2'], banner: { js: "import { createRequire as manetkaCreateRequire } from 'node:module'; const require = manetkaCreateRequire(import.meta.url);" } })
await build({ entryPoints: ['electron/preload.ts'], outfile: 'dist-electron/preload.cjs', bundle: true, platform: 'node', format: 'cjs', external: ['electron'] })
