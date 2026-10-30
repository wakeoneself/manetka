import {chromium} from 'playwright-core'
import {mkdir,readFile,writeFile} from 'node:fs/promises'

const mark=await readFile('src/assets/logo.svg','utf8')
const inner=mark.slice(mark.indexOf('>')+1,mark.lastIndexOf('</svg>'))
const svg=`<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024"><rect x="64" y="64" width="896" height="896" rx="206" fill="#252729"/><g transform="translate(192 192) scale(20)">${inner}</g></svg>`
await mkdir('build',{recursive:true})
await writeFile('build/icon.svg',svg)
await writeFile('build/logo.svg',mark)
await writeFile('build/logo-mono.svg',mark.replace('<circle cx="16" cy="16" r="13.5" fill="#252729"/>','').replace('#EDB477','currentColor'))
const b=await chromium.launch({executablePath:'/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',headless:true})
try {
  const p=await b.newPage({viewport:{width:1024,height:1024},deviceScaleFactor:1})
  await p.setContent(`<html><body style="margin:0;background:transparent">${svg}</body></html>`)
  await p.screenshot({path:'build/icon.png',omitBackground:true})
  const chunks=[]
  for(const [type,size] of [['ic07',128],['ic08',256],['ic09',512],['ic10',1024]]) {
    await p.setViewportSize({width:size,height:size})
    await p.setContent(`<html><body style="margin:0;background:transparent">${svg.replace('width="1024" height="1024"',`width="${size}" height="${size}"`)}</body></html>`)
    const png=await p.screenshot({omitBackground:true})
    const header=Buffer.alloc(8);header.write(type);header.writeUInt32BE(png.length+8,4)
    chunks.push(header,png)
  }
  const body=Buffer.concat(chunks),header=Buffer.alloc(8);header.write('icns');header.writeUInt32BE(body.length+8,4)
  await writeFile('build/icon.icns',Buffer.concat([header,body]))
  await p.setViewportSize({width:512,height:512})
  await p.setContent(`<html><body style="margin:0;background:transparent">${mark.replace('width="32" height="32"','width="512" height="512"')}</body></html>`)
  await p.screenshot({path:'build/logo.png',omitBackground:true})
  const wordmark='<span class="wordmark"><span>ma</span><strong>NET</strong><span>ka</span></span>'
  const scaled=(size)=>mark.replace('width="32" height="32"',`width="${size}" height="${size}"`).replaceAll('route-cut',`route-cut-${size}`)
  const html=`<!doctype html><html><meta charset="utf-8"><style>*{box-sizing:border-box}body{margin:0;background:#171819;color:#edeeeb;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.board{width:1200px;height:760px;display:grid;grid-template-rows:1fr 220px}.hero{display:flex;align-items:center;justify-content:center;gap:34px}.wordmark{font-size:100px;font-weight:450;letter-spacing:-4px;display:inline-flex;align-items:baseline}.wordmark strong{font-weight:750;letter-spacing:-4.5px}.samples{display:grid;grid-template-columns:1fr 1fr;border-top:1px solid #343638}.sample{display:flex;align-items:center;justify-content:center;gap:32px}.sample.light{background:#f4f5f2;color:#252729}.sizes{display:flex;align-items:end;gap:25px}.caption{color:#969c96;font-size:11px;text-align:center;margin-top:10px;letter-spacing:.2px}.small-lockup{display:flex;align-items:center;gap:10px}.small-lockup .wordmark{font-size:28px;letter-spacing:-1px}.small-lockup .wordmark strong{letter-spacing:-1px}</style><body><main class="board"><section class="hero">${scaled(172)}${wordmark}</section><section class="samples"><div class="sample"><div class="sizes">${[24,48,80].map(size=>`<div>${scaled(size)}<div class="caption">${size}px</div></div>`).join('')}</div><div><img width="112" height="112" src="data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}"/><div class="caption">macOS</div></div></div><div class="sample light"><div class="small-lockup">${scaled(40)}${wordmark}</div></div></section></main></body></html>`
  await writeFile('design/brand.html',html)
  await p.setViewportSize({width:1200,height:760})
  await p.setContent(html)
  await p.evaluate(()=>document.fonts.ready)
  await p.screenshot({path:'design/brand.png'})
  await p.locator('.hero').screenshot({path:'design/logo-preview.png'})
} finally {await b.close()}
console.log('maNETka identity: SVG, transparent PNG, macOS ICNS and brand preview generated.')
