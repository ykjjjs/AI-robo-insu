/* 로컬 검증용 정적 서버 (Cloudflare Pages 동작 모사)
   - /foo  → public/foo.html  (clean URL)
   - /api/* → 실배포(ai-robo-insu.pages.dev)로 프록시
   배포물에는 포함되지 않는 개발 전용 파일입니다. */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, 'public');
const PORT = 8788;
const UPSTREAM = 'ai-robo-insu.pages.dev';

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
               '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
               '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  let p = decodeURIComponent(url.pathname);

  if (p.startsWith('/api/')) {                       // API는 실배포로 프록시
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const up = https.request({
        hostname: UPSTREAM, path: req.url, method: req.method,
        headers: { ...req.headers, host: UPSTREAM }
      }, r => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      up.on('error', e => { res.writeHead(502); res.end('proxy error: ' + e.message); });
      if (body.length) up.write(body);
      up.end();
    });
    return;
  }

  if (p === '/') p = '/index.html';
  let file = path.join(ROOT, p);
  if (!fs.existsSync(file) && fs.existsSync(file + '.html')) file += '.html';   // clean URL

  if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('404 Not Found: ' + p);
  }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
  fs.createReadStream(file).pipe(res);
}).listen(PORT, () => console.log('dev server → http://localhost:' + PORT));
