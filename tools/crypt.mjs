// Packs the plaintext source in src/ into an encrypted index.html, or restores src/ from it.
//   GAV_PASSWORD=... node tools/crypt.mjs build    src/  -> index.html
//   GAV_PASSWORD=... node tools/crypt.mjs unpack   index.html -> src/
import { readFileSync, writeFileSync, readdirSync, mkdirSync, statSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { webcrypto as crypto } from 'node:crypto';

const ROOT = join(dirname(new URL(import.meta.url).pathname), '..');
const SRC = join(ROOT, 'src');
const OUT = join(ROOT, 'index.html');
const ITER = 310000;

const pw = process.env.GAV_PASSWORD;
if (!pw) { console.error('Set GAV_PASSWORD'); process.exit(1); }

async function keyFor(salt) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
const b64 = u8 => Buffer.from(u8).toString('base64');
const unb64 = s => new Uint8Array(Buffer.from(s, 'base64'));

function walk(dir) {
  const out = [];
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) out.push(...walk(p)); else out.push(p);
  }
  return out;
}

async function build() {
  const files = {};
  for (const f of walk(SRC)) files[relative(SRC, f)] = readFileSync(f, 'utf8');
  const plain = new TextEncoder().encode(JSON.stringify(files));
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await keyFor(salt), plain));
  const payload = JSON.stringify({ v: 1, it: ITER, s: b64(salt), i: b64(iv), c: b64(ct) });
  writeFileSync(OUT, LOADER.replace('__PAYLOAD__', () => payload));
  console.log('wrote index.html', (payload.length / 1024).toFixed(0) + ' KB,', Object.keys(files).length, 'files');
}

async function unpack() {
  const html = readFileSync(OUT, 'utf8');
  const P = JSON.parse(html.match(/<script id="payload" type="application\/json">([\s\S]*?)<\/script>/)[1]);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(P.i) }, await keyFor(unb64(P.s)), unb64(P.c));
  const files = JSON.parse(new TextDecoder().decode(plain));
  for (const [name, body] of Object.entries(files)) {
    const p = join(SRC, name);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, body);
  }
  console.log('restored', Object.keys(files).length, 'files into src/');
}

const LOADER = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#16161a">
<title>GAV</title>
<style>
html,body{margin:0;height:100%;background:#16161a;color:#eee;font:16px ui-monospace,Menlo,Consolas,monospace}
body{display:flex;align-items:center;justify-content:center}
form{display:flex;flex-direction:column;gap:12px;width:min(300px,86vw);text-align:center}
.ring{width:72px;height:72px;margin:0 auto 8px;border-radius:50%;border:14px solid #F7931E;border-bottom-color:#FFE600;border-right-color:transparent;box-sizing:border-box;transform:rotate(-20deg)}
input,button{font:inherit;padding:12px;border-radius:8px;border:0}
input[type=password]{background:#2b2b33;color:#fff;text-align:center;letter-spacing:2px}
button{background:#F7931E;color:#16161a;font-weight:bold}
label{font-size:12px;color:#aaa}
#e{min-height:1em;color:#ff7070;font-size:13px}
</style>
</head>
<body>
<form id="f">
  <div class="ring"></div>
  <input id="p" type="password" placeholder="password" autocomplete="current-password" autofocus>
  <label><input id="r" type="checkbox" checked> remember on this device</label>
  <button>INSERT CARTRIDGE</button>
  <div id="e"></div>
</form>
<script id="payload" type="application/json">__PAYLOAD__</script>
<script>
(function () {
  var P = JSON.parse(document.getElementById('payload').textContent);
  var K = 'gav_key_' + P.s.slice(0, 8);
  var enc = new TextEncoder();
  function u8(s) { var b = atob(s), a = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; }
  function s64(a) { var s = ''; for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); }
  function derive(pw) {
    return crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']).then(function (base) {
      return crypto.subtle.deriveBits({ name: 'PBKDF2', salt: u8(P.s), iterations: P.it, hash: 'SHA-256' }, base, 256);
    });
  }
  function open(raw, remember) {
    return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']).then(function (key) {
      return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u8(P.i) }, key, u8(P.c));
    }).then(function (plain) {
      if (remember) { try { localStorage.setItem(K, s64(new Uint8Array(raw))); } catch (e) {} }
      var files = JSON.parse(new TextDecoder().decode(plain));
      var html = files['index.html'].replace(/<script src="([^"]+)"><\\/script>/g, function (m, name) {
        return '<script>' + files[name] + '<\\/script>';
      });
      document.open(); document.write(html); document.close();
    });
  }
  var saved = null;
  try { saved = localStorage.getItem(K); } catch (e) {}
  if (saved) open(u8(saved), false).catch(function () { try { localStorage.removeItem(K); } catch (e) {} });
  document.getElementById('f').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var err = document.getElementById('e');
    err.textContent = 'checking...';
    derive(document.getElementById('p').value).then(function (raw) {
      return open(raw, document.getElementById('r').checked);
    }).catch(function () { err.textContent = 'Nope. Try again.'; });
  });
})();
</script>
</body>
</html>
`;

const cmd = process.argv[2];
if (cmd === 'build') await build();
else if (cmd === 'unpack') await unpack();
else { console.error('usage: node tools/crypt.mjs build|unpack'); process.exit(1); }
