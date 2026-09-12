// ═══════════════════════════════════════════════════════════════
// GATE DE AUTENTICACIÓN REAL para pedidos.html
// ═══════════════════════════════════════════════════════════════
// 🔒 Este archivo va ADELANTE de tus archivos estáticos (pedidos.html,
// logo.png, etc). Nada de eso se entrega al navegador hasta que este
// Worker confirme que la sesión es válida — la verificación pasa
// SIEMPRE por el servidor, nunca por JavaScript en el navegador. Así:
//   - Nadie puede ver la contraseña con "Ver código fuente" (antes
//     estaba escrita en texto plano en el HTML).
//   - Nadie puede saltear el login abriendo la consola del navegador
//     y seteando una variable a mano (antes alcanzaba con eso).
//
// CÓMO SE USA:
//   1. En tu repositorio de GitHub (el mismo que tiene pedidos.html),
//      poné este archivo con el nombre EXACTO "_worker.js" en la raíz
//      (al lado de pedidos.html). Cloudflare lo detecta automáticamente
//      y lo ejecuta ANTES de servir cualquier archivo estático.
//   2. En Cloudflare → tu Worker → Settings → Variables and Secrets,
//      agregá estos 2 secrets:
//        - PANEL_PIN: la contraseña real que vos vas a tipear para
//          entrar (podés seguir usando la misma que ya tenías, o
//          cambiarla — te recomiendo cambiarla, ya que la vieja quedó
//          expuesta en el código durante un tiempo).
//        - SESSION_SECRET: pegá exactamente este valor generado al
//          azar (no lo cambies, ya viene listo):
//          _qV5-r3LqO_ggflXyUoc3A0UKqHCl14eoyQcXdBOQVk
//   3. Volvé a desplegar el Worker (Cloudflare lo hace solo si está
//      conectado a GitHub — con el próximo push ya se aplica).
// ═══════════════════════════════════════════════════════════════

const COOKIE_NAME = 'rw_panel_session';
const SESSION_DURATION_HORAS = 12;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // ── Ruta de login (POST con la contraseña) ──
    if (url.pathname === '/__login' && request.method === 'POST') {
      return handleLogin(request, env);
    }

    // ── Ruta de logout ──
    if (url.pathname === '/__logout') {
      return new Response(null, {
        status: 302,
        headers: {
          'Location': '/',
          'Set-Cookie': `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`,
        },
      });
    }

    // ── Verificar sesión para TODO lo demás ──
    const sesionValida = await verificarSesion(request, env);
    if (!sesionValida) {
      return paginaDeLogin();
    }

    // Sesión válida → dejar pasar al archivo estático real (pedidos.html, etc).
    return env.ASSETS.fetch(request);
  },
};

// ─────────────────────────────────────────────
// Verificación de contraseña — ESTO corre en el servidor, nunca en el
// navegador. Devuelve un 401 genérico si falla (sin decir si fue la
// contraseña o algún otro dato, para no dar pistas).
// ─────────────────────────────────────────────
async function handleLogin(request, env) {
  if (!env.PANEL_PIN || !env.SESSION_SECRET) {
    return new Response('Panel no configurado — faltan los secrets PANEL_PIN o SESSION_SECRET en este Worker.', { status: 503 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: 'Solicitud inválida' }, 400);
  }

  const pin = (body.pin || '').trim();

  // 🔒 Comparación en tiempo constante — evita filtrar por cuánto tarda
  // la respuesta si la contraseña es parcialmente correcta.
  const coincide = await compararEnTiempoConstante(pin, env.PANEL_PIN);
  if (!coincide) {
    // Pequeña demora fija para dificultar intentos automáticos rápidos.
    await new Promise(r => setTimeout(r, 400));
    return json({ ok: false, error: 'Contraseña incorrecta' }, 401);
  }

  const token = await crearTokenSesion(env);
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': `${COOKIE_NAME}=${token}; Path=/; Max-Age=${SESSION_DURATION_HORAS * 3600}; HttpOnly; Secure; SameSite=Strict`,
    },
  });
}

// ─────────────────────────────────────────────
// Sesión firmada con HMAC — el navegador solo guarda un token opaco;
// no hay forma de "adivinar" ni fabricar uno válido sin conocer
// SESSION_SECRET (que solo vive en Cloudflare, nunca en el HTML).
// ─────────────────────────────────────────────
async function crearTokenSesion(env) {
  const expira = Date.now() + SESSION_DURATION_HORAS * 3600 * 1000;
  const payload = `ok.${expira}`;
  const firma = await firmar(payload, env.SESSION_SECRET);
  return `${payload}.${firma}`;
}

async function verificarSesion(request, env) {
  if (!env.SESSION_SECRET) return false;
  const cookie = obtenerCookie(request, COOKIE_NAME);
  if (!cookie) return false;

  const partes = cookie.split('.');
  if (partes.length !== 3) return false;
  const [marca, expiraStr, firmaRecibida] = partes;
  if (marca !== 'ok') return false;

  const payload = `${marca}.${expiraStr}`;
  const firmaEsperada = await firmar(payload, env.SESSION_SECRET);
  if (firmaRecibida !== firmaEsperada) return false;

  const expira = Number(expiraStr);
  if (!expira || Date.now() > expira) return false;

  return true;
}

async function firmar(texto, secreto) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secreto),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const firma = await crypto.subtle.sign('HMAC', key, encoder.encode(texto));
  return Array.from(new Uint8Array(firma)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function compararEnTiempoConstante(a, b) {
  const encoder = new TextEncoder();
  const bufA = encoder.encode(a);
  const bufB = encoder.encode(b);
  if (bufA.length !== bufB.length) {
    // Igual se hace un cómputo del mismo largo que "b" para no filtrar
    // la longitud por timing.
    await crypto.subtle.digest('SHA-256', bufB);
    return false;
  }
  const [hashA, hashB] = await Promise.all([
    crypto.subtle.digest('SHA-256', bufA),
    crypto.subtle.digest('SHA-256', bufB),
  ]);
  const arrA = new Uint8Array(hashA), arrB = new Uint8Array(hashB);
  let diff = 0;
  for (let i = 0; i < arrA.length; i++) diff |= arrA[i] ^ arrB[i];
  return diff === 0;
}

function obtenerCookie(request, nombre) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(new RegExp(`${nombre}=([^;]+)`));
  return match ? match[1] : null;
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

// ─────────────────────────────────────────────
// Página de login real — se sirve ANTES de que exista sesión. El
// panel completo (pedidos.html) nunca llega al navegador hasta acá.
// ─────────────────────────────────────────────
function paginaDeLogin() {
  const html = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Revende Ways | Panel de Pedidos</title>
<style>
  :root { --blue:#0066ff; --bg:#0b0d12; --surface:#1c1f2a; --border:rgba(255,255,255,.12); --text:#e8eaf0; --text2:#9aa0b4; --red:#f43f5e; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text); font-family:'DM Sans',sans-serif; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px 16px; }
  .box { background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:32px 28px; width:100%; max-width:340px; }
  h1 { font-size:20px; margin-bottom:4px; }
  p { color:var(--text2); font-size:12px; margin-bottom:20px; }
  label { display:block; font-size:11px; font-weight:700; color:var(--text2); margin-bottom:6px; text-transform:uppercase; letter-spacing:.6px; }
  input { width:100%; padding:11px 14px; background:#111318; border:1px solid var(--border); border-radius:8px; color:var(--text); font-size:14px; margin-bottom:16px; }
  input:focus { outline:none; border-color:var(--blue); }
  button { width:100%; padding:13px; background:var(--blue); color:#fff; border:none; border-radius:8px; font-size:15px; font-weight:700; cursor:pointer; }
  button:disabled { opacity:.6; cursor:not-allowed; }
  .err { background:rgba(244,63,94,.12); color:var(--red); border:1px solid rgba(244,63,94,.2); padding:10px 14px; border-radius:8px; font-size:13px; margin-bottom:16px; display:none; }
  .err.show { display:block; }
</style>
</head>
<body>
  <div class="box">
    <h1>Panel de Pedidos</h1>
    <p>Ingresá la contraseña para acceder</p>
    <div class="err" id="err"></div>
    <label>Contraseña</label>
    <input type="password" id="pin" autocomplete="off" onkeydown="if(event.key==='Enter')ingresar()"/>
    <button id="btn" onclick="ingresar()">Ingresar</button>
  </div>
  <script>
    async function ingresar() {
      const pin = document.getElementById('pin').value;
      const btn = document.getElementById('btn');
      const err = document.getElementById('err');
      err.classList.remove('show');
      btn.disabled = true; btn.textContent = 'Verificando...';
      try {
        const res = await fetch('/__login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pin }),
        });
        if (res.ok) {
          location.reload();
        } else {
          const data = await res.json().catch(() => ({}));
          err.textContent = data.error || 'Contraseña incorrecta';
          err.classList.add('show');
        }
      } catch (e) {
        err.textContent = 'Error de conexión';
        err.classList.add('show');
      }
      btn.disabled = false; btn.textContent = 'Ingresar';
    }
  </script>
</body>
</html>`;
  return new Response(html, { status: 401, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}