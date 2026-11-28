// Calixto Studio · servicio de avisos (Cloudflare Worker)
// Envía una notificación al celular de la administradora cada vez que alguien agenda,
// aunque la app esté cerrada (Web Push). No necesita apps extra.
//
// Necesita: un espacio KV enlazado con el nombre AVISOS.
// Las claves VAPID se crean solas la primera vez y se guardan en ese KV (nadie tiene que copiarlas).
//
// Rutas:
//   GET  /clave      → clave pública VAPID (la página la usa para suscribirse)
//   POST /suscribir  → { token, sub }  guarda el celular de la administradora (token = sesión de Firebase)
//   POST /quitar     → { token, endpoint }
//   POST /prueba     → { token }  manda un aviso de prueba a los celulares suscritos
//   POST /aviso      → { cita, fecha, ini, titulo, cuerpo }  lo llama la página al agendar; se valida contra Firestore

const PROYECTO = "calixto-reservas";
const API_KEY = "AIzaSyCisIsOXhHEj7jTxrtNd4oxVo_eYbLXKcY";
const ADMINS = ["admin@calixtostudio.com", "rbmsolutions819@gmail.com"];
const ORIGENES = ["https://calixtostudiocr.com", "https://www.calixtostudiocr.com", "https://rbmsolutionscr.com"];
const CONTACTO = "https://calixtostudiocr.com";
const APP_URL = "https://calixtostudiocr.com/#admin";

const enc = new TextEncoder();
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const deB64u = s => { s = s.replace(/-/g, "+").replace(/_/g, "/"); s += "===".slice((s.length + 3) % 4); return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
const unir = (...partes) => { const n = partes.reduce((a, p) => a + p.length, 0); const o = new Uint8Array(n); let i = 0; for (const p of partes) { o.set(p, i); i += p.length; } return o; };
const sha256 = async s => b64u(await crypto.subtle.digest("SHA-256", enc.encode(s)));

function cors(req) {
  const o = req.headers.get("Origin") || "";
  const ok = ORIGENES.includes(o) || /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(o);
  return { "Access-Control-Allow-Origin": ok ? o : ORIGENES[0], "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type", "Vary": "Origin" };
}
const json = (req, data, status = 200) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...cors(req) } });

// ---------- claves VAPID (se crean solas) ----------
async function vapid(env) {
  let v = await env.AVISOS.get("vapid", "json");
  if (!v) {
    const par = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    v = { privada: await crypto.subtle.exportKey("jwk", par.privateKey), publica: b64u(await crypto.subtle.exportKey("raw", par.publicKey)) };
    await env.AVISOS.put("vapid", JSON.stringify(v));
  }
  return v;
}
async function jwtVapid(v, endpoint) {
  const aud = new URL(endpoint).origin;
  const cab = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const cuerpo = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: CONTACTO })));
  const llave = await crypto.subtle.importKey("jwk", v.privada, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const firma = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, llave, enc.encode(cab + "." + cuerpo));
  return cab + "." + cuerpo + "." + b64u(firma);
}

// ---------- cifrado del mensaje (RFC 8291, aes128gcm) ----------
async function hmac(clave, datos) {
  const k = await crypto.subtle.importKey("raw", clave, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, datos));
}
export async function cifrar(texto, p256dh, auth) {
  const uaPub = deB64u(p256dh), secreto = deB64u(auth);
  const par = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", par.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, par.privateKey, 256));
  const prkKey = await hmac(secreto, ecdh);
  const ikm = await hmac(prkKey, unir(enc.encode("WebPush: info\0"), uaPub, asPub, new Uint8Array([1])));
  const sal = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hmac(sal, ikm);
  const cek = (await hmac(prk, unir(enc.encode("Content-Encoding: aes128gcm\0"), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmac(prk, unir(enc.encode("Content-Encoding: nonce\0"), new Uint8Array([1])))).slice(0, 12);
  const k = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const cifrado = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, k, unir(enc.encode(texto), new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 16, 0]);
  return unir(sal, rs, new Uint8Array([asPub.length]), asPub, cifrado);
}
async function empujar(env, v, sub, datos) {
  const cuerpo = await cifrar(JSON.stringify(datos), sub.keys.p256dh, sub.keys.auth);
  return fetch(sub.endpoint, { method: "POST", body: cuerpo, headers: {
    "Authorization": `vapid t=${await jwtVapid(v, sub.endpoint)}, k=${v.publica}`,
    "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", "TTL": "86400", "Urgency": "high" } });
}
async function avisarATodas(env, datos) {
  const v = await vapid(env);
  const lista = await env.AVISOS.list({ prefix: "sub:" });
  let enviados = 0;
  for (const k of lista.keys) {
    const s = await env.AVISOS.get(k.name, "json"); if (!s) continue;
    try {
      const r = await empujar(env, v, s.sub, datos);
      if (r.status === 404 || r.status === 410) await env.AVISOS.delete(k.name);   // celular ya no existe
      else if (r.ok) enviados++;
    } catch {}
  }
  return enviados;
}

// ---------- sesión de Firebase (para saber que es la administradora) ----------
async function adminDeToken(token) {
  try {
    const [c, p, f] = token.split(".");
    const cab = JSON.parse(new TextDecoder().decode(deB64u(c)));
    const pl = JSON.parse(new TextDecoder().decode(deB64u(p)));
    const ahora = Date.now() / 1000;
    if (cab.alg !== "RS256" || pl.aud !== PROYECTO || pl.iss !== "https://securetoken.google.com/" + PROYECTO || pl.exp < ahora || pl.iat > ahora + 300) return null;
    const jwks = await (await fetch("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com", { cf: { cacheTtl: 3600 } })).json();
    const jwk = jwks.keys.find(k => k.kid === cab.kid); if (!jwk) return null;
    const llave = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", llave, deB64u(f), enc.encode(c + "." + p));
    return ok && ADMINS.includes(pl.email) ? pl.email : null;
  } catch { return null; }
}

// ---------- validar que la cita existe (los espacios ocupados son públicos en Firestore) ----------
const hhmm = m => String(Math.floor(m / 60)).padStart(2, "0") + String(m % 60).padStart(2, "0");
async function citaReal(cita, fecha, ini) {
  if (!/^[A-Za-z0-9]{10,40}$/.test(cita) || !/^\d{4}-\d{2}-\d{2}$/.test(fecha) || !(ini >= 0 && ini < 1440)) return false;
  const url = `https://firestore.googleapis.com/v1/projects/${PROYECTO}/databases/(default)/documents/ocupados/${fecha}_${hhmm(ini)}?key=${API_KEY}`;
  const r = await fetch(url); if (!r.ok) return false;
  const d = await r.json();
  return d.fields?.cita?.stringValue === cita;
}
const corto = (s, n) => String(s || "").slice(0, n);

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response(null, { headers: cors(req) });
    if (req.method === "GET" && url.pathname === "/clave") return new Response((await vapid(env)).publica, { headers: { "Content-Type": "text/plain", ...cors(req) } });
    if (req.method === "GET" && url.pathname === "/") return new Response("Avisos de Calixto Studio: funcionando", { headers: cors(req) });
    if (req.method !== "POST") return json(req, { error: "ruta" }, 404);
    let b; try { b = await req.json(); } catch { return json(req, { error: "datos" }, 400); }

    if (url.pathname === "/suscribir" || url.pathname === "/quitar" || url.pathname === "/prueba") {
      const email = await adminDeToken(String(b.token || ""));
      if (!email) return json(req, { error: "sesion" }, 401);
      if (url.pathname === "/prueba") {
        const n = await avisarATodas(env, { title: "✅ Avisos de Calixto Studio", body: "Así te va a llegar cada cita nueva, aunque la app esté cerrada.", url: APP_URL, tag: "prueba" });
        return json(req, { ok: true, enviados: n });
      }
      const endpoint = url.pathname === "/quitar" ? b.endpoint : b.sub?.endpoint;
      if (!/^https:\/\//.test(String(endpoint || ""))) return json(req, { error: "sub" }, 400);
      const clave = "sub:" + await sha256(endpoint);
      if (url.pathname === "/quitar") { await env.AVISOS.delete(clave); return json(req, { ok: true }); }
      if (!b.sub.keys?.p256dh || !b.sub.keys?.auth) return json(req, { error: "sub" }, 400);
      await env.AVISOS.put(clave, JSON.stringify({ email, sub: { endpoint, keys: { p256dh: b.sub.keys.p256dh, auth: b.sub.keys.auth } }, desde: Date.now() }));
      return json(req, { ok: true });
    }

    if (url.pathname === "/aviso") {
      const cita = String(b.cita || "");
      if (await env.AVISOS.get("visto:" + cita)) return json(req, { ok: true, repetido: true });
      if (!(await citaReal(cita, String(b.fecha || ""), +b.ini))) return json(req, { error: "cita" }, 400);
      await env.AVISOS.put("visto:" + cita, "1", { expirationTtl: 60 * 60 * 24 * 30 });
      const n = await avisarATodas(env, { title: corto(b.titulo, 120) || "📅 Nueva cita", body: corto(b.cuerpo, 600), url: APP_URL, tag: "cita-" + cita });
      return json(req, { ok: true, enviados: n });
    }
    return json(req, { error: "ruta" }, 404);
  }
};
