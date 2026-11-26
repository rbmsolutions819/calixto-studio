// Pasa a GitHub las fotos que la administradora subió a Firebase (galería y servicios)
// y deja un informe de uso. Modo: "mover" (por defecto) o "informe" (solo cuenta, no mueve nada).
import { initializeApp, cert } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";
import { writeFileSync, mkdirSync, appendFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { execSync } from "node:child_process";

const modo = process.env.MODO || "mover";
const llave = JSON.parse(process.env.LLAVE);
initializeApp({ credential: cert(llave) });
const db = getFirestore();

const esData = s => typeof s === "string" && s.startsWith("data:image/");
const ext = s => (s.match(/^data:image\/(\w+)/)?.[1] || "jpg").replace("jpeg", "jpg");
const bytes = s => Buffer.from(s.slice(s.indexOf(",") + 1), "base64");
const corto = b => createHash("sha1").update(b).digest("hex").slice(0, 10);

const cambios = [];   // [ref, datos] que se aplican en Firebase cuando los archivos ya están publicados
let movidas = 0, pesoFb = 0;

const gal = await db.collection("galeria").get();
for (const d of gal.docs) {
  const x = d.data(); if (x.tipo !== "foto" || !esData(x.data)) continue;
  const b = bytes(x.data); pesoFb += b.length;
  if (modo !== "mover") continue;
  const ruta = `img/galeria/${d.id}.${ext(x.data)}`;
  mkdirSync("img/galeria", { recursive: true }); writeFileSync(ruta, b);
  cambios.push([d.ref, { data: ruta }]); movidas++;
}
const serv = await db.collection("servicios").get();
for (const d of serv.docs) {
  const x = d.data(); if (!Array.isArray(x.fotos) || !x.fotos.some(esData)) continue;
  const nuevas = x.fotos.map(f => {
    if (!esData(f)) return f;
    const b = bytes(f); pesoFb += b.length;
    if (modo !== "mover") return f;
    const ruta = `img/trabajos/${d.id}-${corto(b)}.${ext(f)}`;
    mkdirSync("img/trabajos", { recursive: true }); writeFileSync(ruta, b); movidas++;
    return ruta;
  });
  if (modo === "mover") cambios.push([d.ref, { fotos: nuevas }]);
}

const contar = async c => (await db.collection(c).count().get()).data().count;
const uso = { fecha: new Date().toISOString(), modo, movidas, pesoFotosFirebaseMB: +(pesoFb / 1048576).toFixed(2),
  citas: await contar("citas"), clientas: await contar("clientas"), encuestas: await contar("encuestas"),
  sugerencias: await contar("sugerencias"), fotosGaleria: gal.docs.filter(d => d.data().tipo === "foto").length };
writeFileSync("uso.json", JSON.stringify(uso, null, 1) + "\n");

const resumen = `## Informe de Calixto Studio
| Dato | Valor |
|---|---|
| Fecha | ${uso.fecha} |
| Fotos que estaban en Firebase | ${modo === "mover" ? movidas + " (pasadas a GitHub)" : "sin mover"} · ${uso.pesoFotosFirebaseMB} MB |
| Fotos en la galería | ${uso.fotosGaleria} |
| Citas guardadas | ${uso.citas} |
| Clientas con tarjeta de sellos | ${uso.clientas} |
| Opiniones | ${uso.encuestas} |
| Sugerencias | ${uso.sugerencias} |
`;
console.log(resumen);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, resumen);

// Publicar en GitHub primero; cambiar Firebase solo cuando las fotos ya se vean en la página.
const sh = c => execSync(c, { stdio: "inherit" });
sh('git config user.name "RBM Solutions (automático)" && git config user.email "rbmsolutions819@users.noreply.github.com"');
sh("git add uso.json img/galeria img/trabajos 2>/dev/null || git add uso.json");
try { execSync("git diff --cached --quiet"); console.log("Nada nuevo que subir."); }
catch { sh(`git commit -m "Informe de uso${movidas ? ` y ${movidas} fotos pasadas de Firebase a GitHub` : ""}"`); sh("git push"); }

if (!cambios.length) process.exit(0);
const base = (process.env.PAGINA_URL || "").replace(/\/?$/, "/");
const primera = cambios[0][1].data || (cambios[0][1].fotos || []).find(f => f.startsWith("img/galeria/") || f.startsWith("img/trabajos/")), prueba = base + primera;
for (let i = 0; i < 40; i++) {             // esperar hasta 10 minutos a que GitHub Pages publique
  try { const r = await fetch(prueba, { cache: "no-store" }); if (r.ok) break; } catch {}
  await new Promise(r => setTimeout(r, 15000));
}
for (let i = 0; i < cambios.length; i += 400) {
  const b = db.batch(); cambios.slice(i, i + 400).forEach(([ref, datos]) => b.update(ref, datos)); await b.commit();
}
console.log(`Firebase actualizado: ${cambios.length} documentos ahora apuntan a las fotos en GitHub.`);
