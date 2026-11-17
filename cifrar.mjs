// Cifra / descifra el script con una clave.
//
//   Cifrar:     CLAVE='...' node cifrar.mjs cifrar   ruta/al/script.js  [cargar.js anterior] > nuevo.js
//               (si se da el cargar.js anterior, se conservan los DATOS que tenga escritos)
//   Descifrar:  CLAVE='...' node cifrar.mjs descifrar cargar.js           > script.js
//
// Esquema (implementable en JS puro, sin crypto.subtle, para que funcione
// también en páginas http://):
//   dk   = PBKDF2-HMAC-SHA256(clave, sal, ITER, 32 bytes)
//   kEnc = HMAC(dk, "cifrar"),  kMac = HMAC(dk, "verificar")
//   bloque j del flujo = HMAC(kEnc, iv || uint32be(j))  →  texto XOR flujo
//   etiqueta = HMAC(kMac, iv || cifrado)
//   datos = base64( sal[16] | iv[16] | etiqueta[32] | cifrado )

import crypto from 'node:crypto';
import fs from 'node:fs';

const ITER = 200000;
const hmac = (k, m) => crypto.createHmac('sha256', k).update(m).digest();
const u32 = j => { const b = Buffer.alloc(4); b.writeUInt32BE(j); return b; };

const flujo = (kEnc, iv, datos) => {
  const out = Buffer.alloc(datos.length);
  for (let o = 0, j = 0; o < datos.length; o += 32, j++) {
    const ks = hmac(kEnc, Buffer.concat([iv, u32(j)]));
    for (let i = 0; i < 32 && o + i < datos.length; i++) out[o + i] = datos[o + i] ^ ks[i];
  }
  return out;
};

const claves = (clave, sal) => {
  const dk = crypto.pbkdf2Sync(Buffer.from(clave, 'utf8'), sal, ITER, 32, 'sha256');
  return { kEnc: hmac(dk, 'cifrar'), kMac: hmac(dk, 'verificar') };
};

const [modo, ruta] = process.argv.slice(2);
const clave = process.env.CLAVE;
if (!clave || !ruta || !['cifrar', 'descifrar'].includes(modo)) {
  console.error("Uso: CLAVE='...' node cifrar.mjs cifrar|descifrar <archivo>");
  process.exit(1);
}

if (modo === 'cifrar') {
  const texto = fs.readFileSync(ruta);
  const sal = crypto.randomBytes(16), iv = crypto.randomBytes(16);
  const { kEnc, kMac } = claves(clave, sal);
  const cifrado = flujo(kEnc, iv, texto);
  const etiqueta = hmac(kMac, Buffer.concat([iv, cifrado]));
  const datos = Buffer.concat([sal, iv, etiqueta, cifrado]).toString('base64');
  const plantilla = fs.readFileSync(new URL('./plantilla-cargador.js', import.meta.url), 'utf8');
  let salida = plantilla.replace('__ITER__', String(ITER)).replace('__DATOS__', datos);
  const anterior = process.argv[4];
  if (anterior && fs.existsSync(anterior)) {
    const bloque = /  \/\/ ===== ✏️ DATOS[\s\S]*?\/\/ ===== fin de los datos =====/;
    const viejo = fs.readFileSync(anterior, 'utf8').match(bloque);
    if (viejo) salida = salida.replace(bloque, () => viejo[0]);
  }
  process.stdout.write(salida);
} else {
  const m = fs.readFileSync(ruta, 'utf8').match(/const DATOS = '([^']+)'/);
  if (!m) { console.error('No encontré DATOS en el archivo'); process.exit(1); }
  const b = Buffer.from(m[1], 'base64');
  const sal = b.subarray(0, 16), iv = b.subarray(16, 32), etiqueta = b.subarray(32, 64), cifrado = b.subarray(64);
  const { kEnc, kMac } = claves(clave, sal);
  if (!crypto.timingSafeEqual(etiqueta, hmac(kMac, Buffer.concat([iv, cifrado])))) {
    console.error('Clave incorrecta'); process.exit(2);
  }
  process.stdout.write(flujo(kEnc, iv, cifrado));
}
