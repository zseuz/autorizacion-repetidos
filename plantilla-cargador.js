// Script cifrado. Pégalo completo en la consola (F12) y escribe la clave.
// Para solo VER el código sin ejecutarlo: escribe  verCodigo = true  en la consola antes de pegarlo.
(() => {
  // ===== ✏️ DATOS: edita aquí (código y observación) =====
  const REGISTROS = [
    { "codigo": "12345", "observacion": "Observación de prueba" }
  ];
  // ===== fin de los datos =====

  const ITER = __ITER__;
  const DATOS = '__DATOS__';

  // ---- SHA-256 / HMAC / PBKDF2 en JS puro (funciona también en http://) ----
  const sha256 = (() => {
    const K = new Uint32Array(64), H0 = new Uint32Array(8), W = new Uint32Array(64);
    const frac = x => ((x - Math.floor(x)) * 0x100000000) >>> 0;
    for (let n = 2, i = 0; i < 64; n++) {
      let primo = true;
      for (let d = 2; d * d <= n; d++) if (n % d === 0) { primo = false; break; }
      if (primo) { if (i < 8) H0[i] = frac(Math.pow(n, 1 / 2)); K[i] = frac(Math.pow(n, 1 / 3)); i++; }
    }
    return msg => {
      const l = msg.length, nb = ((l + 9 + 63) >> 6) << 6;
      const m = new Uint8Array(nb); m.set(msg); m[l] = 0x80;
      const dv = new DataView(m.buffer);
      dv.setUint32(nb - 4, (l * 8) >>> 0); dv.setUint32(nb - 8, Math.floor(l / 0x20000000));
      const h = H0.slice();
      for (let o = 0; o < nb; o += 64) {
        for (let t = 0; t < 16; t++) W[t] = dv.getUint32(o + t * 4);
        for (let t = 16; t < 64; t++) {
          const a = W[t - 15], b = W[t - 2];
          const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
          const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
          W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
        }
        let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
        for (let t = 0; t < 64; t++) {
          const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
          const t1 = (k + S1 + ((e & f) ^ (~e & g)) + K[t] + W[t]) | 0;
          const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
          const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
          k = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += k;
      }
      const out = new Uint8Array(32), odv = new DataView(out.buffer);
      for (let i = 0; i < 8; i++) odv.setUint32(i * 4, h[i]);
      return out;
    };
  })();
  const unir = (...a) => {
    const r = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
    let o = 0; for (const x of a) { r.set(x, o); o += x.length; } return r;
  };
  const hmacCon = clave => {
    if (clave.length > 64) clave = sha256(clave);
    const k = new Uint8Array(64); k.set(clave);
    const ip = k.map(x => x ^ 0x36), op = k.map(x => x ^ 0x5c);
    return msg => sha256(unir(op, sha256(unir(ip, msg))));
  };
  const txt = s => new TextEncoder().encode(s);
  const u32 = j => new Uint8Array([j >>> 24, (j >>> 16) & 255, (j >>> 8) & 255, j & 255]);

  // ---- Descifrado ----
  const clave = prompt('Clave del script:');
  if (!clave) { console.warn('Cancelado'); return; }
  console.log('🔐 Descifrando…');

  const b = Uint8Array.from(atob(DATOS), c => c.charCodeAt(0));
  const sal = b.subarray(0, 16), iv = b.subarray(16, 32), etiqueta = b.subarray(32, 64), cifrado = b.subarray(64);

  const prf = hmacCon(txt(clave));
  let u = prf(unir(sal, u32(1)));
  const dk = u.slice();
  for (let i = 1; i < ITER; i++) { u = prf(u); for (let j = 0; j < 32; j++) dk[j] ^= u[j]; }
  const hk = hmacCon(dk);
  const kEnc = hk(txt('cifrar')), kMac = hk(txt('verificar'));

  const esperada = hmacCon(kMac)(unir(iv, cifrado));
  let dif = 0; for (let i = 0; i < 32; i++) dif |= esperada[i] ^ etiqueta[i];
  if (dif) { console.error('❌ Clave incorrecta'); return; }

  const fEnc = hmacCon(kEnc), plano = new Uint8Array(cifrado.length);
  for (let o = 0, j = 0; o < cifrado.length; o += 32, j++) {
    const ks = fEnc(unir(iv, u32(j)));
    for (let i = 0; i < 32 && o + i < cifrado.length; i++) plano[o + i] = cifrado[o + i] ^ ks[i];
  }
  const codigo = new TextDecoder().decode(plano);
  console.log('✅ Clave correcta');

  // Modo ver código: escribe  verCodigo = true  en la consola antes de pegar este script
  if (window.verCodigo) {
    console.log(codigo);
    console.log('ℹ️ Arriba está el código descifrado (no se ejecutó). Clic derecho → "Copy string contents" para copiarlo.\n' +
                '   Para volver a ejecutarlo normal: escribe  verCodigo = false  y pega de nuevo el script.');
    return;
  }

  // pasa los datos de arriba al script descifrado
  window.__registrosAutorizacion = REGISTROS;

  try {
    (0, eval)(codigo);
  } catch (e) {
    console.error('❌ La página no deja ejecutar el código descifrado:', e.message);
    try { copy(codigo); console.log('📋 Lo copié al portapapeles: pégalo en la consola y presiona Enter.'); } catch (_) {}
  }
})();
