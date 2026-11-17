# autorizacion-repetidos

Script para la consola del navegador (Chrome/Edge), **cifrado con clave**. Sin la clave el contenido no se puede leer.

## Uso

1. Abre la página, presiona **F12** → pestaña **Consola**.
2. Si no deja pegar, escribe `allow pasting` y Enter.
3. Abre `cargar.js` → **Raw**, copia todo, pégalo en la consola y presiona Enter.
4. Escribe la clave cuando la pida.

## Datos (código y observación)

Al inicio de `cargar.js` hay un bloque **sin cifrar** para escribir los datos:

```js
  // ===== ✏️ DATOS: edita aquí (código y observación) =====
  const REGISTROS = [
    { "codigo": "12345", "observacion": "Observación de prueba" }
  ];
  // ===== fin de los datos =====
```

Se puede editar en GitHub (lápiz ✏️ sobre `cargar.js`) o en la consola antes de presionar Enter. Al volver a cifrar el script, `cifrar.mjs` conserva este bloque si se le pasa el `cargar.js` anterior.

Para **ver el código sin ejecutarlo**: escribe `verCodigo = true` en la consola, presiona Enter y luego pega `cargar.js`. Para volver al modo normal: `verCodigo = false`.

## Archivos

| Archivo | Qué es |
|---|---|
| `cargar.js` | Script cifrado + cargador que pide la clave y lo ejecuta. |
| `validar.js` | Cifrado (misma clave). Revisa si los registros de su bloque ✏️ DATOS quedaron reversados (solo lee, no cambia nada). |
| `cifrar.mjs` | Herramienta (Node.js) para volver a cifrar o descifrar el script. |
| `plantilla-cargador.js` | Plantilla del cargador que usa `cifrar.mjs`. |

Cifrado: PBKDF2-HMAC-SHA256 + flujo HMAC-SHA256 + etiqueta HMAC (cifrar y luego autenticar), implementado en JS puro para que funcione también en páginas `http://`.
