<<<<<<< HEAD
# Extractor de PKG de PS4 (para shadPS4)

Saca los archivos de un `.pkg` de PS4 a una carpeta de juego que shadPS4 pueda leer.
Pensado para PKG de juegos que tú mismo volcaste de tu consola (fake PKG / fpkg).

## Uso con ventana (lo más fácil)

1. Instala Python 3.8+ desde https://www.python.org/downloads/ (marca *Add python.exe to PATH*).
2. Haz doble clic en `Iniciar_Extractor.bat` (o ejecuta `python pkg_extractor.py` sin argumentos).
3. Si arriba aparece el aviso de que falta una librería, pulsa **Instalar requisitos**
   (instala `cryptography` con pip; también puedes hacerlo a mano con `pip install -r requirements.txt`).
4. Elige el `.pkg` y la carpeta de salida (la que usarás como *Game Install Directory* en shadPS4)
   y pulsa **Extraer**. Hay botones para **Comprobar claves** (verifica el passcode sin escribir
   nada) y **Ver contenido**. «Opciones avanzadas» permite cambiar passcode, EKPFS, sufijo de parche
   y carpeta plana. **Cancelar** detiene la extracción y borra el archivo a medias.

Si la ventana no abre, ejecuta el `.bat` desde una consola para ver el error; la ventana también
escribe `pkg_extractor_gui_error.log`. Los ajustes se guardan en `~/.ps4_pkg_extractor.json`.

## Uso por línea de comandos

```
python pkg_extractor.py install-deps
python pkg_extractor.py info    juego.pkg [--check]
python pkg_extractor.py list    juego.pkg
python pkg_extractor.py extract juego.pkg -o C:\shadps4\games
```

`info` y `list` de la cabecera funcionan sin `cryptography`; `extract` y `--check` la necesitan.
`extract` crea una subcarpeta con el TITLE_ID del juego (por ejemplo `CUSA12345`) dentro de la
carpeta de salida. En shadPS4, apunta *Settings → Game Install Directory* a esa carpeta de salida
y pulsa *Refresh List*.

Opciones útiles de `extract`:

| Opción | Para qué sirve |
|---|---|
| `--passcode P` | Passcode de 32 caracteres. Por defecto son 32 ceros, el valor habitual de los fpkg. |
| `--ekpfs HEX` | EKPFS en hexadecimal (64 caracteres), si lo tienes de otra fuente. Anula `--passcode`. |
| `--flat` | Extrae directamente en la carpeta de salida, sin subcarpeta por TITLE_ID. |
| `--patch-suffix S` | Sufijo de carpeta para parches (por defecto `-patch`). Ver más abajo. |
| `--no-meta` | No copia a `sce_sys` los archivos de sistema que el PKG guarda aparte del PFS (`playgo-chunk.dat`, trofeos, `icon0.png`...). Por defecto sí se copian. |
| `--entries` | Guarda también `param.sfo`, `icon0.png`, etc. del PKG en `_pkg_entries/`. |

## Alcance y límites

- **No incluye claves de Sony.** El PFS se descifra con el passcode o con el EKPFS que le des.
  Un PKG comercial descargado de la tienda, cifrado con claves de Sony, no se puede abrir con esta
  herramienta; en ese caso termina con un error claro y no escribe archivos corruptos.
- **Parches y DLC:** el nombre de carpeta que espera shadPS4 para parches ha cambiado entre
  versiones. No verifiqué cuál espera la tuya; si no reconoce el parche, prueba con
  `--patch-suffix -UPDATE`. Los DLC (`category ac`) se extraen a una carpeta con el Content ID y
  su ubicación final hay que ajustarla a mano.
- Instala primero el juego base y después los parches.
- Los PFS de 64 bits y los árboles de bloques de segundo nivel indirecto (archivos de más de
  ~120 MB con bloques no contiguos) siguen el código de referencia pero no se probaron.

## Cómo se verificó

El formato se implementó leyendo el código de LibOrbisPkg (OpenOrbis, código abierto):
cabecera y tabla de entradas del PKG, `param.sfo`, PFS (inodos firmados y sin firmar), PFSC y
AES-XTS. `python -m unittest test_pkg_extractor` ejecuta 39 pruebas con PKG sintéticos
generados por un escritor propio, incluida la ventana (se omiten si no hay tkinter/pantalla). El XTS se contrastó con una transcripción manual del
algoritmo de referencia.

**Lo que no se pudo comprobar:** ningún PKG real. Y la derivación de claves (`compute_ekpfs`,
`pfs_gen_enc_key`) no tiene un vector de respuesta conocida contra el cual validarla; se
transcribió dos veces desde el código de referencia. Probado en Python 3.12 / Linux (Xvfb);
`Iniciar_Extractor.bat` y el uso con `pythonw` en Windows no se probaron. Si con tu PKG sale el error de
"passcode o EKPFS incorrectos", esa es la primera pieza a revisar.
=======
# PKG-autoExtractor
Pkg autoExtractor is a pkg extractor for easy use into the shadPS4 emulator.
>>>>>>> 605690399c9fe5b643918ab0d2c1b4370337bb92
