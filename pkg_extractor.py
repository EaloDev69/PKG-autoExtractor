#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pkg_extractor.py - Extractor de PKG de PS4 para usar el juego en shadPS4.

Pensado para PKG de juegos que tú mismo volcaste de tu consola (fake PKG / fpkg).
Lee la cabecera, la tabla de entradas, param.sfo y el sistema de archivos PFS
(AES-XTS + PFSC) y deja la carpeta del juego lista para el emulador.

El formato se implementó siguiendo la documentación del proyecto de código abierto
LibOrbisPkg (OpenOrbis). La herramienta NO incluye claves de Sony: el PFS se
descifra con el passcode del PKG (por defecto 32 ceros, el valor habitual de los
fpkg) o con un EKPFS que tú le entregues.

Uso (sin argumentos se abre la ventana: pkg_extractor_gui.py):
    python pkg_extractor.py install-deps
    python pkg_extractor.py info    juego.pkg [--check]
    python pkg_extractor.py list    juego.pkg [--passcode P | --ekpfs HEX]
    python pkg_extractor.py extract juego.pkg -o SALIDA [--passcode P | --ekpfs HEX]
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import hmac
import importlib
import os
import re
import shutil
import struct
import subprocess
import sys
import zlib
from dataclasses import dataclass
from typing import Callable, Dict, Iterator, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Dependencia opcional: 'cryptography' (se puede instalar desde la interfaz)
# --------------------------------------------------------------------------- #
REQUIREMENTS = ["cryptography"]
Cipher = algorithms = modes = None
CRYPTO_OK = False


def load_crypto() -> bool:
    """Intenta importar 'cryptography'. Se puede volver a llamar tras instalarla."""
    global Cipher, algorithms, modes, CRYPTO_OK
    importlib.invalidate_caches()
    for attempt in range(2):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _c, algorithms as _a, modes as _m
        except ImportError:
            if attempt == 0:
                # Una instalación con --user puede crear una carpeta que aún no estaba en sys.path.
                with contextlib.suppress(Exception):
                    import site
                    user_site = site.getusersitepackages()
                    if os.path.isdir(user_site):
                        site.addsitedir(user_site)
                importlib.invalidate_caches()
                continue
            CRYPTO_OK = False
            return False
        Cipher, algorithms, modes = _c, _a, _m
        CRYPTO_OK = True
        return True
    return False


load_crypto()

# --------------------------------------------------------------------------- #
# Constantes del formato
# --------------------------------------------------------------------------- #
PKG_MAGIC = 0x7F434E54          # "\x7fCNT", big-endian
PKG_ENTRY_SIZE = 0x20
PFSC_MAGIC = 0x43534650         # "PFSC", little-endian
PFS_MAGIC = 20130315
PFS_VERSION = 1
XTS_SECTOR_SIZE = 0x1000
PFS_FLAG_NEW_CRYPT = 0x2000000000000000
DEFAULT_PASSCODE = "0" * 32

ENTRY_ID_ENTRY_NAMES = 0x200
ENTRY_ID_PARAM_SFO = 0x1000

KNOWN_ENTRY_NAMES: Dict[int, str] = {
    0x1000: "param.sfo",
    0x1001: "playgo-chunk.dat",
    0x1002: "playgo-chunk.sha",
    0x1003: "playgo-manifest.xml",
    0x1006: "pic1.png",
    0x1200: "icon0.png",
    0x1220: "pic0.png",
    0x1240: "snd0.at9",
    0x1260: "changeinfo/changeinfo.xml",
}

CONTENT_TYPES = {
    0x1A: "GD (juego, parche o remaster)",
    0x1B: "AC (DLC con datos / tema)",
    0x1C: "AL (DLC sin datos)",
    0x1E: "DP (parche delta)",
}

COPY_CHUNK = 4 * 1024 * 1024

Log = Callable[[str], None]


class PkgError(Exception):
    """Error legible para el usuario."""


class Cancelled(Exception):
    """La operación fue cancelada por el usuario."""


def require_crypto() -> None:
    if not CRYPTO_OK:
        raise PkgError(
            "Falta la librería 'cryptography'. Pulsa «Instalar requisitos» en la ventana "
            "o ejecuta:  python pkg_extractor.py install-deps"
        )


# --------------------------------------------------------------------------- #
# Lectores (todos exponen read(offset, n) -> bytes)
# --------------------------------------------------------------------------- #
def read_exact(reader, offset: int, n: int) -> bytes:
    data = reader.read(offset, n)
    if len(data) != n:
        raise PkgError(
            f"Lectura incompleta en 0x{offset:x}: se pidieron {n} bytes y llegaron "
            f"{len(data)}. ¿El PKG está truncado o incompleto?"
        )
    return data


class Region:
    """Ventana [base, base+size) sobre un archivo abierto."""

    def __init__(self, f, base: int, size: int):
        self.f, self.base, self.size = f, base, size

    def read(self, offset: int, n: int) -> bytes:
        if offset < 0 or n < 0:
            raise PkgError("Lectura con offset o tamaño negativo")
        if offset >= self.size or n == 0:
            return b""
        n = min(n, self.size - offset)
        self.f.seek(self.base + offset)
        return self.f.read(n)


class XtsReader:
    """Descifra al vuelo con AES-XTS-128 (tweak = nº de sector en little-endian)."""

    def __init__(self, inner, data_key: bytes, tweak_key: bytes,
                 start_sector: int, sector_size: int = XTS_SECTOR_SIZE):
        require_crypto()
        self.inner = inner
        self.key = data_key + tweak_key      # 'cryptography' espera data||tweak
        self.start = start_sector
        self.ss = sector_size

    def _decrypt_sector(self, idx: int, buf: bytes) -> bytes:
        dec = Cipher(algorithms.AES(self.key),
                     modes.XTS(idx.to_bytes(16, "little"))).decryptor()
        return dec.update(buf) + dec.finalize()

    def read(self, offset: int, n: int) -> bytes:
        if n <= 0:
            return b""
        ss = self.ss
        first, last = offset // ss, (offset + n - 1) // ss
        span = (last - first + 1) * ss
        raw = self.inner.read(first * ss, span).ljust(span, b"\0")
        out = bytearray()
        for k, idx in enumerate(range(first, last + 1)):
            sector = raw[k * ss:(k + 1) * ss]
            out += self._decrypt_sector(idx, sector) if idx >= self.start else sector
        skip = offset - first * ss
        return bytes(out[skip:skip + n])


class PfscReader:
    """Presenta un archivo PFSC (bloques con deflate) como si fuera plano."""

    def __init__(self, inner):
        self.inner = inner
        hdr = read_exact(inner, 0, 0x30)
        magic, unk4, _unk8, block_sz, block_sz2, block_offsets, _data_start, data_len = \
            struct.unpack("<iiiiqqQq", hdr)
        if magic != PFSC_MAGIC:
            raise PkgError("La imagen interna no es un PFSC válido")
        if unk4 != 0 or block_sz != block_sz2 or block_sz <= 0:
            raise PkgError("Cabecera PFSC inesperada")
        self.block_sz = block_sz
        self.data_len = data_len
        num_blocks = data_len // block_sz2
        raw = read_exact(inner, block_offsets, 8 * (num_blocks + 1))
        self.sector_map = list(struct.unpack(f"<{num_blocks + 1}q", raw))

    def _read_sector(self, idx: int) -> bytes:
        off = self.sector_map[idx]
        size = self.sector_map[idx + 1] - off
        bs = self.block_sz
        if size == bs:
            return read_exact(self.inner, off, bs)
        if size > bs or size <= 2:
            return b"\0" * bs
        comp = read_exact(self.inner, off, size)
        out = zlib.decompressobj(-15).decompress(comp[2:])   # salta la cabecera zlib
        return out.ljust(bs, b"\0")[:bs]

    def read(self, offset: int, n: int) -> bytes:
        if offset < 0 or n < 0:
            raise PkgError("Lectura PFSC con offset o tamaño negativo")
        n = max(0, min(n, self.data_len - offset))
        out = bytearray()
        bs = self.block_sz
        while n > 0:
            idx, within = divmod(offset, bs)
            sector = self._read_sector(idx)
            take = min(bs - within, n)
            out += sector[within:within + take]
            offset += take
            n -= take
        return bytes(out)


class ContiguousFile:
    def __init__(self, reader, base: int):
        self.reader, self.base = reader, base

    def read(self, offset: int, n: int) -> bytes:
        return self.reader.read(self.base + offset, n)


class ChunkedFile:
    """Archivo cuyos bloques no son contiguos (lista explícita de bloques)."""

    def __init__(self, reader, block_size: int, blocks: List[int]):
        self.reader, self.bs, self.blocks = reader, block_size, blocks

    def read(self, offset: int, n: int) -> bytes:
        out = bytearray()
        while n > 0:
            idx, within = divmod(offset, self.bs)
            if idx >= len(self.blocks):
                break
            take = min(self.bs - within, n)
            out += self.reader.read(self.blocks[idx] * self.bs + within, take)
            offset += take
            n -= take
        return bytes(out)


# --------------------------------------------------------------------------- #
# Criptografía
# --------------------------------------------------------------------------- #
def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def compute_ekpfs(content_id: str, passcode: str) -> bytes:
    """EKPFS = SHA256( SHA256(índice 1, BE) || SHA256(content_id relleno a 48) || passcode )."""
    if len(content_id) != 36:
        raise PkgError(f"El Content ID debe tener 36 caracteres (tiene {len(content_id)})")
    if len(passcode) != 32:
        raise PkgError("El passcode debe tener exactamente 32 caracteres")
    data = (_sha256(struct.pack(">I", 1))
            + _sha256(content_id.encode("ascii").ljust(48, b"\0"))
            + passcode.encode("ascii"))
    return _sha256(data)


def pfs_gen_enc_key(ekpfs: bytes, seed: bytes, new_crypt: bool) -> Tuple[bytes, bytes]:
    """Devuelve (tweak_key, data_key) para AES-XTS a partir del EKPFS y la semilla del PFS."""
    base = hmac.new(ekpfs, seed, hashlib.sha256).digest() if new_crypt else ekpfs
    enc = hmac.new(base, struct.pack("<I", 1) + seed, hashlib.sha256).digest()
    return enc[:16], enc[16:32]


# --------------------------------------------------------------------------- #
# Cabecera y tabla de entradas del PKG
# --------------------------------------------------------------------------- #
@dataclass
class PkgHeader:
    flags: int
    entry_count: int
    entry_table_offset: int
    body_offset: int
    body_size: int
    content_id: str
    drm_type: int
    content_type: int
    content_flags: int
    pfs_image_count: int
    pfs_flags: int
    pfs_image_offset: int
    pfs_image_size: int
    package_size: int


@dataclass
class Entry:
    id: int
    name_offset: int
    flags1: int
    flags2: int
    offset: int
    size: int
    name: str = ""

    @property
    def encrypted(self) -> bool:
        return bool(self.flags1 & 0x80000000)


def read_header(f) -> PkgHeader:
    f.seek(0)
    raw = f.read(0x440)
    if len(raw) < 0x440:
        raise PkgError("El archivo es demasiado pequeño para ser un PKG de PS4")
    magic, flags = struct.unpack_from(">II", raw, 0)
    if magic != PKG_MAGIC:
        raise PkgError("No es un PKG de PS4 (falta la firma \\x7fCNT al inicio del archivo)")
    entry_count, = struct.unpack_from(">I", raw, 0x10)
    entry_table_offset, = struct.unpack_from(">I", raw, 0x18)
    body_offset, body_size = struct.unpack_from(">QQ", raw, 0x20)
    content_id = raw[0x40:0x70].split(b"\0")[0].decode("ascii", "replace")
    drm_type, content_type, content_flags = struct.unpack_from(">III", raw, 0x70)
    pfs_image_count, = struct.unpack_from(">I", raw, 0x404)
    pfs_flags, pfs_off, pfs_size = struct.unpack_from(">QQQ", raw, 0x408)
    package_size, = struct.unpack_from(">Q", raw, 0x430)
    return PkgHeader(flags, entry_count, entry_table_offset, body_offset, body_size,
                     content_id, drm_type, content_type, content_flags,
                     pfs_image_count, pfs_flags, pfs_off, pfs_size, package_size)


def read_entries(f, hdr: PkgHeader) -> List[Entry]:
    if hdr.entry_count > 0x10000:
        raise PkgError(f"Número de entradas absurdo ({hdr.entry_count}): PKG corrupto")
    reader = Region(f, 0, os.fstat(f.fileno()).st_size)
    raw = read_exact(reader, hdr.entry_table_offset, hdr.entry_count * PKG_ENTRY_SIZE)
    entries: List[Entry] = []
    for i in range(hdr.entry_count):
        eid, name_off, flags1, flags2, off, size, _pad = struct.unpack_from(
            ">IIIIIIQ", raw, i * PKG_ENTRY_SIZE)
        entries.append(Entry(eid, name_off, flags1, flags2, off, size))

    names_blob = b""
    for e in entries:
        if e.id == ENTRY_ID_ENTRY_NAMES and not e.encrypted and 0 < e.size < 0x100000:
            names_blob = read_exact(reader, e.offset, e.size)
    for e in entries:
        if e.name_offset and e.name_offset < len(names_blob):
            end = names_blob.find(b"\0", e.name_offset)
            end = len(names_blob) if end < 0 else end
            e.name = names_blob[e.name_offset:end].decode("utf-8", "replace")
        elif e.id in KNOWN_ENTRY_NAMES:
            e.name = KNOWN_ENTRY_NAMES[e.id]
        else:
            e.name = f"entry_{e.id:08x}.bin"
    return entries


def read_entry_data(f, e: Entry) -> bytes:
    return read_exact(Region(f, 0, os.fstat(f.fileno()).st_size), e.offset, e.size)


# --------------------------------------------------------------------------- #
# param.sfo
# --------------------------------------------------------------------------- #
def parse_sfo(data: bytes) -> Dict[str, object]:
    if data[:4] != b"\x00PSF":
        raise PkgError("param.sfo inválido (falta la firma PSF)")
    _ver, key_start, data_start, count = struct.unpack_from("<IIII", data, 4)
    out: Dict[str, object] = {}
    for i in range(count):
        koff, fmt, length, _maxlen, doff = struct.unpack_from("<HHIII", data, 0x14 + 16 * i)
        kend = data.index(b"\0", key_start + koff)
        key = data[key_start + koff:kend].decode("utf-8", "replace")
        raw = data[data_start + doff:data_start + doff + length]
        if fmt == 0x404:
            out[key] = struct.unpack("<i", raw[:4])[0]
        else:
            out[key] = raw.split(b"\0")[0].decode("utf-8", "replace")
    return out


def load_sfo(f, entries: List[Entry]) -> Optional[Dict[str, object]]:
    for e in entries:
        if e.id == ENTRY_ID_PARAM_SFO and not e.encrypted:
            try:
                return parse_sfo(read_entry_data(f, e))
            except (PkgError, ValueError, struct.error):
                return None
    return None


# --------------------------------------------------------------------------- #
# PFS
# --------------------------------------------------------------------------- #
DIRENT_FILE, DIRENT_DIR, DIRENT_DOT, DIRENT_DOTDOT = 2, 3, 4, 5


@dataclass
class Inode:
    mode: int
    flags: int
    size: int
    size_compressed: int
    blocks: int
    db: List[int]
    ib: List[int]


class PfsImage:
    def __init__(self, reader, ekpfs: Optional[bytes] = None, new_crypt: bool = False):
        hdr = read_exact(reader, 0, 0x400)
        version, magic = struct.unpack_from("<qq", hdr, 0)
        if version != PFS_VERSION or magic != PFS_MAGIC:
            raise PkgError("Superbloque PFS inválido")
        mode, = struct.unpack_from("<H", hdr, 0x1C)
        self.block_size, = struct.unpack_from("<I", hdr, 0x20)
        dinode_count, _ndblock, dinode_block_count = struct.unpack_from("<qqq", hdr, 0x30)
        if self.block_size < XTS_SECTOR_SIZE or self.block_size & (self.block_size - 1):
            raise PkgError(f"Tamaño de bloque PFS inesperado: 0x{self.block_size:x}")
        if mode & 0x2:
            raise PkgError("Imágenes PFS de 64 bits no soportadas")
        self.signed = bool(mode & 0x1)
        self.encrypted = bool(mode & 0x4)

        ib_off = 0x50 + 104 + 12 * 40        # InodeBlockSig (DinodeS64): bloques indirectos
        indirect = [struct.unpack_from("<q", hdr, ib_off + 40 * i + 32)[0] for i in range(5)]
        seed = hdr[0x370:0x380]

        if self.encrypted:
            if ekpfs is None:
                raise PkgError("La imagen PFS está cifrada y no hay clave")
            tweak, data = pfs_gen_enc_key(ekpfs, seed, new_crypt)
            reader = XtsReader(reader, data, tweak, self.block_size // XTS_SECTOR_SIZE)
        self.reader = reader

        inode_size = 0x2C8 if self.signed else 0xA8
        per_block = self.block_size // inode_size
        start = self.block_size + self.block_size * sum(1 for b in indirect if b > 0)
        if not 0 < dinode_count < 50_000_000 or not 0 < dinode_block_count < 50_000_000:
            raise PkgError("Cabecera PFS corrupta (nº de inodos fuera de rango)")
        self.inodes: List[Inode] = []
        for i in range(dinode_block_count):
            buf = read_exact(reader, start + self.block_size * i, self.block_size)
            for j in range(per_block):
                if len(self.inodes) >= dinode_count:
                    break
                self.inodes.append(self._parse_inode(buf, j * inode_size))
        self.root_entries = self.list_dir(0)

    def _parse_inode(self, buf: bytes, p: int) -> Inode:
        mode, _nlink, flags, size, size_comp = struct.unpack_from("<HHIqq", buf, p)
        blocks, = struct.unpack_from("<I", buf, p + 96)
        if self.signed:
            db = [struct.unpack_from("<i", buf, p + 100 + 36 * i + 32)[0] for i in range(12)]
            ib = [struct.unpack_from("<i", buf, p + 532 + 36 * i + 32)[0] for i in range(5)]
        else:
            db = list(struct.unpack_from("<12i", buf, p + 100))
            ib = list(struct.unpack_from("<5i", buf, p + 148))
        return Inode(mode, flags, size, size_comp, blocks, db, ib)

    def list_dir(self, ino: int) -> List[Tuple[str, int, int]]:
        if not 0 <= ino < len(self.inodes):
            raise PkgError(f"Inodo {ino} fuera de rango (PFS corrupto o clave incorrecta)")
        node = self.inodes[ino]
        max_blocks = 100_000_000
        if node.blocks < 1 or node.db[0] < 1 or node.db[0] > max_blocks or node.blocks > max_blocks:
            raise PkgError(f"El inodo {ino} está corrupto (¿passcode o EKPFS incorrectos?)")
        out: List[Tuple[str, int, int]] = []
        for k in range(node.blocks):
            buf = read_exact(self.reader, (node.db[0] + k) * self.block_size, self.block_size)
            pos = 0
            while pos + 16 <= self.block_size:
                d_ino, d_type, name_len, ent_size = struct.unpack_from("<IiiI", buf, pos)
                if ent_size == 0:
                    break
                if d_type in (DIRENT_FILE, DIRENT_DIR):
                    name = buf[pos + 16:pos + 16 + name_len].split(b"\0")[0].decode("utf-8", "replace")
                    if not name or name in (".", "..") or "/" in name or "\\" in name:
                        raise PkgError(f"Nombre de archivo sospechoso dentro del PFS: {name!r}")
                    out.append((name, d_type, d_ino))
                pos += ent_size
        return out

    def find(self, entries: List[Tuple[str, int, int]], name: str) -> Optional[Tuple[str, int, int]]:
        for e in entries:
            if e[0] == name:
                return e
        return None

    def uroot_ino(self) -> int:
        e = self.find(self.root_entries, "uroot")
        if e is None or e[1] != DIRENT_DIR:
            raise PkgError("PFS inválido: no hay 'uroot' (¿passcode o EKPFS incorrectos?)")
        return e[2]

    def walk(self, ino: int, prefix: str = "", depth: int = 0) -> Iterator[Tuple[str, int, int]]:
        """Genera (ruta_relativa, tipo, inodo) recorriendo el árbol."""
        if depth > 64:
            raise PkgError("Árbol de directorios demasiado profundo")
        for name, kind, child in self.list_dir(ino):
            rel = f"{prefix}{name}"
            yield rel, kind, child
            if kind == DIRENT_DIR:
                yield from self.walk(child, rel + "/", depth + 1)

    def file_reader(self, ino: int):
        node = self.inodes[ino]
        bs = self.block_size
        if node.blocks > 1 and node.db[1] != -1:
            if not self.signed:
                raise PkgError("Una imagen PFS sin firmar con bloques no contiguos es inesperada")
            blocks = self._block_list(node)
            if blocks != list(range(blocks[0], blocks[0] + len(blocks))):
                return ChunkedFile(self.reader, bs, blocks)
        return ContiguousFile(self.reader, node.db[0] * bs)

    def _read_i32(self, offset: int) -> int:
        return struct.unpack("<i", read_exact(self.reader, offset, 4))[0]

    def _block_list(self, node: Inode) -> List[int]:
        bs = self.block_size
        total = node.blocks
        blocks = [0] * total
        remaining = total
        spb = bs // 36                          # firmas+bloque por bloque indirecto
        for i in range(min(12, remaining)):
            blocks[i] = node.db[i]
        remaining -= 12
        idx_off = 12
        for i in range(min(max(remaining, 0), spb)):
            blocks[i + idx_off] = self._read_i32(node.ib[0] * bs + i * 36 + 32)
        remaining -= spb
        idx_off += spb
        j = 0
        while j * spb < remaining:
            ind = self._read_i32(node.ib[1] * bs + j * 36 + 32)
            i = 0
            while i < spb and i + j * spb < remaining:
                blocks[i + idx_off] = self._read_i32(ind * bs + i * 36 + 32)
                i += 1
            idx_off += spb
            j += 1
        return blocks


# --------------------------------------------------------------------------- #
# Alto nivel
# --------------------------------------------------------------------------- #
def open_pfs_layers(f, hdr: PkgHeader, ekpfs: bytes) -> PfsImage:
    """Abre el PFS externo (cifrado) y devuelve el PFS interno con los archivos del juego."""
    require_crypto()
    if not hdr.pfs_image_offset or not hdr.pfs_image_size:
        raise PkgError("El PKG no contiene imagen PFS (¿es un PKG sin datos?)")
    region = Region(f, hdr.pfs_image_offset, hdr.pfs_image_size)
    try:
        outer = PfsImage(region, ekpfs, bool(hdr.pfs_flags & PFS_FLAG_NEW_CRYPT))
        uroot = outer.list_dir(outer.uroot_ino())
        inner_entry = outer.find(uroot, "pfs_image.dat")
        if inner_entry is None:
            raise PkgError("No se encontró pfs_image.dat dentro del PFS externo")
        inner_reader = outer.file_reader(inner_entry[2])
        magic, = struct.unpack("<I", read_exact(inner_reader, 0, 4))
        if magic == PFSC_MAGIC:
            inner_reader = PfscReader(inner_reader)
        return PfsImage(inner_reader)
    except (PkgError, struct.error, ValueError, zlib.error) as exc:
        raise PkgError(
            f"No se pudo leer el sistema de archivos del PKG: {exc}\n"
            "Causas probables: passcode/EKPFS incorrectos, o es un PKG comercial (retail) "
            "cifrado con claves que esta herramienta no incluye."
        ) from exc


def resolve_ekpfs(hdr: PkgHeader, passcode: Optional[str], ekpfs_hex: Optional[str]) -> bytes:
    if ekpfs_hex and ekpfs_hex.strip():
        try:
            key = bytes.fromhex(ekpfs_hex.strip())
        except ValueError as exc:
            raise PkgError("El EKPFS debe ser una cadena hexadecimal") from exc
        if len(key) != 32:
            raise PkgError("El EKPFS debe medir 32 bytes (64 caracteres hexadecimales)")
        return key
    return compute_ekpfs(hdr.content_id, passcode or DEFAULT_PASSCODE)


def describe(hdr: PkgHeader, sfo: Optional[Dict[str, object]]) -> List[str]:
    lines = [
        f"Content ID    : {hdr.content_id}",
        f"Tipo          : {CONTENT_TYPES.get(hdr.content_type, hex(hdr.content_type))}",
        f"Entradas      : {hdr.entry_count}",
        f"Tamaño PFS    : {hdr.pfs_image_size / (1024 ** 3):.2f} GiB",
        f"Tamaño PKG    : {hdr.package_size / (1024 ** 3):.2f} GiB",
    ]
    if sfo:
        for key in ("TITLE", "TITLE_ID", "CATEGORY", "APP_VER", "VERSION", "SYSTEM_VER"):
            if key in sfo:
                val = sfo[key]
                if key == "SYSTEM_VER" and isinstance(val, int):
                    val = f"0x{val & 0xFFFFFFFF:08x}"
                lines.append(f"{key:<14}: {val}")
    return lines


def _safe_component(text: str, fallback: str) -> str:
    """Deja solo caracteres seguros para un nombre de carpeta (evita rutas como '../x')."""
    return re.sub(r"[^A-Za-z0-9_\-]", "_", text).strip("._ ") or fallback


def target_folder_name(hdr: PkgHeader, sfo: Optional[Dict[str, object]], patch_suffix: str) -> str:
    raw_id = str(sfo.get("TITLE_ID")) if sfo and sfo.get("TITLE_ID") else hdr.content_id[7:16]
    title_id = _safe_component(raw_id, "juego")
    category = str(sfo.get("CATEGORY", "")) if sfo else ""
    if category == "gp":
        return title_id + re.sub(r"[^A-Za-z0-9_\-]", "", patch_suffix)
    if category == "ac":
        return _safe_component(hdr.content_id, "dlc")
    return title_id


def safe_join(base: str, rel: str) -> str:
    target = os.path.normpath(os.path.join(base, *rel.split("/")))
    base_abs = os.path.abspath(base)
    if os.path.commonpath([base_abs, os.path.abspath(target)]) != base_abs:
        raise PkgError(f"Ruta fuera de la carpeta de salida bloqueada: {rel!r}")
    return target


def copy_file(img: PfsImage, ino: int, dest: str,
              cancel: Optional[Callable[[], bool]] = None,
              on_bytes: Optional[Callable[[int], None]] = None) -> int:
    """Copia un archivo del PFS. Si falla o se cancela, borra el archivo a medias."""
    node = img.inodes[ino]
    reader = img.file_reader(ino)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    pos, ok = 0, False
    try:
        with open(dest, "wb") as out:
            while pos < node.size:
                if cancel and cancel():
                    raise Cancelled()
                n = min(COPY_CHUNK, node.size - pos)
                data = reader.read(pos, n)
                if len(data) != n:
                    raise PkgError(f"Lectura incompleta al extraer {dest}")
                out.write(data)
                pos += n
                if on_bytes:
                    on_bytes(pos)
        ok = True
    finally:
        if not ok:
            with contextlib.suppress(OSError):
                os.remove(dest)
    return node.size


@contextlib.contextmanager
def open_package(pkg: str, passcode: Optional[str] = None, ekpfs_hex: Optional[str] = None,
                 need_keys: bool = True):
    """Abre el PKG y entrega (archivo, cabecera, entradas, sfo, PFS interno o None)."""
    f = open(pkg, "rb")
    try:
        hdr = read_header(f)
        entries = read_entries(f, hdr)
        sfo = load_sfo(f, entries)
        inner = None
        if need_keys:
            inner = open_pfs_layers(f, hdr, resolve_ekpfs(hdr, passcode, ekpfs_hex))
        yield f, hdr, entries, sfo, inner
    finally:
        f.close()


def run_info(pkg: str, passcode: Optional[str] = None, ekpfs: Optional[str] = None,
             check_keys: bool = False, log: Log = print) -> Optional[bool]:
    """Muestra cabecera, param.sfo y entradas. Con check_keys prueba además el passcode/EKPFS.

    Devuelve True/False según las claves abran o no el PKG, o None si no se comprobaron."""
    with open_package(pkg, need_keys=False) as (f, hdr, entries, sfo, _):
        for line in describe(hdr, sfo):
            log(line)
        log("")
        log("Entradas del PKG:")
        for e in entries:
            flag = " [cifrada]" if e.encrypted else ""
            log(f"  0x{e.id:08x}  {e.size:>10} bytes  {e.name}{flag}")
        if not check_keys:
            return None
        log("")
        if not CRYPTO_OK:
            log("Comprobación de claves omitida: falta 'cryptography' (usa «Instalar requisitos»).")
            return None
        try:
            inner = open_pfs_layers(f, hdr, resolve_ekpfs(hdr, passcode, ekpfs))
            sizes = [inner.inodes[i].size for _r, k, i in inner.walk(inner.uroot_ino())
                     if k != DIRENT_DIR]
        except PkgError as exc:
            log(f"Claves NO válidas: {exc}")
            return False
        log(f"Claves correctas: el juego contiene {len(sizes)} archivos "
            f"({sum(sizes) / (1024 ** 3):.2f} GiB).")
        return True


def destination_for(pkg: str, output: str, flat: bool = False, patch_suffix: str = "-patch") -> str:
    """Carpeta exacta donde run_extract dejaría el juego (no necesita claves)."""
    with open_package(pkg, need_keys=False) as (_f, hdr, _entries, sfo, _inner):
        return output if flat else os.path.join(output, target_folder_name(hdr, sfo, patch_suffix))


def run_list(pkg: str, passcode: Optional[str] = None, ekpfs: Optional[str] = None,
             log: Log = print) -> None:
    with open_package(pkg, passcode, ekpfs) as (_f, hdr, _entries, sfo, inner):
        for line in describe(hdr, sfo):
            log(line)
        log("")
        total = 0
        for rel, kind, ino in inner.walk(inner.uroot_ino()):
            if kind == DIRENT_DIR:
                log(f"{'<dir>':>14}  {rel}/")
            else:
                size = inner.inodes[ino].size
                total += size
                log(f"{size:>14}  {rel}")
        log(f"\nTotal: {total / (1024 ** 3):.2f} GiB")


# Entradas con id < 0x1000 que shadPS4 lee desde sce_sys (trofeos / identidad NP).
SCE_SYS_LOW_ENTRIES = ("npbind.dat", "nptitle.dat")


def write_sce_sys_entries(f, ents, dest_root: str, log: Log = print) -> int:
    """Copia a <dest>/sce_sys las entradas del PKG con nombre real (no cifradas) que aún no
    estén allí. No sobrescribe nada que ya haya salido del PFS. Devuelve cuántas escribió."""
    count = 0
    for e in ents:
        wanted = e.id >= ENTRY_ID_PARAM_SFO or e.name in SCE_SYS_LOW_ENTRIES
        if (not wanted or e.encrypted or e.size == 0
                or e.id == ENTRY_ID_ENTRY_NAMES or e.name.startswith("entry_")):
            continue
        try:
            path = safe_join(os.path.join(dest_root, "sce_sys"), e.name)
        except PkgError:
            log(f"Aviso: nombre de entrada sospechoso omitido: {e.name!r}")
            continue
        if os.path.exists(path):
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as out:
            out.write(read_entry_data(f, e))
        count += 1
    return count


def run_extract(pkg: str, output: str, passcode: Optional[str] = None,
                ekpfs: Optional[str] = None, flat: bool = False, patch_suffix: str = "-patch",
                entries: bool = False, log: Log = print,
                progress: Optional[Callable[[int, int], None]] = None,
                cancel: Optional[Callable[[], bool]] = None, meta: bool = True) -> str:
    """Extrae el juego. Devuelve la carpeta donde quedó. progress(hechos, total) en bytes.

    meta=True copia a sce_sys los archivos de sistema que viven en la tabla de entradas del PKG
    (playgo-chunk.dat, trofeos, icon0...) y no dentro del PFS; sin ellos el juego se queja
    de PlayGo y de trofeos."""
    with open_package(pkg, passcode, ekpfs) as (f, hdr, ents, sfo, inner):
        for line in describe(hdr, sfo):
            log(line)
        log("")
        dest_root = output if flat else os.path.join(
            output, target_folder_name(hdr, sfo, patch_suffix))
        os.makedirs(dest_root, exist_ok=True)

        files, dirs = [], []
        for rel, kind, ino in inner.walk(inner.uroot_ino()):
            (dirs if kind == DIRENT_DIR else files).append((rel, ino))
        total = sum(inner.inodes[i].size for _r, i in files)
        free = shutil.disk_usage(dest_root).free
        if total > free:
            raise PkgError(f"Espacio insuficiente: se necesitan {total / 1024 ** 3:.2f} GiB y "
                           f"hay {free / 1024 ** 3:.2f} GiB libres en {dest_root}")

        for rel, _ino in dirs:
            os.makedirs(safe_join(dest_root, rel), exist_ok=True)
        done = 0
        for n, (rel, ino) in enumerate(files, 1):
            if cancel and cancel():
                raise Cancelled()
            on_bytes = (lambda k, base=done: progress(base + k, total)) if progress else None
            done += copy_file(inner, ino, safe_join(dest_root, rel), cancel, on_bytes)
            pct = 100 * done / total if total else 100
            log(f"[{n}/{len(files)}] {pct:5.1f}%  {rel}")
            if progress:
                progress(done, total)

        if meta:
            n_meta = write_sce_sys_entries(f, ents, dest_root, log)
            if n_meta:
                log(f"Añadidos {n_meta} archivos de sistema del PKG a sce_sys")
        if entries:
            ent_dir = os.path.join(dest_root, "_pkg_entries")
            for e in ents:
                if e.encrypted or e.size == 0 or e.id == ENTRY_ID_ENTRY_NAMES:
                    continue
                path = safe_join(ent_dir, e.name)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as out:
                    out.write(read_entry_data(f, e))
        log(f"\nListo: {len(files)} archivos en {dest_root}")
    return dest_root


# --------------------------------------------------------------------------- #
# Instalación de requisitos
# --------------------------------------------------------------------------- #
def _console_python() -> str:
    """Intérprete para pip. En Windows, pythonw.exe no tiene consola: se prefiere python.exe."""
    exe = sys.executable
    if os.name == "nt" and os.path.basename(exe).lower() == "pythonw.exe":
        candidate = os.path.join(os.path.dirname(exe), "python.exe")
        if os.path.isfile(candidate):
            return candidate
    return exe


def install_requirements(log: Log = print,
                         attempts: Optional[List[List[str]]] = None) -> bool:
    """Instala los requisitos con pip (reintenta con --user). True si quedan disponibles.

    `attempts` permite sustituir los comandos (se usa en las pruebas)."""
    if load_crypto():
        log("Los requisitos ya están instalados.")
        return True
    base = [_console_python(), "-m", "pip", "install", "--disable-pip-version-check", *REQUIREMENTS]
    attempts = attempts or [base, base + ["--user"]]
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)     # evita ventanas negras en Windows
    for cmd in attempts:
        log("> " + " ".join(cmd))
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, errors="replace",
                                    creationflags=flags)
        except OSError as exc:
            log(f"No se pudo ejecutar pip: {exc}")
            continue
        assert proc.stdout is not None
        for line in proc.stdout:
            log(line.rstrip())
        code = proc.wait()
        if code == 0 and load_crypto():
            log("Requisitos instalados correctamente.")
            return True
        log(f"Intento fallido (código {code}).")
    log("No se pudieron instalar los requisitos automáticamente.")
    log("Prueba a mano en una terminal:  python -m pip install cryptography")
    log("(En Linux/macOS con el Python del sistema, crea antes un entorno: python3 -m venv .venv)")
    return False


# --------------------------------------------------------------------------- #
# Línea de comandos
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Extractor de PKG de PS4 (juegos propios / volcados).")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, keys: bool):
        sp.add_argument("pkg", help="ruta al archivo .pkg")
        if keys:
            sp.add_argument("--passcode", help="passcode de 32 caracteres (por defecto: 32 ceros)")
            sp.add_argument("--ekpfs", help="EKPFS en hexadecimal (64 caracteres); anula --passcode")

    info = sub.add_parser("info", help="muestra cabecera, param.sfo y entradas")
    common(info, keys=True)
    info.add_argument("--check", action="store_true",
                      help="además comprueba que el passcode/EKPFS abre el sistema de archivos")
    common(sub.add_parser("list", help="lista los archivos del juego"), keys=True)
    ex = sub.add_parser("extract", help="extrae el juego a una carpeta")
    common(ex, keys=True)
    ex.add_argument("-o", "--output", required=True, help="carpeta de salida")
    ex.add_argument("--flat", action="store_true",
                    help="extrae directamente en la carpeta de salida, sin subcarpeta por TITLE_ID")
    ex.add_argument("--patch-suffix", default="-patch",
                    help="sufijo de carpeta para parches (category gp). Por defecto: -patch")
    ex.add_argument("--entries", action="store_true",
                    help="guarda también las entradas del PKG (icon0.png, param.sfo...) en _pkg_entries/")
    ex.add_argument("--no-meta", action="store_true",
                    help="no copiar a sce_sys los archivos de sistema del PKG (playgo, trofeos...)")
    sub.add_parser("install-deps", help="instala los requisitos (cryptography) con pip")
    return p


def launch_gui() -> int:
    """Abre la ventana, si pkg_extractor_gui.py está junto a este archivo."""
    try:
        import pkg_extractor_gui
    except ModuleNotFoundError as exc:
        if exc.name != "pkg_extractor_gui":
            raise
        build_parser().print_help()
        return 0
    return pkg_extractor_gui.main([])


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None and len(sys.argv) == 1:
        return launch_gui()
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "install-deps":
            return 0 if install_requirements() else 1
        if args.cmd == "info":
            return 1 if run_info(args.pkg, args.passcode, args.ekpfs, args.check) is False else 0
        if args.cmd == "list":
            run_list(args.pkg, args.passcode, args.ekpfs)
        elif args.cmd == "extract":
            run_extract(args.pkg, args.output, args.passcode, args.ekpfs, args.flat,
                        args.patch_suffix, args.entries, meta=not args.no_meta)
        return 0
    except PkgError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Cancelled:
        print("Cancelado.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error de archivo: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
