#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pruebas del extractor con PKG sintéticos.

No hay ningún juego real aquí: cada PKG se construye con un escritor mínimo que sigue
el mismo formato que lee pkg_extractor.py (cabecera big-endian, tabla de entradas,
PFS externo cifrado con AES-XTS que contiene un PFSC con el PFS interno).

Para no depender solo de la librería 'cryptography', el cifrado XTS del escritor usa
una implementación manual transcrita del algoritmo de referencia de LibOrbisPkg
(XtsDecryptReader.cs); el extractor, en cambio, usa la librería. Si ambos coinciden,
la equivalencia queda comprobada.
"""
import contextlib
import hashlib
import hmac
import io
import os
import random
import struct
import sys
import tempfile
import time
import types
import unittest
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import pkg_extractor as px

BS = 0x10000
CONTENT_ID = "UP9000-CUSA99999_00-ABCDEFGHIJKLMNOP"
ZERO_PASS = "0" * 32


# --------------------------------------------------------------------------- #
# XTS de referencia (transcrito de XtsDecryptReader.cs)
# --------------------------------------------------------------------------- #
def ref_xts_sector(data: bytes, data_key: bytes, tweak_key: bytes, sector: int, decrypt: bool) -> bytes:
    et = bytearray(Cipher(algorithms.AES(tweak_key), modes.ECB()).encryptor()
                   .update(sector.to_bytes(8, "little") + bytes(8)))
    c = Cipher(algorithms.AES(data_key), modes.ECB())
    op = c.decryptor() if decrypt else c.encryptor()
    out = bytearray()
    for off in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[off:off + 16], et))
        blk = op.update(blk)
        out += bytes(a ^ b for a, b in zip(blk, et))
        feedback = 0
        for k in range(16):
            tmp = et[k]
            et[k] = ((2 * et[k]) | feedback) & 0xFF
            feedback = (tmp & 0x80) >> 7
        if feedback:
            et[0] ^= 0x87
    return bytes(out)


# --------------------------------------------------------------------------- #
# Escritor mínimo de PFS
# --------------------------------------------------------------------------- #
def _inode(signed: bool, is_dir: bool, size: int, blocks: int, db, ib):
    mode = (0x4000 if is_dir else 0x8000) | 0x16D
    head = struct.pack("<HHIqq4q4IIIQQI", mode, 1, 0x10, size, size,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, blocks)
    db = list(db) + [-1] * (12 - len(db))
    ib = list(ib) + [-1] * (5 - len(ib))
    if signed:
        body = b"".join(bytes(32) + struct.pack("<i", b) for b in db + ib)
        assert len(head + body) == 0x2C8
    else:
        body = struct.pack("<12i5i", *db, *ib)
        assert len(head + body) == 0xA8
    return head + body


def build_pfs(superroot: dict, signed: bool, enc=None, seed: bytes = b"\x11" * 16,
              new_crypt: bool = False) -> bytes:
    """superroot: dict nombre -> bytes | (bytes,'scatter') | dict. enc = (tweak_key, data_key)."""
    nodes = []

    def add(**kw):
        nodes.append(kw)
        return len(nodes) - 1

    def build_dir(d: dict, parent: int) -> int:
        ino = add(kind="dir", children=[])
        for name, val in d.items():
            if isinstance(val, dict):
                cino = build_dir(val, ino)
                nodes[ino]["children"].append((name, 3, cino))
            else:
                scatter = isinstance(val, tuple)
                data = val[0] if scatter else val
                cino = add(kind="file", data=data, scatter=scatter)
                nodes[ino]["children"].append((name, 2, cino))
        nodes[ino]["parent"] = parent if parent >= 0 else ino
        return ino

    build_dir(superroot, -1)

    def dirent(ino, typ, name):
        nb = name.encode()
        ent = (len(nb) + 17 + 7) // 8 * 8
        return struct.pack("<IiiI", ino, typ, len(nb), ent) + nb + bytes(ent - 16 - len(nb))

    isz = 0x2C8 if signed else 0xA8
    per_block = BS // isz
    dblocks = -(-len(nodes) // per_block)
    nxt = 1 + dblocks
    inode_bytes = []
    placed = []                                       # (block_index, data)
    for ino, n in enumerate(nodes):
        if n["kind"] == "dir":
            raw = dirent(ino, 4, ".") + dirent(n["parent"], 5, "..")
            raw += b"".join(dirent(ci, t, name) for name, t, ci in n["children"])
            nblk = max(1, -(-len(raw) // BS))
            placed.append((nxt, raw))
            inode_bytes.append(_inode(signed, True, nblk * BS, nblk, [nxt], []))
            nxt += nblk
        else:
            data = n["data"]
            nblk = max(1, -(-len(data) // BS))
            if n["scatter"] and signed and nblk > 12:
                region = list(range(nxt, nxt + nblk))
                mapping = list(reversed(region))      # bloques no contiguos
                ind = nxt + nblk
                nxt += nblk + 1
                ind_raw = bytearray(BS)
                for i, b in enumerate(mapping[12:]):
                    struct.pack_into("<i", ind_raw, i * 36 + 32, b)
                placed.append((ind, bytes(ind_raw)))
                inode_bytes.append(_inode(signed, False, len(data), nblk, mapping[:12], [ind]))
                for i, b in enumerate(mapping):
                    placed.append((b, data[i * BS:(i + 1) * BS]))
            else:
                placed.append((nxt, data))
                inode_bytes.append(_inode(signed, False, len(data), nblk, [nxt], []))
                nxt += nblk

    img = bytearray(nxt * BS)
    mode = 0x8 | (0x1 if signed else 0) | (0x4 if enc else 0)
    struct.pack_into("<qq", img, 0, 1, 20130315)
    struct.pack_into("<H", img, 0x1C, mode)
    struct.pack_into("<I", img, 0x20, BS)
    struct.pack_into("<qqq", img, 0x30, len(nodes), 0, dblocks)
    img[0x370:0x380] = seed
    for i, raw in enumerate(inode_bytes):
        blk, j = divmod(i, per_block)
        pos = BS * (1 + blk) + j * isz
        img[pos:pos + isz] = raw
    for blk, data in placed:
        img[blk * BS:blk * BS + len(data)] = data

    if enc:
        tweak_key, data_key = enc
        for s in range(BS // px.XTS_SECTOR_SIZE, len(img) // px.XTS_SECTOR_SIZE):
            a, b = s * px.XTS_SECTOR_SIZE, (s + 1) * px.XTS_SECTOR_SIZE
            img[a:b] = ref_xts_sector(bytes(img[a:b]), data_key, tweak_key, s, decrypt=False)
    return bytes(img)


def build_pfsc(image: bytes) -> bytes:
    image = image.ljust(-(-len(image) // BS) * BS, b"\0")
    n = len(image) // BS
    map_off = 0x30
    data_start = map_off + 8 * (n + 1)
    blobs, offsets, pos = [], [], data_start
    for i in range(n):
        block = image[i * BS:(i + 1) * BS]
        comp = zlib.compress(block)
        blob = comp if len(comp) < BS else block
        offsets.append(pos)
        blobs.append(blob)
        pos += len(blob)
    offsets.append(pos)
    hdr = struct.pack("<iiiiqqQq", px.PFSC_MAGIC, 0, 6, BS, BS, map_off, data_start, n * BS)
    return hdr + struct.pack(f"<{n + 1}q", *offsets) + b"".join(blobs)


# --------------------------------------------------------------------------- #
# Escritor mínimo de param.sfo y PKG
# --------------------------------------------------------------------------- #
def build_sfo(values: dict) -> bytes:
    keys = sorted(values)
    key_tab = b"".join(k.encode() + b"\0" for k in keys)
    key_offs, o = [], 0
    for k in keys:
        key_offs.append(o)
        o += len(k) + 1
    data_tab, ents = b"", b""
    for k, ko in zip(keys, key_offs):
        v = values[k]
        if isinstance(v, int):
            raw, fmt, ln, mx = struct.pack("<i", v), 0x404, 4, 4
        else:
            raw = v.encode() + b"\0"
            fmt, ln, mx = 0x204, len(raw), max(len(raw), 8)
            raw = raw.ljust(mx, b"\0")
        ents += struct.pack("<HHIII", ko, fmt, ln, mx, len(data_tab))
        data_tab += raw
    key_start = 0x14 + 16 * len(keys)
    data_start = key_start + len(key_tab)
    return (b"\x00PSF" + struct.pack("<IIII", 0x101, key_start, data_start, len(keys))
            + ents + key_tab + data_tab)


def build_pkg(path: str, inner_tree: dict, *, signed_inner=True, passcode=ZERO_PASS,
              category="gd", content_id=CONTENT_ID, new_crypt=False, title_id="CUSA99999") -> dict:
    sfo_vals = {"TITLE": "Juego de Prueba", "TITLE_ID": title_id,
                "CATEGORY": category, "APP_VER": "01.00", "SYSTEM_VER": 0x05050000}
    sfo = build_sfo(sfo_vals)
    icon = b"\x89PNG\r\n\x1a\n" + bytes(random.Random(7).randrange(256) for _ in range(300))

    ekpfs = px.compute_ekpfs(content_id, passcode)
    seed = bytes(range(16))
    tweak, data = px.pfs_gen_enc_key(ekpfs, seed, new_crypt)

    inner = build_pfs({"uroot": inner_tree}, signed=signed_inner)
    pfsc = build_pfsc(inner)
    outer = build_pfs({"flat_path_table": bytes(range(64)), "uroot": {"pfs_image.dat": pfsc}},
                      signed=True, enc=(tweak, data), seed=seed, new_crypt=new_crypt)

    names = b"\0param.sfo\0npbind.dat\0"
    entries = [  # id, name_off, flags1, flags2, data
        (0x200, 0, 0, 0, names),
        (0x1000, 1, 0, 0, sfo),
        (0x1200, 0, 0, 0, icon),
        (0x0409, 11, 0, 0, b"NPBIND-DATA"),
        (0x0010, 0, 0x80000000, 0x3000, bytes(range(256))),   # cifrada: debe omitirse
    ]
    table_off, pos = 0x2000, 0x2000 + 0x20 * len(entries)
    pos = (pos + 0xFF) // 0x100 * 0x100
    table, blob = b"", b""
    for eid, noff, f1, f2, d in entries:
        table += struct.pack(">IIIIIIQ", eid, noff, f1, f2, pos + len(blob), len(d), 0)
        blob += d.ljust((len(d) + 15) // 16 * 16, b"\0")
    pfs_off = (pos + len(blob) + 0xFFFF) // 0x10000 * 0x10000

    hdr = bytearray(0x1000)
    struct.pack_into(">II", hdr, 0, px.PKG_MAGIC, 0x80000000)
    struct.pack_into(">I", hdr, 0x10, len(entries))
    struct.pack_into(">HH", hdr, 0x14, 0, len(entries))
    struct.pack_into(">I", hdr, 0x18, table_off)
    struct.pack_into(">QQ", hdr, 0x20, 0, 0)
    hdr[0x40:0x40 + len(content_id)] = content_id.encode()
    struct.pack_into(">III", hdr, 0x70, 0xF, 0x1A, 0)
    struct.pack_into(">I", hdr, 0x404, 1)
    struct.pack_into(">QQQ", hdr, 0x408, px.PFS_FLAG_NEW_CRYPT if new_crypt else 0, pfs_off, len(outer))
    struct.pack_into(">Q", hdr, 0x430, pfs_off + len(outer))

    with open(path, "wb") as f:
        f.write(bytes(hdr))
        f.write(bytes(table_off - 0x1000))
        f.write(table)
        f.write(bytes(pos - table_off - len(table)))
        f.write(blob)
        f.write(bytes(pfs_off - pos - len(blob)))
        f.write(outer)
    return {"sfo": sfo, "icon": icon, "ekpfs": ekpfs}


def sample_tree() -> dict:
    rnd = random.Random(1234)
    big = bytes(rnd.randrange(256) for _ in range(14 * BS - 123))      # incompresible, 14 bloques
    text = (b"hola mundo\n" * 20000) + bytes(BS) + (b"fin\n" * 10)      # comprimible, > 1 bloque
    return {
        "eboot.bin": b"\x7fELF" + bytes(rnd.randrange(256) for _ in range(5000)),
        "sce_sys": {"param.sfo": build_sfo({"TITLE": "Dentro del PFS", "TITLE_ID": "CUSA99999"}),
                    "icon0.png": b"\x89PNG-fake"},
        "Media": {"datos.bin": (big, "scatter"), "texto.txt": text, "vacio.bin": b""},
    }


def flatten(tree: dict, prefix=""):
    for k, v in tree.items():
        if isinstance(v, dict):
            yield from flatten(v, prefix + k + "/")
        else:
            yield prefix + k, (v[0] if isinstance(v, tuple) else v)


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = px.main(list(argv))
    return code, out.getvalue(), err.getvalue()


# --------------------------------------------------------------------------- #
class KeyDerivationTests(unittest.TestCase):
    """Fórmulas escritas aparte, directamente desde Crypto.cs de LibOrbisPkg.

    OJO: son una segunda transcripción, no vectores de respuesta conocida (el repositorio
    de referencia no los trae). Detectan errores de tipeo, no errores de comprensión.
    """

    def test_ekpfs_formula(self):
        a = hashlib.sha256((1).to_bytes(4, "big")).digest()
        b = hashlib.sha256(CONTENT_ID.encode().ljust(48, b"\0")).digest()
        expected = hashlib.sha256(a + b + ZERO_PASS.encode()).digest()
        self.assertEqual(px.compute_ekpfs(CONTENT_ID, ZERO_PASS), expected)
        self.assertEqual(len(expected), 32)

    def test_pfs_key_formula(self):
        ekpfs, seed = bytes(range(32)), bytes(range(16, 32))
        idx = (1).to_bytes(4, "little")
        h = hmac.new(ekpfs, idx + seed, "sha256").digest()
        self.assertEqual(px.pfs_gen_enc_key(ekpfs, seed, False), (h[:16], h[16:]))
        k2 = hmac.new(ekpfs, seed, "sha256").digest()
        h2 = hmac.new(k2, idx + seed, "sha256").digest()
        self.assertEqual(px.pfs_gen_enc_key(ekpfs, seed, True), (h2[:16], h2[16:]))

    def test_bad_lengths_rejected(self):
        with self.assertRaises(px.PkgError):
            px.compute_ekpfs("corto", ZERO_PASS)
        with self.assertRaises(px.PkgError):
            px.compute_ekpfs(CONTENT_ID, "corto")


class XtsTests(unittest.TestCase):
    def test_matches_reference_algorithm(self):
        rnd = random.Random(99)
        dk, tk = bytes(rnd.randrange(256) for _ in range(16)), bytes(rnd.randrange(256) for _ in range(16))
        plain = bytes(rnd.randrange(256) for _ in range(px.XTS_SECTOR_SIZE * 40))
        ref = bytearray(plain)
        for s in range(40):
            a, b = s * 4096, (s + 1) * 4096
            ref[a:b] = ref_xts_sector(plain[a:b], dk, tk, s, decrypt=False)

        class Mem:
            def read(self, off, n):
                return bytes(ref[off:off + n])

        reader = px.XtsReader(Mem(), dk, tk, start_sector=0)
        self.assertEqual(reader.read(0, len(plain)), plain)
        self.assertEqual(reader.read(4096 * 7 + 100, 9000), plain[4096 * 7 + 100:4096 * 7 + 9100])

    def test_start_sector_leaves_header_plain(self):
        class Mem:
            def read(self, off, n):
                return b"A" * n

        reader = px.XtsReader(Mem(), bytes(16), bytes(range(16)), start_sector=16)
        self.assertEqual(reader.read(0, 0x10000), b"A" * 0x10000)
        self.assertNotEqual(reader.read(0x10000, 16), b"A" * 16)


class ExtractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _compare(self, root, tree):
        for rel, data in flatten(tree):
            p = os.path.join(root, *rel.split("/"))
            self.assertTrue(os.path.isfile(p), rel)
            with open(p, "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).digest(), hashlib.sha256(data).digest(), rel)

    def test_signed_inner_with_scattered_blocks(self):
        tree = sample_tree()
        pkg = os.path.join(self.dir, "a.pkg")
        build_pkg(pkg, tree, signed_inner=True)
        out = os.path.join(self.dir, "out")
        code, stdout, stderr = run_cli("extract", pkg, "-o", out)
        self.assertEqual(code, 0, stderr)
        self._compare(os.path.join(out, "CUSA99999"), tree)

    def test_unsigned_inner(self):
        tree = {"eboot.bin": b"abc" * 100, "dir": {"x.bin": bytes(range(256)) * 300}}
        pkg = os.path.join(self.dir, "b.pkg")
        build_pkg(pkg, tree, signed_inner=False)
        out = os.path.join(self.dir, "out")
        self.assertEqual(run_cli("extract", pkg, "-o", out)[0], 0)
        self._compare(os.path.join(out, "CUSA99999"), tree)

    def test_new_crypt_flag(self):
        tree = {"eboot.bin": b"nuevo cifrado" * 50}
        pkg = os.path.join(self.dir, "n.pkg")
        build_pkg(pkg, tree, new_crypt=True)
        out = os.path.join(self.dir, "out")
        self.assertEqual(run_cli("extract", pkg, "-o", out, "--flat")[0], 0)
        self._compare(out, tree)

    def test_custom_passcode_and_explicit_ekpfs(self):
        tree = {"eboot.bin": b"clave propia" * 80}
        pc = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
        pkg = os.path.join(self.dir, "c.pkg")
        info = build_pkg(pkg, tree, passcode=pc)
        out1, out2 = os.path.join(self.dir, "o1"), os.path.join(self.dir, "o2")
        self.assertEqual(run_cli("extract", pkg, "-o", out1, "--passcode", pc, "--flat")[0], 0)
        self.assertEqual(run_cli("extract", pkg, "-o", out2, "--ekpfs", info["ekpfs"].hex(), "--flat")[0], 0)
        self._compare(out1, tree)
        self._compare(out2, tree)

    def test_wrong_passcode_fails_cleanly(self):
        pkg = os.path.join(self.dir, "d.pkg")
        build_pkg(pkg, {"eboot.bin": b"x" * 10}, passcode="ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
        code, _out, err = run_cli("extract", pkg, "-o", os.path.join(self.dir, "o"))
        self.assertEqual(code, 1)
        self.assertIn("passcode", err.lower())

    def test_info_and_list(self):
        pkg = os.path.join(self.dir, "e.pkg")
        build_pkg(pkg, sample_tree())
        code, out, _ = run_cli("info", pkg)
        self.assertEqual(code, 0)
        self.assertIn("Juego de Prueba", out)
        self.assertIn("CUSA99999", out)
        self.assertIn("[cifrada]", out)
        code, out, _ = run_cli("list", pkg)
        self.assertEqual(code, 0)
        self.assertIn("Media/datos.bin", out)
        self.assertIn("eboot.bin", out)

    def test_entries_dump_skips_encrypted(self):
        pkg = os.path.join(self.dir, "f.pkg")
        info = build_pkg(pkg, {"eboot.bin": b"1"})
        out = os.path.join(self.dir, "o")
        self.assertEqual(run_cli("extract", pkg, "-o", out, "--entries", "--flat")[0], 0)
        ent = os.path.join(out, "_pkg_entries")
        with open(os.path.join(ent, "param.sfo"), "rb") as f:
            self.assertEqual(f.read(), info["sfo"])
        with open(os.path.join(ent, "icon0.png"), "rb") as f:
            self.assertEqual(f.read(), info["icon"])
        self.assertFalse(os.path.exists(os.path.join(ent, "entry_00000010.bin")))

    def test_sce_sys_entries_copied_by_default(self):
        pkg = os.path.join(self.dir, "m.pkg")
        info = build_pkg(pkg, {"eboot.bin": b"1"})
        out = os.path.join(self.dir, "o")
        self.assertEqual(run_cli("extract", pkg, "-o", out, "--flat")[0], 0)
        with open(os.path.join(out, "sce_sys", "param.sfo"), "rb") as f:
            self.assertEqual(f.read(), info["sfo"])
        with open(os.path.join(out, "sce_sys", "icon0.png"), "rb") as f:
            self.assertEqual(f.read(), info["icon"])
        self.assertFalse(os.path.exists(os.path.join(out, "sce_sys", "entry_00000010.bin")))
        with open(os.path.join(out, "sce_sys", "npbind.dat"), "rb") as f:
            self.assertEqual(f.read(), b"NPBIND-DATA")

    def test_sce_sys_entries_do_not_overwrite_pfs_files(self):
        pkg = os.path.join(self.dir, "n.pkg")
        build_pkg(pkg, {"eboot.bin": b"1", "sce_sys": {"param.sfo": b"DEL_PFS"}})
        out = os.path.join(self.dir, "o")
        self.assertEqual(run_cli("extract", pkg, "-o", out, "--flat")[0], 0)
        with open(os.path.join(out, "sce_sys", "param.sfo"), "rb") as f:
            self.assertEqual(f.read(), b"DEL_PFS")
        self.assertTrue(os.path.isfile(os.path.join(out, "sce_sys", "icon0.png")))

    def test_no_meta_flag(self):
        pkg = os.path.join(self.dir, "o.pkg")
        build_pkg(pkg, {"eboot.bin": b"1"})
        out = os.path.join(self.dir, "o")
        self.assertEqual(run_cli("extract", pkg, "-o", out, "--flat", "--no-meta")[0], 0)
        self.assertFalse(os.path.exists(os.path.join(out, "sce_sys")))

    def test_patch_goes_to_suffixed_folder(self):
        pkg = os.path.join(self.dir, "g.pkg")
        build_pkg(pkg, {"eboot.bin": b"1"}, category="gp")
        out = os.path.join(self.dir, "o")
        self.assertEqual(run_cli("extract", pkg, "-o", out)[0], 0)
        self.assertTrue(os.path.isfile(os.path.join(out, "CUSA99999-patch", "eboot.bin")))

    def test_not_a_pkg_and_truncated(self):
        junk = os.path.join(self.dir, "junk.pkg")
        with open(junk, "wb") as f:
            f.write(b"hola" * 1000)
        code, _o, err = run_cli("info", junk)
        self.assertEqual(code, 1)
        self.assertIn("No es un PKG", err)

        pkg = os.path.join(self.dir, "h.pkg")
        build_pkg(pkg, {"eboot.bin": b"x" * 1000})
        cut = os.path.join(self.dir, "cut.pkg")
        with open(pkg, "rb") as f, open(cut, "wb") as g:
            g.write(f.read()[:0x30000])
        code, _o, err = run_cli("extract", cut, "-o", os.path.join(self.dir, "o"))
        self.assertEqual(code, 1)
        self.assertTrue(err.startswith("Error"))

    def test_suspicious_names_rejected(self):
        pkg = os.path.join(self.dir, "i.pkg")
        build_pkg(pkg, {"..": b"malo"})
        out = os.path.join(self.dir, "o")
        code, _o, err = run_cli("extract", pkg, "-o", out)
        self.assertEqual(code, 1)
        self.assertIn("sospechoso", err)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "malo")))


# --------------------------------------------------------------------------- #
# Núcleo: requirements.txt, nombres de carpeta, instalador
# --------------------------------------------------------------------------- #
class CoreExtrasTests(unittest.TestCase):
    def test_requirements_txt_matches_code(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
        with open(path, encoding="utf-8") as f:
            listed = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        self.assertEqual(listed, px.REQUIREMENTS)

    def test_folder_name_is_sanitized(self):
        hdr = types.SimpleNamespace(content_id=CONTENT_ID)
        for evil in ("../../Windows", "..\\x", "a/b", "...", ""):
            name = px.target_folder_name(hdr, {"TITLE_ID": evil, "CATEGORY": "gd"}, "-patch")
            self.assertTrue(name)
            for bad in ("/", "\\", ".."):
                self.assertNotIn(bad, name)
        gp = {"TITLE_ID": "CUSA12345", "CATEGORY": "gp"}
        self.assertEqual(px.target_folder_name(hdr, gp, "-UPDATE"), "CUSA12345-UPDATE")
        self.assertEqual(px.target_folder_name(hdr, gp, "../x"), "CUSA12345x")

    def test_malicious_title_id_cannot_escape_output(self):
        with tempfile.TemporaryDirectory() as d:
            pkg = os.path.join(d, "t.pkg")
            build_pkg(pkg, {"eboot.bin": b"1"}, title_id="../../escapado")
            out = os.path.join(d, "salida")
            code, _o, err = run_cli("extract", pkg, "-o", out)
            self.assertEqual(code, 0, err)
            self.assertFalse(os.path.exists(os.path.join(d, "escapado")))
            self.assertTrue(os.path.isfile(os.path.join(out, "escapado", "eboot.bin")))

    def test_without_crypto_info_works_and_extract_explains(self):
        with tempfile.TemporaryDirectory() as d:
            pkg = os.path.join(d, "t.pkg")
            build_pkg(pkg, {"eboot.bin": b"1"})
            orig = px.CRYPTO_OK
            px.CRYPTO_OK = False
            try:
                code, out, _ = run_cli("info", pkg)
                self.assertEqual(code, 0)
                self.assertIn("Juego de Prueba", out)
                code, _o, err = run_cli("extract", pkg, "-o", os.path.join(d, "o"))
                self.assertEqual(code, 1)
                self.assertIn("cryptography", err)
                self.assertIn("Instalar requisitos", err)
            finally:
                px.CRYPTO_OK = orig

    def test_install_requirements_failure_then_success(self):
        orig = px.load_crypto
        try:
            px.load_crypto = lambda: False
            logs = []
            ok = px.install_requirements(logs.append,
                                         attempts=[[sys.executable, "-c", "import sys; sys.exit(3)"]])
            self.assertFalse(ok)
            self.assertTrue(any("Intento fallido" in line for line in logs))

            seq = iter([False, True])           # antes de instalar: no está; después: ya se puede cargar
            px.load_crypto = lambda: next(seq, True)
            logs = []
            ok = px.install_requirements(
                logs.append, attempts=[[sys.executable, "-c", "print('instalado de mentira')"]])
            self.assertTrue(ok)
            self.assertIn("instalado de mentira", logs)
        finally:
            px.load_crypto = orig

    def test_install_requirements_noop_when_present(self):
        logs = []
        self.assertTrue(px.install_requirements(logs.append, attempts=[["no-existe-este-comando"]]))
        self.assertIn("ya están instalados", logs[0])


# --------------------------------------------------------------------------- #
# Interfaz gráfica (se omite si no hay tkinter o pantalla; en Linux: xvfb-run)
# --------------------------------------------------------------------------- #
try:
    import tkinter as _tk
    import pkg_extractor_gui as gui
except ImportError:                       # p. ej. Python del sistema sin python3-tk
    _tk = gui = None


@unittest.skipIf(gui is None, "tkinter no está instalado")
class GuiHelperTests(unittest.TestCase):
    def test_human_formats(self):
        self.assertEqual(gui.human_size(0), "0 B")
        self.assertEqual(gui.human_size(1536), "1.5 KiB")
        self.assertEqual(gui.human_size(5 * 1024 ** 3), "5.00 GiB")
        self.assertEqual(gui.human_time(42), "42 s")
        self.assertEqual(gui.human_time(125), "2 min 05 s")
        self.assertEqual(gui.human_time(3700), "1 h 01 min")

    def test_file_line_matches_what_run_extract_logs(self):
        with tempfile.TemporaryDirectory() as d:
            pkg = os.path.join(d, "a.pkg")
            build_pkg(pkg, sample_tree())
            lines = []
            px.run_extract(pkg, os.path.join(d, "o"), log=lines.append)
            hits = [m for m in (gui.FILE_LINE.match(line) for line in lines) if m]
            self.assertEqual(len(hits), len(list(flatten(sample_tree()))))
            self.assertIn("Media/datos.bin", [m.group(3) for m in hits])

    def test_summary_and_check_keys(self):
        with tempfile.TemporaryDirectory() as d:
            pkg = os.path.join(d, "a.pkg")
            build_pkg(pkg, sample_tree())
            s = gui.read_summary(pkg)
            self.assertEqual((s["title"], s["title_id"], s["kind"], s["version"]),
                             ("Juego de Prueba", "CUSA99999", "Juego base", "01.00"))
            logs = []
            self.assertTrue(gui.check_keys(pkg, None, None, logs.append))
            self.assertIn("Clave correcta", logs[0])
            logs = []
            self.assertFalse(gui.check_keys(pkg, "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", None, logs.append))
            self.assertIn("no abre", logs[0])
            junk = os.path.join(d, "junk.pkg")
            with open(junk, "wb") as f:
                f.write(b"x" * 5000)
            with self.assertRaises(px.PkgError):
                gui.read_summary(junk)

    def test_config_roundtrip_and_corruption(self):
        with tempfile.TemporaryDirectory() as d:
            orig = gui.CONFIG_PATH
            gui.CONFIG_PATH = os.path.join(d, "cfg.json")
            try:
                self.assertEqual(gui.load_config(), {})
                gui.save_config({"last_output": "C:\\juegos ñ"})
                self.assertEqual(gui.load_config(), {"last_output": "C:\\juegos ñ"})
                with open(gui.CONFIG_PATH, "w") as f:
                    f.write("{no es json")
                self.assertEqual(gui.load_config(), {})
            finally:
                gui.CONFIG_PATH = orig


@unittest.skipIf(gui is None, "tkinter no está instalado")
class GuiTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = _tk.Tk()
        except _tk.TclError:
            self.skipTest("no hay pantalla (en Linux usa xvfb-run)")
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self._cfg = gui.CONFIG_PATH
        gui.CONFIG_PATH = os.path.join(self.d, "cfg.json")
        mb = gui.messagebox
        self._saved = (mb.showinfo, mb.showerror, mb.showwarning, mb.askyesno)
        self.msgs, self.answer = [], True
        mb.showinfo = lambda *a, **k: self.msgs.append(("info",) + a)
        mb.showerror = lambda *a, **k: self.msgs.append(("error",) + a)
        mb.showwarning = lambda *a, **k: self.msgs.append(("warning",) + a)
        mb.askyesno = lambda *a, **k: (self.msgs.append(("ask",) + a), self.answer)[1]
        self._crypto = px.CRYPTO_OK
        self._install = px.install_requirements
        self._chunk, self._copy = px.COPY_CHUNK, px.copy_file
        self.app = gui.App(self.root)

    def tearDown(self):
        mb = gui.messagebox
        mb.showinfo, mb.showerror, mb.showwarning, mb.askyesno = self._saved
        px.CRYPTO_OK, px.install_requirements = self._crypto, self._install
        px.COPY_CHUNK, px.copy_file = self._chunk, self._copy
        gui.CONFIG_PATH = self._cfg
        self.root.destroy()
        self.tmp.cleanup()

    def pump(self, seconds=0.2):
        end = time.time() + seconds
        while time.time() < end:
            self.root.update()
            time.sleep(0.01)

    def wait_idle(self, timeout=60):
        end = time.time() + timeout
        while (self.app.busy or not self.app.q.empty()) and time.time() < end:
            self.root.update()
            time.sleep(0.01)
        self.pump(0.2)
        self.assertEqual(self.app.busy, "", "la operación no terminó a tiempo")

    def log_text(self):
        return self.app.logbox.get("1.0", "end")

    def load(self, tree=None, **kw):
        pkg = os.path.join(self.d, "juego.pkg")
        build_pkg(pkg, tree or sample_tree(), **kw)
        self.app.pkg_var.set(pkg)
        self.app.load_info()
        self.app.out_var.set(os.path.join(self.d, "salida"))
        return pkg

    def test_full_flow(self):
        tree = sample_tree()
        self.load(tree)
        self.assertIn("Juego de Prueba", self.app.card_title.cget("text"))
        self.assertIn("Juego base", self.app.card_detail.cget("text"))
        self.app._update_dest()
        self.assertIn("CUSA99999", self.app.dest_label.cget("text"))
        self.app.start_extract()
        self.assertEqual(self.app.busy, "extract")
        self.assertEqual(str(self.app.extract_btn.cget("state")), "disabled")
        self.assertEqual(str(self.app.cancel_btn.cget("state")), "normal")
        self.wait_idle()
        root = os.path.join(self.d, "salida", "CUSA99999")
        for rel, data in flatten(tree):
            with open(os.path.join(root, *rel.split("/")), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).digest(), hashlib.sha256(data).digest(), rel)
        self.assertEqual(float(self.app.bar.cget("value")), 1000.0)
        self.assertEqual(str(self.app.open_btn.cget("state")), "normal")
        self.assertEqual(str(self.app.extract_btn.cget("state")), "normal")
        self.assertTrue(any(m[0] == "info" and "Extracción terminada" in m[1] for m in self.msgs))
        self.assertNotIn("[1/", self.log_text())          # el avance por archivo va a la línea de estado
        self.assertEqual(gui.load_config().get("last_output"), os.path.join(self.d, "salida"))

    def test_wrong_passcode_shows_error_and_recovers(self):
        self.load(passcode="ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
        self.app.start_extract()
        self.wait_idle()
        errors = [m for m in self.msgs if m[0] == "error"]
        self.assertEqual(len(errors), 1)
        self.assertIn("passcode", errors[0][2].lower())
        self.assertIn("Error:", self.log_text())
        self.assertEqual(str(self.app.extract_btn.cget("state")), "normal")
        self.app.pass_var.set("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")          # con la clave buena sí funciona
        self.msgs.clear()
        self.app.start_extract()
        self.wait_idle()
        self.assertTrue(any(m[0] == "info" for m in self.msgs))

    def test_missing_requirements_button_flow(self):
        self.load()
        px.CRYPTO_OK = False
        self.app._refresh_requirements()
        self.assertIn("Falta", self.app.req_label.cget("text"))
        self.assertEqual(str(self.app.extract_btn.cget("state")), "disabled")
        self.assertEqual(str(self.app.req_btn.cget("state")), "normal")
        self.app.start_extract()                                    # sin requisitos: avisa, no arranca
        self.assertEqual(self.app.busy, "")
        self.assertTrue(any("Instalar requisitos" in m[2] for m in self.msgs))

        def fake_install(log=print, attempts=None):
            log("> pip install cryptography")
            time.sleep(0.2)
            px.CRYPTO_OK = True
            log("Requisitos instalados correctamente.")
            return True

        px.install_requirements = fake_install
        self.app.install_deps()
        self.assertEqual(self.app.busy, "install")
        self.assertEqual(str(self.app.req_btn.cget("state")), "disabled")
        self.wait_idle()
        self.assertIn("instalados", self.app.req_label.cget("text"))
        self.assertEqual(str(self.app.extract_btn.cget("state")), "normal")
        self.assertEqual(str(self.app.req_btn.cget("state")), "disabled")
        self.assertIn("pip install cryptography", self.log_text())

    def test_failed_install_warns(self):
        px.CRYPTO_OK = False
        self.app._refresh_requirements()
        px.install_requirements = lambda log=print, attempts=None: (log("sin internet"), False)[1]
        self.app.install_deps()
        self.wait_idle()
        self.assertTrue(any(m[0] == "warning" for m in self.msgs))
        self.assertEqual(str(self.app.req_btn.cget("state")), "normal")     # se puede reintentar

    def test_cancel_midway_removes_partial_file(self):
        self.load()
        px.COPY_CHUNK = 64 * 1024
        orig = self._copy
        app = self.app

        def cancelling(*a, **k):
            app.cancel_event.set()                                  # Event es seguro entre hilos
            return orig(*a, **k)

        px.copy_file = cancelling
        self.app.start_extract()
        self.wait_idle()
        self.assertEqual(self.app.prog_label.cget("text"), "Cancelado")
        self.assertIn("Cancelado", self.log_text())
        self.assertFalse(os.path.exists(os.path.join(self.d, "salida", "CUSA99999", "eboot.bin")))
        self.assertEqual(str(self.app.extract_btn.cget("state")), "normal")

    def test_existing_folder_asks_before_overwriting(self):
        self.load()
        dest = os.path.join(self.d, "salida", "CUSA99999")
        os.makedirs(dest)
        with open(os.path.join(dest, "eboot.bin"), "wb") as f:
            f.write(b"VIEJO")
        self.answer = False
        self.app.start_extract()
        self.assertEqual(self.app.busy, "")
        self.assertTrue(any(m[0] == "ask" for m in self.msgs))
        with open(os.path.join(dest, "eboot.bin"), "rb") as f:
            self.assertEqual(f.read(), b"VIEJO")
        self.answer = True
        self.app.start_extract()
        self.wait_idle()
        with open(os.path.join(dest, "eboot.bin"), "rb") as f:
            self.assertNotEqual(f.read(), b"VIEJO")

    def test_check_and_list_buttons(self):
        self.load()
        self.app.start_check()
        self.wait_idle()
        self.assertIn("Clave correcta", self.log_text())
        self.assertIn("Clave correcta", self.app.prog_label.cget("text"))
        self.app.start_list()
        self.wait_idle()
        self.assertIn("Media/datos.bin", self.log_text())
        self.app.pass_var.set("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
        self.app.start_check()
        self.wait_idle()
        self.assertIn("no abre", self.log_text())

    def test_bad_inputs_are_reported_not_crashing(self):
        self.app.start_extract()                                    # sin PKG
        self.assertTrue(any(m[0] == "warning" for m in self.msgs))
        self.app.pkg_var.set(os.path.join(self.d, "no_existe.pkg"))
        self.app.load_info()
        self.assertEqual(self.app.card_title.cget("text"), "No se pudo leer este archivo")
        self.app.start_extract()
        self.assertEqual(self.app.busy, "")
        self.assertEqual(len([m for m in self.msgs if m[0] == "warning"]), 2)

    def test_advanced_panel_toggles(self):
        self.pump()
        self.assertFalse(self.app.adv.winfo_ismapped())
        self.app.toggle_adv()
        self.pump()
        self.assertTrue(self.app.adv.winfo_ismapped())
        self.app.toggle_adv()
        self.pump()
        self.assertFalse(self.app.adv.winfo_ismapped())

    def test_flat_option_changes_destination(self):
        self.load()
        self.app._update_dest()
        self.assertTrue(self.app.dest_label.cget("text").endswith("CUSA99999"))
        self.app.flat_var.set(True)
        self.app._update_dest()
        self.assertTrue(self.app.dest_label.cget("text").endswith("salida"))

    def test_initial_pkg_argument_prefills_card(self):
        pkg = os.path.join(self.d, "arrastrado.pkg")
        build_pkg(pkg, {"eboot.bin": b"1"})
        app2 = gui.App(_tk.Toplevel(self.root), initial_pkg=pkg)
        self.assertIn("Juego de Prueba", app2.card_title.cget("text"))
        self.assertTrue(app2.out_var.get().endswith("juegos_extraidos"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
