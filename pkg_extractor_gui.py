#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pkg_extractor_gui.py - Ventana sencilla para el extractor de PKG de PS4.

Cómo abrirla: doble clic en este archivo o en Iniciar_Extractor.bat. También puedes arrastrar
un .pkg sobre este archivo, o ejecutar:  python pkg_extractor_gui.py juego.pkg

Si falta la librería 'cryptography', arriba aparece el botón «Instalar requisitos».
Solo usa tkinter, que viene con Python.
"""
from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import traceback
from typing import Callable, Dict, Optional, Tuple

try:
    import tkinter as tk
    from tkinter import filedialog, font as tkfont, messagebox, ttk
except ImportError:  # pragma: no cover - depende de cómo esté instalado Python
    sys.exit(
        "Esta ventana necesita tkinter, que no está instalado en tu Python.\n"
        "  Windows: reinstala Python desde python.org dejando marcada la opción «tcl/tk and IDLE».\n"
        "  Linux:   sudo apt install python3-tk"
    )

import pkg_extractor as core

APP_TITLE = "Extractor de PKG de PS4"
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".ps4_pkg_extractor.json")
CRASH_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pkg_extractor_gui_error.log")

ACCENT, ACCENT_DARK = "#2563eb", "#1d4ed8"
OK_COLOR, ERR_COLOR, DIM_COLOR = "#15803d", "#b91c1c", "#6b7280"

# Formato exacto que escribe pkg_extractor.run_extract por cada archivo: "[n/m]  pct%  ruta".
# La ventana lo muestra en la línea de estado en vez de llenar el registro con miles de líneas.
FILE_LINE = re.compile(r"^\[(\d+)/(\d+)\]\s+[\d.]+%\s+(.*)$")
MAX_LOG_LINES = 6000

CATEGORY_NAMES = {
    "gd": "Juego base",
    "gp": "Parche / actualización",
    "ac": "DLC / contenido adicional",
    "al": "DLC sin datos",
}


# --------------------------------------------------------------------------- #
# Utilidades sin interfaz (se prueban por separado)
# --------------------------------------------------------------------------- #
def human_size(n: float) -> str:
    n = float(n)
    for unit in ("B", "KiB", "MiB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.2f} GiB"


def human_time(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} min {secs:02d} s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes:02d} min"


def read_summary(pkg: str) -> Dict[str, str]:
    """Datos para la ficha del juego. Solo lee la cabecera: no necesita claves ni 'cryptography'."""
    with core.open_package(pkg, need_keys=False) as (_f, hdr, _entries, sfo, _inner):
        sfo = sfo or {}
        category = str(sfo.get("CATEGORY", ""))
        return {
            "title": str(sfo.get("TITLE") or "(sin título)"),
            "title_id": str(sfo.get("TITLE_ID") or hdr.content_id[7:16]),
            "category": category,
            "kind": CATEGORY_NAMES.get(category)
                    or core.CONTENT_TYPES.get(hdr.content_type, "Tipo desconocido"),
            "version": str(sfo.get("APP_VER") or sfo.get("VERSION") or "?"),
            "size": human_size(hdr.package_size or hdr.pfs_image_size),
        }


def check_keys(pkg: str, passcode: Optional[str], ekpfs: Optional[str],
               log: Callable[[str], None]) -> bool:
    """Comprueba si el passcode/EKPFS abre el PKG, sin extraer nada."""
    try:
        with core.open_package(pkg, passcode, ekpfs) as (_f, _hdr, _entries, _sfo, inner):
            sizes = [inner.inodes[i].size for _r, kind, i in inner.walk(inner.uroot_ino())
                     if kind != core.DIRENT_DIR]
    except core.PkgError as exc:
        log(f"✖ La clave no abre este PKG: {exc}")
        return False
    log(f"✔ Clave correcta: el juego tiene {len(sizes)} archivos ({human_size(sum(sizes))}).")
    return True


def load_config() -> Dict[str, str]:
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(cfg: Dict[str, str]) -> None:
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except OSError:
        pass                                   # guardar preferencias nunca debe estorbar


def open_folder(path: str) -> None:
    if sys.platform.startswith("win"):
        os.startfile(path)                     # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


# --------------------------------------------------------------------------- #
# Ventana
# --------------------------------------------------------------------------- #
class App:
    def __init__(self, root: tk.Tk, initial_pkg: Optional[str] = None):
        self.root = root
        self.q: "queue.Queue[Tuple]" = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker: Optional[threading.Thread] = None
        self.busy = ""                  # "" = libre | "extract" | "check" | "list" | "install"
        self.last_dest: Optional[str] = None
        self.cfg = load_config()
        self._loaded_pkg: Optional[str] = None
        self._pkg_ok = False
        self._t0 = 0.0
        self._last_prog = 0.0
        self._dest_job: Optional[str] = None

        self.pkg_var = tk.StringVar()
        self.out_var = tk.StringVar(value=self.cfg.get("last_output", ""))
        self.pass_var = tk.StringVar()
        self.ekpfs_var = tk.StringVar()
        self.flat_var = tk.BooleanVar(value=False)
        self.suffix_var = tk.StringVar(value=self.cfg.get("patch_suffix", "-patch"))
        self.entries_var = tk.BooleanVar(value=False)

        self._build()
        for var in (self.out_var, self.flat_var, self.suffix_var):
            var.trace_add("write", lambda *_: self._schedule_dest_update())
        self._refresh_requirements()
        if initial_pkg:
            self.pkg_var.set(initial_pkg)
            self.load_info()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(80, self._poll)

    # ---- construcción --------------------------------------------------- #
    def _build(self) -> None:
        r = self.root
        r.title(APP_TITLE)
        r.minsize(700, 500)
        r.geometry(f"780x{max(520, min(700, r.winfo_screenheight() - 100))}")
        self._h_before: Optional[int] = None
        r.columnconfigure(0, weight=1)
        r.rowconfigure(7, weight=1)

        base = tkfont.nametofont("TkDefaultFont")
        base.configure(size=10)
        self.f_bold = tkfont.Font(font=base)
        self.f_bold.configure(weight="bold")
        self.f_title = tkfont.Font(font=base)
        self.f_title.configure(size=17, weight="bold")

        head = ttk.Frame(r)
        head.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 2))
        ttk.Label(head, text=APP_TITLE, font=self.f_title).pack(anchor="w")
        ttk.Label(head, text="Para juegos de PS4 que tú mismo volcaste de tu consola.",
                  foreground=DIM_COLOR).pack(anchor="w")

        bar = ttk.Frame(r)
        bar.grid(row=1, column=0, sticky="ew", padx=16, pady=(8, 2))
        bar.columnconfigure(0, weight=1)
        self.req_label = ttk.Label(bar, text="", font=self.f_bold)
        self.req_label.grid(row=0, column=0, sticky="w")
        self.req_btn = ttk.Button(bar, text="Instalar requisitos", command=self.install_deps)
        self.req_btn.grid(row=0, column=1, sticky="e")

        s1 = ttk.LabelFrame(r, text=" 1 · Archivo PKG ", padding=10)
        s1.grid(row=2, column=0, sticky="ew", padx=16, pady=(8, 4))
        s1.columnconfigure(0, weight=1)
        e1 = ttk.Entry(s1, textvariable=self.pkg_var)
        e1.grid(row=0, column=0, sticky="ew")
        e1.bind("<Return>", lambda _e: self.load_info())
        e1.bind("<FocusOut>", lambda _e: self._maybe_reload())
        ttk.Button(s1, text="Examinar…", command=self.pick_pkg).grid(row=0, column=1, padx=(8, 0))
        self.card_title = ttk.Label(s1, text="", font=self.f_bold)
        self.card_title.grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self.card_detail = ttk.Label(s1, text="", justify="left")
        self.card_detail.grid(row=2, column=0, columnspan=2, sticky="w")
        s1.bind("<Configure>", lambda e: self.card_detail.configure(wraplength=max(200, e.width - 30)))
        self._set_card("Elige un archivo .pkg para empezar.", "", DIM_COLOR)

        s2 = ttk.LabelFrame(r, text=" 2 · Carpeta de salida ", padding=10)
        s2.grid(row=3, column=0, sticky="ew", padx=16, pady=4)
        s2.columnconfigure(0, weight=1)
        ttk.Entry(s2, textvariable=self.out_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(s2, text="Examinar…", command=self.pick_out).grid(row=0, column=1, padx=(8, 0))
        self.dest_label = ttk.Label(s2, text="", foreground=DIM_COLOR, justify="left")
        self.dest_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))
        s2.bind("<Configure>", lambda e: self.dest_label.configure(wraplength=max(200, e.width - 30)))

        holder = ttk.Frame(r)
        holder.grid(row=4, column=0, sticky="ew", padx=16)
        holder.columnconfigure(0, weight=1)
        self.adv_btn = ttk.Button(holder, text="▸ Opciones avanzadas", command=self.toggle_adv)
        self.adv_btn.grid(row=0, column=0, sticky="w", pady=(2, 0))
        self.adv = ttk.LabelFrame(holder, padding=10)
        self.adv.grid(row=1, column=0, sticky="ew", pady=(4, 0))
        self.adv.grid_remove()
        self.adv_open = False
        ttk.Label(self.adv, text="Passcode:").grid(row=0, column=0, sticky="w")
        ttk.Entry(self.adv, textvariable=self.pass_var, width=36).grid(row=0, column=1, sticky="w", padx=6)
        ttk.Label(self.adv, text="vacío = el habitual (32 ceros)", foreground=DIM_COLOR
                  ).grid(row=0, column=2, sticky="w")
        ttk.Label(self.adv, text="EKPFS (hex):").grid(row=1, column=0, sticky="w", pady=(4, 0))
        ttk.Entry(self.adv, textvariable=self.ekpfs_var, width=36).grid(
            row=1, column=1, sticky="w", padx=6, pady=(4, 0))
        ttk.Label(self.adv, text="solo si ya lo conoces", foreground=DIM_COLOR
                  ).grid(row=1, column=2, sticky="w", pady=(4, 0))
        ttk.Label(self.adv, text="Sufijo de parches:").grid(row=2, column=0, sticky="w", pady=(4, 0))
        ttk.Combobox(self.adv, textvariable=self.suffix_var, values=["-patch", "-UPDATE"], width=12
                     ).grid(row=2, column=1, sticky="w", padx=6, pady=(4, 0))
        ttk.Label(self.adv, text="carpeta del parche: ID + sufijo", foreground=DIM_COLOR
                  ).grid(row=2, column=2, sticky="w", pady=(4, 0))
        ttk.Checkbutton(self.adv, variable=self.flat_var,
                        text="Extraer directamente en la carpeta de salida (sin subcarpeta con el ID del juego)"
                        ).grid(row=3, column=0, columnspan=3, sticky="w", pady=(6, 0))
        ttk.Checkbutton(self.adv, variable=self.entries_var,
                        text="Guardar también el icono y param.sfo del PKG (carpeta _pkg_entries)"
                        ).grid(row=4, column=0, columnspan=3, sticky="w")

        act = ttk.Frame(r)
        act.grid(row=5, column=0, sticky="ew", padx=16, pady=(12, 4))
        self.extract_btn = tk.Button(
            act, text="Extraer juego", command=self.start_extract, bg=ACCENT, fg="white",
            activebackground=ACCENT_DARK, activeforeground="white", disabledforeground="#f3f4f6",
            relief="flat", bd=0, padx=22, pady=8, font=self.f_bold, cursor="hand2")
        self.extract_btn.pack(side="left")
        self.check_btn = ttk.Button(act, text="Comprobar clave", command=self.start_check)
        self.check_btn.pack(side="left", padx=(10, 0))
        self.list_btn = ttk.Button(act, text="Ver archivos", command=self.start_list)
        self.list_btn.pack(side="left", padx=(6, 0))
        self.open_btn = ttk.Button(act, text="Abrir carpeta", command=self.open_output)
        self.open_btn.pack(side="right")
        self.cancel_btn = ttk.Button(act, text="Cancelar", command=self.cancel)
        self.cancel_btn.pack(side="right", padx=(0, 6))

        prog = ttk.Frame(r)
        prog.grid(row=6, column=0, sticky="ew", padx=16, pady=(6, 2))
        prog.columnconfigure(0, weight=1)
        ttk.Style(r).configure("Accent.Horizontal.TProgressbar", background=ACCENT,
                               troughcolor="#e5e7eb", bordercolor="#d1d5db",
                               lightcolor=ACCENT, darkcolor=ACCENT_DARK)
        self.bar = ttk.Progressbar(prog, maximum=1000, mode="determinate",
                                   style="Accent.Horizontal.TProgressbar")
        self.bar.grid(row=0, column=0, sticky="ew")
        self.prog_label = ttk.Label(prog, text="", font=self.f_bold)
        self.prog_label.grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.file_label = ttk.Label(prog, text="", foreground=DIM_COLOR)
        self.file_label.grid(row=2, column=0, sticky="w")

        logf = ttk.Frame(r)
        logf.grid(row=7, column=0, sticky="nsew", padx=16, pady=(6, 14))
        logf.columnconfigure(0, weight=1)
        logf.rowconfigure(0, weight=1)
        self.logbox = tk.Text(logf, height=6, wrap="word", state="disabled", relief="flat",
                              bg="#f4f5f7", fg="#111827", padx=8, pady=6, font="TkFixedFont")
        self.logbox.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(logf, command=self.logbox.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.logbox.configure(yscrollcommand=sb.set)
        self.logbox.tag_configure("ok", foreground=OK_COLOR)
        self.logbox.tag_configure("err", foreground=ERR_COLOR)

    # ---- registro y estado ---------------------------------------------- #
    def log(self, text: str) -> None:
        self.logbox.configure(state="normal")
        for line in str(text).splitlines() or [""]:
            tag = "ok" if line.startswith("✔") else "err" if line.startswith(("✖", "Error")) else ""
            self.logbox.insert("end", line + "\n", tag)
        lines = int(self.logbox.index("end-1c").split(".")[0])
        if lines > MAX_LOG_LINES:
            self.logbox.delete("1.0", f"{lines - MAX_LOG_LINES}.0")
        self.logbox.see("end")
        self.logbox.configure(state="disabled")

    def _qlog(self, text: str) -> None:        # lo llama el hilo de trabajo
        self.q.put(("log", text))

    def _make_progress(self) -> Callable[[int, int], None]:
        def cb(done: int, total: int) -> None:
            now = time.monotonic()
            if now - self._last_prog < 0.1 and done < total:
                return
            self._last_prog = now
            self.q.put(("progress", done, total))
        return cb

    def _set_card(self, title: str, detail: str, color: Optional[str]) -> None:
        self.card_title.configure(text=title, foreground=color or "")
        self.card_detail.configure(text=detail, foreground=color if color == ERR_COLOR else "")

    def _refresh_requirements(self) -> None:
        if core.CRYPTO_OK:
            self.req_label.configure(text="✔ Requisitos instalados", foreground=OK_COLOR)
        else:
            self.req_label.configure(
                text="✖ Falta instalar «cryptography» (hace falta para descifrar el juego)",
                foreground=ERR_COLOR)
        self._update_buttons()

    def _update_buttons(self) -> None:
        free = not self.busy
        ready = free and core.CRYPTO_OK
        for btn in (self.extract_btn, self.check_btn, self.list_btn):
            btn.configure(state="normal" if ready else "disabled")
        self.extract_btn.configure(bg=ACCENT if ready else "#9ca3af",
                                   cursor="hand2" if ready else "arrow")
        self.req_btn.configure(state="normal" if free and not core.CRYPTO_OK else "disabled")
        self.cancel_btn.configure(state="normal" if self.busy == "extract" else "disabled")
        can_open = free and bool(self.last_dest) and os.path.isdir(self.last_dest or "")
        self.open_btn.configure(state="normal" if can_open else "disabled")

    def _set_busy(self, kind: str) -> None:
        self.busy = kind
        self.bar.stop()
        if kind == "install":
            self.bar.configure(mode="indeterminate")
            self.bar.start(12)
        else:
            self.bar.configure(mode="determinate", value=0)
        self._update_buttons()

    # ---- elegir archivos ------------------------------------------------- #
    def pick_pkg(self) -> None:
        path = filedialog.askopenfilename(
            title="Elige el archivo PKG", initialdir=self.cfg.get("last_pkg_dir") or None,
            filetypes=[("Paquetes de PS4", "*.pkg"), ("Todos los archivos", "*.*")])
        if path:
            self.pkg_var.set(path)
            self.load_info()

    def pick_out(self) -> None:
        path = filedialog.askdirectory(title="Elige la carpeta de salida",
                                       initialdir=self.out_var.get().strip() or None)
        if path:
            self.out_var.set(path)

    def _maybe_reload(self) -> None:
        if self.pkg_var.get().strip().strip('"') != (self._loaded_pkg or ""):
            self.load_info()

    def load_info(self) -> None:
        path = self.pkg_var.get().strip().strip('"')
        self.pkg_var.set(path)
        self._loaded_pkg = path
        self._pkg_ok = False
        if not path:
            self._set_card("Elige un archivo .pkg para empezar.", "", DIM_COLOR)
            self._update_dest()
            return
        try:
            s = read_summary(path)
        except (core.PkgError, OSError) as exc:
            self._set_card("No se pudo leer este archivo", str(exc), ERR_COLOR)
            self._update_dest()
            return
        self._pkg_ok = True
        detail = f"{s['kind']}  ·  versión {s['version']}  ·  {s['size']}"
        if s["category"] == "gp":
            detail += "\nEs un parche: extrae primero el juego base y después este parche."
        self._set_card(f"{s['title']}  ({s['title_id']})", detail, None)
        if not self.out_var.get().strip():
            self.out_var.set(os.path.join(os.path.dirname(os.path.abspath(path)), "juegos_extraidos"))
        self._update_dest()

    def toggle_adv(self) -> None:
        self.adv_open = not self.adv_open
        self.root.update_idletasks()
        have = self.root.winfo_height()
        if self.adv_open:
            self.adv.grid()
            self.adv_btn.configure(text="▾ Opciones avanzadas")
            self.root.update_idletasks()
            need = self.root.winfo_reqheight()
            limit = self.root.winfo_screenheight() - 80
            if need > have:
                self._h_before = have
                self.root.geometry(f"{self.root.winfo_width()}x{min(need, limit)}")
        else:
            self.adv.grid_remove()
            self.adv_btn.configure(text="▸ Opciones avanzadas")
            if self._h_before:
                self.root.geometry(f"{self.root.winfo_width()}x{self._h_before}")
                self._h_before = None

    def _schedule_dest_update(self) -> None:
        if self._dest_job is not None:
            self.root.after_cancel(self._dest_job)
        self._dest_job = self.root.after(250, self._update_dest)

    def _dest(self) -> Optional[str]:
        pkg, out = self._loaded_pkg, self.out_var.get().strip()
        if not (pkg and out and self._pkg_ok):
            return None
        try:
            return core.destination_for(pkg, out, self.flat_var.get(), self.suffix_var.get().strip())
        except (core.PkgError, OSError):
            return None

    def _update_dest(self) -> None:
        self._dest_job = None
        dest = self._dest()
        self.dest_label.configure(text=f"El juego quedará en:  {dest}" if dest else "")

    # ---- validaciones comunes --------------------------------------------- #
    def _need_pkg(self) -> Optional[str]:
        self._maybe_reload()
        path = (self._loaded_pkg or "").strip()
        if not path:
            messagebox.showwarning(APP_TITLE, "Elige primero el archivo .pkg (paso 1).")
            return None
        if not self._pkg_ok:
            messagebox.showwarning(APP_TITLE, "Ese archivo no se pudo leer como PKG de PS4. "
                                              "Revisa el mensaje en rojo del paso 1.")
            return None
        return path

    def _need_out(self) -> Optional[str]:
        out = self.out_var.get().strip().strip('"')
        if not out:
            messagebox.showwarning(APP_TITLE, "Elige la carpeta de salida (paso 2).")
            return None
        return out

    def _keys(self) -> Tuple[Optional[str], Optional[str]]:
        return (self.pass_var.get().strip() or None, self.ekpfs_var.get().strip() or None)

    def _save_config(self) -> None:
        pkg = self._loaded_pkg or ""
        self.cfg.update(last_output=self.out_var.get().strip(), patch_suffix=self.suffix_var.get().strip(),
                        last_pkg_dir=os.path.dirname(pkg) if pkg else self.cfg.get("last_pkg_dir", ""))
        save_config(self.cfg)

    # ---- acciones ----------------------------------------------------------- #
    def _start(self, kind: str, fn: Callable[[], object], status: str = "") -> None:
        self.cancel_event.clear()
        self._t0 = time.monotonic()
        self._last_prog = 0.0
        self.prog_label.configure(text=status, foreground="")
        self.file_label.configure(text="")
        self._set_busy(kind)

        def target() -> None:
            try:
                self.q.put(("done", kind, fn()))
            except core.Cancelled:
                self.q.put(("cancelled", kind, None))
            except (core.PkgError, OSError) as exc:
                self.q.put(("error", kind, str(exc)))
            except Exception:
                self.q.put(("crash", kind, traceback.format_exc()))

        self.worker = threading.Thread(target=target, daemon=True)
        self.worker.start()

    def install_deps(self) -> None:
        if self.busy or core.CRYPTO_OK:
            return
        self.log("Instalando requisitos (puede tardar un minuto)…")
        self._start("install", lambda: core.install_requirements(log=self._qlog),
                    "Instalando requisitos…")

    def start_extract(self) -> None:
        if self.busy:
            return
        pkg = self._need_pkg()
        if not pkg:
            return
        out = self._need_out()
        if not out:
            return
        if not core.CRYPTO_OK:
            messagebox.showinfo(APP_TITLE, "Primero pulsa «Instalar requisitos» (arriba a la derecha).")
            return
        dest = self._dest()
        if dest and os.path.isdir(dest) and os.listdir(dest):
            if not messagebox.askyesno(
                    "La carpeta ya existe",
                    f"«{dest}» ya contiene archivos.\nSi continúas, los que tengan el mismo nombre "
                    f"se reemplazarán.\n\n¿Continuar?"):
                return
        self._save_config()
        self.last_dest = None
        passcode, ekpfs = self._keys()
        flat, suffix, entries = self.flat_var.get(), self.suffix_var.get().strip(), self.entries_var.get()
        progress = self._make_progress()
        self._start("extract", lambda: core.run_extract(
            pkg, out, passcode=passcode, ekpfs=ekpfs, flat=flat, patch_suffix=suffix, entries=entries,
            log=self._qlog, progress=progress, cancel=self.cancel_event.is_set), "Preparando…")

    def start_check(self) -> None:
        if self.busy:
            return
        pkg = self._need_pkg()
        if not pkg:
            return
        passcode, ekpfs = self._keys()
        self._start("check", lambda: check_keys(pkg, passcode, ekpfs, self._qlog),
                    "Comprobando la clave…")

    def start_list(self) -> None:
        if self.busy:
            return
        pkg = self._need_pkg()
        if not pkg:
            return
        passcode, ekpfs = self._keys()
        self._start("list", lambda: core.run_list(pkg, passcode, ekpfs, log=self._qlog),
                    "Leyendo el contenido…")

    def cancel(self) -> None:
        if self.busy == "extract":
            self.cancel_event.set()
            self.prog_label.configure(text="Cancelando…")

    def open_output(self) -> None:
        if self.last_dest and os.path.isdir(self.last_dest):
            try:
                open_folder(self.last_dest)
            except OSError as exc:
                messagebox.showerror(APP_TITLE, f"No se pudo abrir la carpeta: {exc}")

    # ---- mensajes del hilo de trabajo --------------------------------------- #
    def _poll(self) -> None:
        for _ in range(300):                   # un tope por vuelta para no congelar la ventana
            try:
                msg = self.q.get_nowait()
            except queue.Empty:
                break
            self._handle(msg)
        self.root.after(30 if not self.q.empty() else 80, self._poll)

    def _handle(self, msg: Tuple) -> None:
        kind = msg[0]
        if kind == "log":
            m = FILE_LINE.match(msg[1])
            if m and self.busy == "extract":
                self.file_label.configure(text=f"Archivo {m.group(1)} de {m.group(2)}:  {m.group(3)}")
            else:
                self.log(msg[1])
        elif kind == "progress":
            self._show_progress(msg[1], msg[2])
        elif kind == "done":
            self._on_done(msg[1], msg[2])
        elif kind == "cancelled":
            self._set_busy("")
            self.prog_label.configure(text="Cancelado")
            self.file_label.configure(text="")
            self.log("Cancelado. Lo que ya se había extraído se queda en la carpeta de salida.")
        elif kind == "error":
            self._set_busy("")
            self.prog_label.configure(text="No se pudo completar")
            self.file_label.configure(text="")
            self.log(f"Error: {msg[2]}")
            messagebox.showerror(APP_TITLE, msg[2])
        elif kind == "crash":
            self._set_busy("")
            self.prog_label.configure(text="Error inesperado")
            self.log("Error inesperado:\n" + msg[2])
            self._write_crash_log(msg[2])
            messagebox.showerror(APP_TITLE, "Ocurrió un error inesperado. Los detalles están en el "
                                            "registro de abajo.")

    def _show_progress(self, done: int, total: int) -> None:
        frac = done / total if total else 1.0
        self.bar.configure(value=frac * 1000)
        text = f"{frac * 100:.1f}%  ·  {human_size(done)} de {human_size(total)}"
        elapsed = time.monotonic() - self._t0
        if elapsed > 2 and done > 0:
            rate = done / elapsed
            text += f"  ·  {human_size(rate)}/s"
            if done < total:
                text += f"  ·  faltan ~{human_time((total - done) / rate)}"
        self.prog_label.configure(text=text)

    def _on_done(self, kind: str, result: object) -> None:
        self._set_busy("")
        if kind == "extract":
            self.last_dest = str(result)
            self.bar.configure(value=1000)
            self.prog_label.configure(text="✔ Listo", foreground=OK_COLOR)
            self.file_label.configure(text="")
            self._update_buttons()
            messagebox.showinfo(
                "Extracción terminada",
                f"El juego quedó en:\n{self.last_dest}\n\n"
                "En shadPS4: Settings → Game Install Directory → elige la carpeta de salida "
                "y pulsa «Refresh List».")
            self.prog_label.configure(foreground="")
        elif kind == "install":
            self._refresh_requirements()
            self.prog_label.configure(text="")
            if not result:
                messagebox.showwarning(APP_TITLE, "No se pudieron instalar los requisitos. "
                                                  "Los detalles están en el registro de abajo.")
        elif kind == "check":
            self.prog_label.configure(text="✔ Clave correcta" if result else "✖ La clave no abre el PKG")
        elif kind == "list":
            self.prog_label.configure(text="")

    def _write_crash_log(self, text: str) -> None:
        try:
            with open(CRASH_LOG, "a", encoding="utf-8") as f:
                f.write(time.strftime("[%Y-%m-%d %H:%M:%S]\n") + text + "\n")
        except OSError:
            pass

    def on_close(self) -> None:
        if self.busy:
            if not messagebox.askyesno(APP_TITLE, "Hay una operación en curso. ¿Cancelar y salir?"):
                return
            self.cancel_event.set()
            if self.worker is not None:
                self.worker.join(timeout=3)
        self.root.destroy()


# --------------------------------------------------------------------------- #
def _enable_dpi_awareness() -> None:
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)     # texto nítido en pantallas escaladas
        except Exception:
            pass


def _apply_theme(root: tk.Tk) -> None:
    style = ttk.Style(root)
    for name in ("vista", "clam"):
        if name in style.theme_names():
            style.theme_use(name)
            break


def main(argv: Optional[list] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    _enable_dpi_awareness()
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"No se pudo abrir la ventana: {exc}", file=sys.stderr)
        return 1
    try:
        _apply_theme(root)
        initial = next((a for a in argv if os.path.isfile(a)), None)
        app = App(root, initial)

        def report(exc_type, exc, tb) -> None:           # errores dentro de la propia ventana
            text = "".join(traceback.format_exception(exc_type, exc, tb))
            app._write_crash_log(text)
            messagebox.showerror(APP_TITLE, f"Error inesperado:\n{exc}\n\nDetalles en:\n{CRASH_LOG}")

        root.report_callback_exception = report
        root.mainloop()
    except Exception:
        text = traceback.format_exc()
        try:
            with open(CRASH_LOG, "a", encoding="utf-8") as f:
                f.write(time.strftime("[%Y-%m-%d %H:%M:%S]\n") + text + "\n")
        except OSError:
            pass
        messagebox.showerror(APP_TITLE, f"No se pudo iniciar la ventana.\n\nDetalles en:\n{CRASH_LOG}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
