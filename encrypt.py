#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import zipfile
import secrets
import threading
import queue
import subprocess
import traceback
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

import tkinter as tk
from tkinter import ttk, filedialog, messagebox


# =========================
# Dependency (pycryptodome) auto install
# =========================

def in_venv() -> bool:
    # venv/virtualenv 감지(대부분 이걸로 잡힘)
    return getattr(sys, "base_prefix", sys.prefix) != sys.prefix or hasattr(sys, "real_prefix")

def try_import_crypto() -> bool:
    try:
        from Crypto.Cipher import AES  # noqa: F401
        return True
    except Exception:
        return False

def pip_install_pycryptodome(log_fn=None) -> bool:
    """
    venv면 --user 없이 설치
    venv 아니면 --user 먼저 시도하고, 실패하면 --user 없이 재시도
    """
    def log(msg: str):
        if log_fn:
            log_fn(msg)

    python = sys.executable

    # 1) venv 환경: --user 금지인 경우가 많으니 빼고 시도
    if in_venv():
        cmds = [
            [python, "-m", "pip", "install", "--upgrade", "pycryptodome"],
        ]
    else:
        # 2) 일반 환경: --user 먼저 → 안되면 일반 설치로 재시도
        cmds = [
            [python, "-m", "pip", "install", "--user", "--upgrade", "pycryptodome"],
            [python, "-m", "pip", "install", "--upgrade", "pycryptodome"],
        ]

    for cmd in cmds:
        try:
            log("필수 구성요소(pycryptodome)를 설치하는 중...")
            log("설치 명령: " + " ".join(cmd))

            p = subprocess.run(cmd, capture_output=True, text=True)
            out = (p.stdout or "").strip()
            err = (p.stderr or "").strip()

            if out:
                log(out)
            if err:
                log(err)

            if p.returncode == 0:
                return True
        except Exception as e:
            log(f"설치 도중 오류가 발생했습니다: {e}")

    return False

def ensure_pycryptodome(log_fn=None) -> bool:
    """
    이미 있으면 OK
    없으면 자동 설치 시도 후 OK/FAIL 반환
    """
    if try_import_crypto():
        return True

    ok = pip_install_pycryptodome(log_fn)
    if not ok:
        return False

    # 설치 후 재확인
    return try_import_crypto()


# =========================
# Core encrypt logic (원본 로직 유지)
# =========================

KEY_LENGTH = 32
VERSION = bytes([0, 0, 0, 0])
MAGIC = bytes([0xFC, 0xB9, 0xCF, 0x9B])
DEFAULT_EXCLUDED_FILES = {"manifest.json", "pack_icon.png", "bug_pack_icon.png"}

def random_key():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return ''.join(secrets.choice(alphabet) for _ in range(KEY_LENGTH))

def pad_to(buf: bytearray, size: int):
    while len(buf) < size:
        buf.append(0)
    return buf

def encrypt_bytes(data: bytes, key: str) -> bytes:
    from Crypto.Cipher import AES
    cipher = AES.new(
        key.encode('utf-8'),
        AES.MODE_CFB,
        iv=key[:16].encode('utf-8'),
        segment_size=8
    )
    return cipher.encrypt(data)

def find_manifest_member(z: zipfile.ZipFile) -> Optional[str]:
    candidates = [i.filename for i in z.infolist() if i.filename.endswith("manifest.json")]
    if not candidates:
        return None
    candidates.sort(key=lambda n: (n.count('/'), len(n)))
    return candidates[0]

def get_manifest_uuid(zip_path: Path) -> str:
    with zipfile.ZipFile(zip_path, 'r') as z:
        name = find_manifest_member(z)
        if not name:
            return "00000000-0000-0000-0000-000000000000"
        try:
            data = z.read(name)
            manifest = json.loads(data.decode('utf-8'))
            return manifest["header"]["uuid"]
        except Exception:
            return "00000000-0000-0000-0000-000000000000"

def is_dir(name: str) -> bool:
    return name.endswith('/')

def is_subpack_file(name: str) -> bool:
    return name.startswith("subpacks/")

def is_subpack_root(name: str) -> bool:
    return name.startswith("subpacks/") and is_dir(name) and name.count('/') == 2

def write_contents_json(zout: zipfile.ZipFile, entry_name: str, content_id: str, master_key: str, entries: list[dict]):
    meta = bytearray()
    meta += VERSION
    meta += MAGIC
    pad_to(meta, 0x10)

    cid = content_id.encode('utf-8')
    if len(cid) > 255:
        raise ValueError("ContentId too long (>255).")
    meta.append(len(cid))
    meta += cid
    pad_to(meta, 0x100)

    content_json = json.dumps({"content": entries}, ensure_ascii=False).encode('utf-8')
    meta += encrypt_bytes(content_json, master_key)
    zout.writestr(entry_name, meta)

@dataclass
class EncryptOptions:
    input_zip: Path
    output_dir: Path
    output_zip: Path
    key_file: Path
    master_key: str
    excluded_files: set[str]

def encrypt_pack(opts: EncryptOptions, log_cb=None, progress_cb=None, cancel_flag=None):
    def log(msg: str):
        if log_cb:
            log_cb(msg)

    def check_cancel():
        if cancel_flag is not None and cancel_flag.is_set():
            raise RuntimeError("작업이 취소되었습니다.")

    inzip = opts.input_zip
    outzip = opts.output_zip
    key_path = opts.key_file
    master_key = opts.master_key
    excluded = opts.excluded_files

    if len(master_key) != KEY_LENGTH:
        raise ValueError(f"마스터 키는 반드시 {KEY_LENGTH}자여야 합니다.")

    uuid = get_manifest_uuid(inzip)
    log(f"Manifest UUID: {uuid}")

    with zipfile.ZipFile(inzip, 'r') as zin, zipfile.ZipFile(outzip, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
        infolist = zin.infolist()

        # Copy directory entries
        for item in infolist:
            check_cancel()
            if is_dir(item.filename):
                zout.writestr(item.filename, b'')

        # Root files
        root_files = []
        for item in infolist:
            name = item.filename
            if is_dir(name) or is_subpack_file(name):
                continue
            root_files.append(name)

        subpack_roots = [i.filename for i in infolist if is_subpack_root(i.filename)]
        subpack_files = {}
        for root in subpack_roots:
            files = []
            for item in infolist:
                name = item.filename
                if is_dir(name) or not name.startswith(root):
                    continue
                files.append(name)
            subpack_files[root] = files

        total = len(root_files) + sum(len(v) for v in subpack_files.values()) + (1 + len(subpack_roots))
        done = 0

        def prog(phase: str):
            if progress_cb:
                progress_cb(done, total, phase)

        content_entries = []

        log(f"루트 파일 {len(root_files)}개를 처리합니다.")
        for name in root_files:
            check_cancel()
            data = zin.read(name)

            if name in excluded:
                zout.writestr(name, data)
                entry_key = None
                log(f"복사: {name}")
            else:
                entry_key = random_key()
                enc = encrypt_bytes(data, entry_key)
                zout.writestr(name, enc)
                log(f"암호화: {name}")

            content_entries.append({"path": name, "key": entry_key})
            done += 1
            prog("루트 파일 처리 중")

        check_cancel()
        write_contents_json(zout, "contents.json", uuid, master_key, content_entries)
        log("contents.json 작성 완료")
        done += 1
        prog("메타데이터 작성 중")

        for root in subpack_roots:
            check_cancel()
            files = subpack_files[root]
            log(f"서브팩 처리: {root} ({len(files)}개)")

            sub_entries = []
            for name in files:
                check_cancel()
                data = zin.read(name)
                entry_key = random_key()
                enc = encrypt_bytes(data, entry_key)
                zout.writestr(name, enc)

                rel = name[len(root):]
                sub_entries.append({"path": rel, "key": entry_key})

                log(f"암호화: {name}")
                done += 1
                prog("서브팩 처리 중")

            check_cancel()
            write_contents_json(zout, f"{root}contents.json", uuid, master_key, sub_entries)
            log(f"{root}contents.json 작성 완료")
            done += 1
            prog("서브팩 메타데이터 작성 중")

    with open(key_path, "wb") as f:
        f.write(master_key.encode('utf-8'))

    info_path = key_path.with_suffix(key_path.suffix + ".info.txt")
    with open(info_path, "w", encoding="utf-8") as f:
        f.write(f"UUID: {uuid}\nEncrypted file: {outzip.name}\n")

    log("완료되었습니다.")
    log(f"출력 ZIP: {outzip.name}")
    log(f"키 파일: {key_path.name}")
    log(f"추가 정보: {info_path.name}")


# =========================
# GUI (깔끔한 라이트 테마)
# =========================

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Resource Pack Encryptor")
        self.geometry("920x620")
        self.minsize(920, 620)

        self.q = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker: Optional[threading.Thread] = None

        self.input_zip: Optional[Path] = None
        self.output_dir: Optional[Path] = None

        self.var_input = tk.StringVar(value="선택된 파일 없음")
        self.var_output = tk.StringVar(value="선택된 폴더 없음")
        self.var_status = tk.StringVar(value="대기 중")
        self.var_phase = tk.StringVar(value="")

        self.var_ex_manifest = tk.BooleanVar(value=True)
        self.var_ex_pack_icon = tk.BooleanVar(value=True)
        self.var_ex_bug_icon = tk.BooleanVar(value=True)

        self._build_ui()
        self._poll_queue()

        # 설치/확인 (UI에 자연어 로그로만 표시)
        self._log("프로그램을 시작했습니다.")
        self._log("필수 구성요소를 확인하는 중...")
        ok = ensure_pycryptodome(self._log)
        if ok:
            self._log("필수 구성요소 확인 완료.")
        else:
            self._log("필수 구성요소 설치에 실패했습니다.")
            self._show_install_help()

    def _show_install_help(self):
        # 상황별 안내(venv/일반)
        if in_venv():
            cmd = f"{sys.executable} -m pip install pycryptodome"
            extra = "현재 가상환경(venv)에서 실행 중이라 --user 설치가 불가합니다."
        else:
            cmd = f"{sys.executable} -m pip install --user pycryptodome"
            extra = "일반 환경에서 설치가 막힌 경우, 관리자 권한으로 실행하거나 venv를 사용하세요."
        messagebox.showerror(
            "필수 구성요소 설치 실패",
            f"{extra}\n\n아래 명령을 터미널에서 실행하세요:\n\n{cmd}\n"
        )

    def _build_ui(self):
        # 폰트/여백 중심으로 “앱” 느낌 내기
        self.configure(bg="#f6f7fb")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 10))
        style.configure("TFrame", background="#f6f7fb")
        style.configure("Card.TFrame", background="#ffffff")
        style.configure("TLabel", background="#ffffff", foreground="#111827")
        style.configure("Sub.TLabel", background="#ffffff", foreground="#6b7280")
        style.configure("TButton", padding=10)
        style.configure("Accent.TButton", padding=10)
        style.map("Accent.TButton",
                  background=[("active", "#2563eb"), ("!active", "#3b82f6")],
                  foreground=[("active", "white"), ("!active", "white")])
        style.configure("Horizontal.TProgressbar", thickness=14)

        root = ttk.Frame(self, padding=18)
        root.pack(fill="both", expand=True)

        # Header
        header = ttk.Frame(root, style="TFrame")
        header.pack(fill="x", pady=(0, 12))
        title = tk.Label(header, text="Resource Pack Encryptor", bg="#f6f7fb",
                         fg="#111827", font=("Segoe UI", 18, "bold"))
        title.pack(anchor="w")
        subtitle = tk.Label(header, text="ZIP 리소스팩을 선택하고, 출력 폴더를 정한 뒤 암호화를 실행하세요.",
                            bg="#f6f7fb", fg="#6b7280", font=("Segoe UI", 10))
        subtitle.pack(anchor="w", pady=(4, 0))

        # Cards row
        cards = ttk.Frame(root, style="TFrame")
        cards.pack(fill="x")

        left = ttk.Frame(cards, style="Card.TFrame", padding=14)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))

        right = ttk.Frame(cards, style="Card.TFrame", padding=14)
        right.pack(side="left", fill="both", expand=True)

        # Left: file pick
        tk.Label(left, text="파일 선택", bg="#ffffff", fg="#111827",
                 font=("Segoe UI", 12, "bold")).pack(anchor="w")
        tk.Label(left, text="경로를 직접 입력할 필요 없이 버튼으로 선택합니다.",
                 bg="#ffffff", fg="#6b7280").pack(anchor="w", pady=(4, 12))

        row1 = ttk.Frame(left, style="Card.TFrame")
        row1.pack(fill="x", pady=(0, 10))
        tk.Label(row1, text="입력 ZIP", bg="#ffffff", fg="#111827").pack(anchor="w")
        tk.Label(row1, textvariable=self.var_input, bg="#ffffff", fg="#6b7280").pack(anchor="w", pady=(2, 6))
        ttk.Button(row1, text="ZIP 파일 선택", command=self.pick_input_zip, style="Accent.TButton").pack(anchor="w")

        row2 = ttk.Frame(left, style="Card.TFrame")
        row2.pack(fill="x")
        tk.Label(row2, text="출력 폴더", bg="#ffffff", fg="#111827").pack(anchor="w")
        tk.Label(row2, textvariable=self.var_output, bg="#ffffff", fg="#6b7280").pack(anchor="w", pady=(2, 6))
        ttk.Button(row2, text="폴더 선택", command=self.pick_output_dir).pack(anchor="w")

        # Right: options
        tk.Label(right, text="옵션", bg="#ffffff", fg="#111827",
                 font=("Segoe UI", 12, "bold")).pack(anchor="w")
        tk.Label(right, text="아래 파일은 보통 암호화하지 않고 그대로 두는 편입니다.",
                 bg="#ffffff", fg="#6b7280").pack(anchor="w", pady=(4, 12))

        optbox = ttk.Frame(right, style="Card.TFrame")
        optbox.pack(fill="x")

        ttk.Checkbutton(optbox, text="manifest.json 제외(그대로 복사)", variable=self.var_ex_manifest).pack(anchor="w", pady=2)
        ttk.Checkbutton(optbox, text="pack_icon.png 제외(그대로 복사)", variable=self.var_ex_pack_icon).pack(anchor="w", pady=2)
        ttk.Checkbutton(optbox, text="bug_pack_icon.png 제외(그대로 복사)", variable=self.var_ex_bug_icon).pack(anchor="w", pady=2)

        # Action card
        action = ttk.Frame(root, style="Card.TFrame", padding=14)
        action.pack(fill="x", pady=12)

        topbar = ttk.Frame(action, style="Card.TFrame")
        topbar.pack(fill="x")
        tk.Label(topbar, text="실행", bg="#ffffff", fg="#111827",
                 font=("Segoe UI", 12, "bold")).pack(side="left")

        self.btn_run = ttk.Button(topbar, text="암호화 시작", command=self.start_encrypt, style="Accent.TButton")
        self.btn_run.pack(side="right")
        self.btn_cancel = ttk.Button(topbar, text="취소", command=self.cancel_encrypt, state="disabled")
        self.btn_cancel.pack(side="right", padx=(0, 10))

        self.pbar = ttk.Progressbar(action, mode="determinate")
        self.pbar.pack(fill="x", pady=(10, 6))

        status_line = ttk.Frame(action, style="Card.TFrame")
        status_line.pack(fill="x")
        tk.Label(status_line, text="상태:", bg="#ffffff", fg="#6b7280").pack(side="left")
        tk.Label(status_line, textvariable=self.var_status, bg="#ffffff", fg="#111827").pack(side="left", padx=(6, 0))
        tk.Label(status_line, textvariable=self.var_phase, bg="#ffffff", fg="#6b7280").pack(side="right")

        # Log card
        logs = ttk.Frame(root, style="Card.TFrame", padding=14)
        logs.pack(fill="both", expand=True)

        top = ttk.Frame(logs, style="Card.TFrame")
        top.pack(fill="x")
        tk.Label(top, text="작업 기록", bg="#ffffff", fg="#111827",
                 font=("Segoe UI", 12, "bold")).pack(side="left")

        ttk.Button(top, text="기록 지우기", command=self.clear_log).pack(side="right")

        self.txt = tk.Text(
            logs, height=10,
            bg="#ffffff", fg="#111827",
            insertbackground="#111827",
            relief="solid", bd=1,
            wrap="word"
        )
        self.txt.pack(fill="both", expand=True, pady=(10, 0))

    def _log(self, msg: str):
        self.q.put(("log", msg))

    def clear_log(self):
        self.txt.delete("1.0", "end")

    def _append_log(self, msg: str):
        self.txt.insert("end", msg + "\n")
        self.txt.see("end")

    def _set_progress(self, done: int, total: int, phase: str):
        self.q.put(("progress", done, total, phase))

    def _poll_queue(self):
        try:
            while True:
                kind, *payload = self.q.get_nowait()
                if kind == "log":
                    self._append_log(payload[0])
                elif kind == "progress":
                    done, total, phase = payload
                    self.pbar["maximum"] = max(total, 1)
                    self.pbar["value"] = done
                    self.var_status.set(f"{done}/{total}")
                    self.var_phase.set(phase)
                elif kind == "done":
                    ok, outdir, outzip, keyfile = payload
                    self.btn_run.config(state="normal")
                    self.btn_cancel.config(state="disabled")
                    self.var_phase.set("")
                    if ok:
                        self.var_status.set("완료")
                        messagebox.showinfo(
                            "완료",
                            "암호화가 완료되었습니다.\n\n"
                            f"출력 ZIP: {outzip}\n"
                            f"키 파일: {keyfile}\n"
                            f"출력 폴더: {outdir}"
                        )
                    else:
                        self.var_status.set("실패")
                        messagebox.showerror("실패", "암호화에 실패했습니다.\n작업 기록을 확인하세요.")
        except queue.Empty:
            pass
        self.after(80, self._poll_queue)

    def pick_input_zip(self):
        path = filedialog.askopenfilename(
            title="리소스팩 ZIP 선택",
            filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")]
        )
        if not path:
            return
        self.input_zip = Path(path)
        self.var_input.set(self.input_zip.name)
        self._log(f"입력 ZIP 선택: {self.input_zip}")

        # 출력 폴더 기본값: 입력 ZIP 폴더
        if self.output_dir is None:
            self.output_dir = self.input_zip.parent
            self.var_output.set(str(self.output_dir))
            self._log(f"출력 폴더 자동 설정: {self.output_dir}")

    def pick_output_dir(self):
        path = filedialog.askdirectory(title="출력 폴더 선택")
        if not path:
            return
        self.output_dir = Path(path)
        self.var_output.set(str(self.output_dir))
        self._log(f"출력 폴더 선택: {self.output_dir}")

    def cancel_encrypt(self):
        if self.worker and self.worker.is_alive():
            self.cancel_event.set()
            self._log("취소 요청을 보냈습니다. 잠시만 기다려주세요...")

    def start_encrypt(self):
        # 1) dependency
        if not ensure_pycryptodome(self._log):
            self._show_install_help()
            return

        # 2) validate selection
        if not self.input_zip or not self.input_zip.exists():
            messagebox.showwarning("안내", "입력 ZIP 파일을 먼저 선택하세요.")
            return
        if not self.output_dir or not self.output_dir.exists():
            messagebox.showwarning("안내", "출력 폴더를 먼저 선택하세요.")
            return

        excluded = set()
        if self.var_ex_manifest.get():
            excluded.add("manifest.json")
        if self.var_ex_pack_icon.get():
            excluded.add("pack_icon.png")
        if self.var_ex_bug_icon.get():
            excluded.add("bug_pack_icon.png")

        outzip = self.output_dir / f"{self.input_zip.stem}_encrypted.zip"
        keyfile = self.output_dir / f"{self.input_zip.stem}.zip.key"

        if outzip.exists() or keyfile.exists():
            if not messagebox.askyesno(
                "덮어쓰기 확인",
                "같은 이름의 출력 파일이 이미 존재합니다.\n덮어쓸까요?\n\n"
                f"- {outzip.name}\n"
                f"- {keyfile.name}"
            ):
                return

        opts = EncryptOptions(
            input_zip=self.input_zip,
            output_dir=self.output_dir,
            output_zip=outzip,
            key_file=keyfile,
            master_key=random_key(),
            excluded_files=excluded
        )

        self.cancel_event.clear()
        self.btn_run.config(state="disabled")
        self.btn_cancel.config(state="normal")
        self.pbar["value"] = 0
        self.var_status.set("준비 중")
        self.var_phase.set("")

        self._log("—" * 40)
        self._log("암호화를 시작합니다.")
        self._log(f"출력 파일: {outzip.name}")
        self._log(f"키 파일: {keyfile.name}")
        self._log("—" * 40)

        def worker():
            ok = False
            try:
                encrypt_pack(
                    opts,
                    log_cb=self._log,
                    progress_cb=self._set_progress,
                    cancel_flag=self.cancel_event
                )
                ok = True
            except Exception as e:
                self._log("오류가 발생했습니다:")
                self._log(str(e))
                self._log(traceback.format_exc())
            finally:
                self.q.put(("done", ok, str(self.output_dir), str(outzip), str(keyfile)))

        self.worker = threading.Thread(target=worker, daemon=True)
        self.worker.start()


def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
