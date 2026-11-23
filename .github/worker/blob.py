#!/usr/bin/env python3
"""Generic sealed-bundle tool: pack a folder, seal it with authenticated encryption, split it into parts, and the reverse.

Standard library + the `openssl` program only (present on this computer and on a stock Linux runner). One file, used
unchanged on both sides.

METHOD (the same on both sides)
  cipher   AES-256-CTR through `openssl enc` (PBKDF2-HMAC-SHA256 key schedule inside openssl, passphrase handed over a pipe,
           never on a command line)
  auth     HMAC-SHA256 over header + ciphertext (encrypt-then-MAC), checked BEFORE anything is decrypted
  keys     the one 32-byte master key (hex, env JOB_KEY or a mode-600 file) is never used directly: per file
           enc_key = HMAC(master, "enc|" + context + "|" + salt), mac_key = HMAC(master, "mac|" + context + "|" + salt);
           the context names job and direction so a part of one job or direction cannot be swapped into another
  layout   MAGIC(4) | salt(16) | openssl stream | HMAC(32); the stream is cut into parts of at most part_bytes
  content  a tar whose first member is MANIFEST.json (sha256 + size of every file); unpack refuses absolute paths, '..',
           links, devices, extra or missing files and any hash that differs

CLI (the key is read from the environment variable JOB_KEY; output is neutral: only a status word and counts)
  blob.py seal   CONTEXT FOLDER OUTPREFIX [PART_MB]     folder -> OUTPREFIX.p000, .p001 ...
  blob.py open   CONTEXT PARTSDIR PREFIX OUTFOLDER      parts -> verified folder
  blob.py group  GROUPS.json INDEX                      prints the comma-separated items of group INDEX
  blob.py pins   JOBSPEC.json VERSION URL               exits 1 unless the spec names exactly this version and URL
  blob.py --selftest
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import secrets
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

MAGIC = b"NXB1"
CHUNK = 1 << 20
MANIFEST = "MANIFEST.json"
SCAN_BYTES = 2 << 20
SECRET_NAME_RE = re.compile(r"(^|/)(\.env[^/]*|id_(rsa|dsa|ecdsa|ed25519)[^/]*|[^/]*\.(pem|key|p12|pfx|jks|keystore|kdbx)|"
                            r"[^/]*(token|secret|credential|cookie|passwd|password)[^/]*|kaggle\.json|\.netrc|\.npmrc|\.pypirc|"
                            r"\.git-credentials|hosts\.yml|[^/]*\.pat)$", re.I)
SECRET_BODY_RE = re.compile(rb"(-----BEGIN [A-Z ]*PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|"
                            rb"\bAKIA[0-9A-Z]{16}\b|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bsk-[A-Za-z0-9]{32,}|"
                            rb"(?i:(api[_-]?key|secret|password|passwd|token|cookie)\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{16,}))")


class BlobError(Exception):
    """Carries a short neutral code, never a file name or content."""


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def _keys(master: bytes, context: str, salt: bytes) -> tuple[bytes, bytes]:
    c = context.encode()
    return _hmac(master, b"enc|" + c + b"|" + salt), _hmac(master, b"mac|" + c + b"|" + salt)


def parse_key(text: str) -> bytes:
    t = (text or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", t):
        raise BlobError("key_format")
    return bytes.fromhex(t)


def key_from_env() -> bytes:
    return parse_key(os.environ.get("JOB_KEY", ""))


def key_from_file(path) -> bytes:
    p = Path(path)
    st = p.stat()
    if (st.st_mode & 0o077) != 0:
        raise BlobError("key_file_permissions")
    return parse_key(p.read_text())


def new_key_file(path) -> None:
    """Writes a new random key to a file created with mode 600 (refuses to overwrite). Prints nothing."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(p.parent, 0o700)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secrets.token_bytes(32).hex() + "\n")


# ------------------------------------------------------------------------------------------------ pack / unpack
def scan_for_secrets(root: Path, files: list[Path]) -> list[str]:
    """-> list of neutral findings (kind + count only is enough for the caller; the relative path is returned for the LOCAL
    caller to show on this computer). A secret-looking name or body refuses the whole bundle."""
    bad = []
    for f in files:
        rel = f.relative_to(root).as_posix()
        if SECRET_NAME_RE.search(rel):
            bad.append(f"secret_like_name:{rel}")
            continue
        try:
            with f.open("rb") as fh:
                head = fh.read(SCAN_BYTES)
        except OSError:
            continue
        if SECRET_BODY_RE.search(head):
            bad.append(f"secret_like_content:{rel}")
    return bad


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(CHUNK), b""):
            h.update(b)
    return h.hexdigest()


def list_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink())


def pack(root: Path, tar_path: Path, scan: bool = True, extra: dict | None = None) -> dict:
    """Folder -> tar with MANIFEST.json first. Returns the manifest. Refuses symlinks and (scan) secret-looking files."""
    root = Path(root)
    for p in root.rglob("*"):
        if p.is_symlink():
            raise BlobError("symlink_in_folder")
    files = list_files(root)
    if scan:
        bad = scan_for_secrets(root, files)
        if bad:
            raise BlobError("secret_like_file:" + ";".join(bad)[:400])
    man = {"schema": "BUNDLE_MANIFEST.v1", "files": {f.relative_to(root).as_posix(): {"sha256": _sha(f), "size": f.stat().st_size}
                                                    for f in files}}
    if extra:
        man["extra"] = extra
    data = json.dumps(man, indent=1, sort_keys=True).encode()
    with tarfile.open(tar_path, "w") as tf:
        ti = tarfile.TarInfo(MANIFEST)
        ti.size, ti.mtime, ti.mode = len(data), 0, 0o600
        tf.addfile(ti, io.BytesIO(data))
        for f in files:
            tf.add(f, arcname=f.relative_to(root).as_posix(), recursive=False)
    with tarfile.open(tar_path, "r") as tf:           # every member exactly once (a repeated member makes a host refuse the bundle)
        names = tf.getnames()
    if len(names) != len(set(names)):
        raise BlobError("duplicate_members")
    return man


def unpack(tar_path: Path, dest: Path) -> dict:
    """Verified extraction. Raises BlobError(code) on anything unexpected. Returns the manifest."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with tarfile.open(tar_path, "r") as tf:
        members = tf.getmembers()
        if not members or members[0].name != MANIFEST:
            raise BlobError("manifest_missing")
        man = json.loads(tf.extractfile(members[0]).read())
        want = man.get("files", {})
        seen = set()
        for m in members[1:]:
            n = m.name
            if not m.isreg() or n.startswith("/") or ".." in Path(n).parts or n not in want or n in seen:
                raise BlobError("unexpected_member")
            seen.add(n)
            target = (root / n).resolve()
            if root not in target.parents:
                raise BlobError("path_escape")
            target.parent.mkdir(parents=True, exist_ok=True)
            with tf.extractfile(m) as src, open(target, "wb") as out:
                h = hashlib.sha256()
                for b in iter(lambda: src.read(CHUNK), b""):
                    h.update(b)
                    out.write(b)
            if h.hexdigest() != want[n]["sha256"] or target.stat().st_size != want[n]["size"]:
                raise BlobError("hash_mismatch")
        if seen != set(want):
            raise BlobError("file_missing")
    return man


# ------------------------------------------------------------------------------------------------ seal / open
def _openssl(mode: str, passphrase: str, stdin, stdout) -> subprocess.Popen:
    r, w = os.pipe()
    os.write(w, passphrase.encode())
    os.close(w)
    cmd = ["openssl", "enc", "-aes-256-ctr", "-pbkdf2", "-iter", "1000", "-md", "sha256", "-pass", f"fd:{r}"]
    if mode == "dec":
        cmd.append("-d")
    try:
        return subprocess.Popen(cmd, stdin=stdin, stdout=stdout, stderr=subprocess.DEVNULL, pass_fds=(r,))
    finally:
        os.close(r)


def seal_file(master: bytes, context: str, src: Path, out_prefix: Path, part_bytes: int = 512 << 20) -> list[Path]:
    """Encrypts `src` and writes out_prefix.p000, .p001 ... Returns the part paths."""
    salt = secrets.token_bytes(16)
    ek, mk = _keys(master, context, salt)
    mac = hmac.new(mk, digestmod=hashlib.sha256)
    parts: list[Path] = []
    cur = {"f": None, "n": 0}

    def emit(b: bytes) -> None:
        while b:
            if cur["f"] is None or cur["n"] >= part_bytes:
                if cur["f"]:
                    cur["f"].close()
                p = Path(f"{out_prefix}.p{len(parts):03d}")
                parts.append(p)
                cur["f"], cur["n"] = open(p, "wb"), 0
            take = b[: part_bytes - cur["n"]]
            cur["f"].write(take)
            cur["n"] += len(take)
            b = b[len(take):]

    head = MAGIC + salt
    mac.update(head)
    emit(head)
    with open(src, "rb") as fin:
        pr = _openssl("enc", ek.hex(), fin, subprocess.PIPE)
        for b in iter(lambda: pr.stdout.read(CHUNK), b""):
            mac.update(b)
            emit(b)
        if pr.wait() != 0:
            raise BlobError("encrypt_failed")
    emit(mac.digest())
    cur["f"].close()
    return parts


def _stream(parts: list[Path]):
    for p in parts:
        with open(p, "rb") as f:
            for b in iter(lambda: f.read(CHUNK), b""):
                yield b


def open_file(master: bytes, context: str, parts: list[Path], dest: Path) -> None:
    """Verifies the HMAC over all parts first, then decrypts to `dest`. Wrong key / changed byte / missing part -> BlobError."""
    parts = sorted(parts)
    total = sum(p.stat().st_size for p in parts)
    if total < len(MAGIC) + 16 + 32:
        raise BlobError("too_short")
    with open(parts[0], "rb") as f:
        head = f.read(20)
    if head[:4] != MAGIC:
        raise BlobError("bad_magic")
    salt = head[4:20]
    ek, mk = _keys(master, context, salt)
    body = total - 32
    mac = hmac.new(mk, digestmod=hashlib.sha256)
    seen, tail = 0, b""
    for b in _stream(parts):
        tail += b
        if len(tail) > 32:
            cut = tail[:-32]
            tail = tail[-32:]
            mac.update(cut)
            seen += len(cut)
    if seen != body or not hmac.compare_digest(mac.digest(), tail):
        raise BlobError("authentication_failed")
    with open(dest, "wb") as fout:
        pr = _openssl("dec", ek.hex(), subprocess.PIPE, fout)
        skip, sent = 20, 0
        try:
            for b in _stream(parts):
                if skip:
                    d = min(skip, len(b))
                    b, skip = b[d:], skip - d
                room = body - 20 - sent
                b = b[:room]
                if b:
                    pr.stdin.write(b)
                    sent += len(b)
            pr.stdin.close()
        except BrokenPipeError:
            raise BlobError("decrypt_failed")
        if pr.wait() != 0:
            raise BlobError("decrypt_failed")


def seal_folder(master: bytes, context: str, folder: Path, out_prefix: Path, part_bytes: int = 512 << 20,
                scan: bool = True, extra: dict | None = None) -> dict:
    with tempfile.TemporaryDirectory() as td:
        tar = Path(td) / "b.tar"
        man = pack(folder, tar, scan=scan, extra=extra)
        parts = seal_file(master, context, tar, out_prefix, part_bytes)
        tar.unlink()
    return {"manifest": man, "parts": [p.name for p in parts], "part_sha256": {p.name: _sha(p) for p in parts}}


def open_folder(master: bytes, context: str, parts: list[Path], dest: Path) -> dict:
    with tempfile.TemporaryDirectory() as td:
        tar = Path(td) / "b.tar"
        open_file(master, context, parts, tar)
        return unpack(tar, dest)


# ------------------------------------------------------------------------------------------------ CLI
def main(argv: list[str]) -> int:
    if argv[:1] == ["--selftest"]:
        return selftest()
    try:
        cmd = argv[0]
        if cmd == "seal":
            ctx, folder, prefix = argv[1], Path(argv[2]), Path(argv[3])
            mb = int(argv[4]) if len(argv) > 4 else 512
            r = seal_folder(key_from_env(), ctx, folder, prefix, mb << 20, scan=False)
            print(f"sealed parts {len(r['parts'])} files {len(r['manifest']['files'])}")
            return 0
        if cmd == "open":
            ctx, pdir, prefix, dest = argv[1], Path(argv[2]), argv[3], Path(argv[4])
            parts = sorted(pdir.glob(prefix + ".p[0-9][0-9][0-9]"))
            if not parts:
                raise BlobError("no_parts")
            m = open_folder(key_from_env(), ctx, parts, dest)
            print(f"opened files {len(m['files'])}")
            return 0
        if cmd == "group":
            groups = json.loads(Path(argv[1]).read_text())
            print(",".join(groups[int(argv[2])]))
            return 0
        if cmd == "pins":
            spec = json.loads(Path(argv[1]).read_text())
            if spec.get("blender_version") != argv[2] or spec.get("blender_url") != argv[3]:
                raise BlobError("pin_mismatch")
            print("pins ok")
            return 0
        print("usage")
        return 2
    except BlobError as e:
        print("failed", str(e).split(":")[0])
        return 1
    except Exception:  # noqa: BLE001  (no traceback: it could carry names)
        print("failed unexpected")
        return 1


def selftest() -> int:
    fails: list[str] = []

    def ok(c, n):
        if not c:
            fails.append(n)

    master = secrets.token_bytes(32)
    other = secrets.token_bytes(32)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        src = td / "src"
        (src / "a" / "b").mkdir(parents=True)
        (src / "a" / "one.txt").write_bytes(b"hello one")
        (src / "a" / "b" / "two.bin").write_bytes(os.urandom(300_000))
        (src / "three.json").write_text('{"k": 1}')
        # round trip, several parts
        info = seal_folder(master, "job1|in", src, td / "enc", part_bytes=100_000)
        parts = sorted(td.glob("enc.p*"))
        ok(len(parts) >= 4 and all(p.stat().st_size <= 100_000 for p in parts), f"split_into_parts_{len(parts)}")
        dst = td / "dst"
        man = open_folder(master, "job1|in", parts, dst)
        ok((dst / "a" / "one.txt").read_bytes() == b"hello one" and (dst / "a" / "b" / "two.bin").stat().st_size == 300_000
           and len(man["files"]) == 3, "round_trip")
        ok(b"hello one" not in b"".join(p.read_bytes() for p in parts), "ciphertext_does_not_contain_plaintext")
        # wrong key
        try:
            open_folder(other, "job1|in", parts, td / "x1")
            ok(False, "wrong_key_must_fail")
        except BlobError as e:
            ok(str(e) == "authentication_failed", "wrong_key_fails")
        # wrong context (a part of another job / direction)
        try:
            open_folder(master, "job2|in", parts, td / "x2")
            ok(False, "wrong_context_must_fail")
        except BlobError:
            pass
        # tamper: flip one byte in the middle part, then in the first part's salt, then drop a part
        mid = parts[len(parts) // 2]
        raw = bytearray(mid.read_bytes())
        raw[len(raw) // 2] ^= 1
        mid.write_bytes(bytes(raw))
        try:
            open_folder(master, "job1|in", parts, td / "x3")
            ok(False, "tamper_must_fail")
        except BlobError as e:
            ok(str(e) == "authentication_failed", "tamper_fails")
        raw[len(raw) // 2] ^= 1
        mid.write_bytes(bytes(raw))
        try:
            open_folder(master, "job1|in", parts[:-1], td / "x4")
            ok(False, "missing_part_must_fail")
        except BlobError:
            pass
        ok(open_folder(master, "job1|in", parts, td / "x5")["files"] is not None, "restored_round_trip")
        # secret-looking files refused
        for name, body in ((".env", b"A=1"), ("keys/id_rsa", b"x"), ("cookies.txt", b"x"), ("n/token.json", b"{}"),
                           ("notes.txt", b"password = abcdefghijklmnopqrstuv"), ("n.txt", b"ghp_" + b"a" * 36),
                           ("p.txt", b"-----BEGIN RSA PRIVATE KEY-----")):
            s2 = td / "s2"
            if s2.exists():
                import shutil
                shutil.rmtree(s2)
            (s2 / "keys").mkdir(parents=True)
            (s2 / "n").mkdir()
            (s2 / "fine.txt").write_text("fine")
            (s2 / name).write_bytes(body)
            try:
                pack(s2, td / "s2.tar")
                ok(False, f"secret_must_be_refused_{name}")
            except BlobError as e:
                ok("secret_like" in str(e), f"secret_refused_{name}")
        # unsafe tar members refused on unpack
        bad = td / "bad.tar"
        with tarfile.open(bad, "w") as tf:
            m = json.dumps({"files": {"../x": {"sha256": "0", "size": 1}}}).encode()
            ti = tarfile.TarInfo(MANIFEST)
            ti.size = len(m)
            tf.addfile(ti, io.BytesIO(m))
            ti2 = tarfile.TarInfo("../x")
            ti2.size = 1
            tf.addfile(ti2, io.BytesIO(b"x"))
        try:
            unpack(bad, td / "bd")
            ok(False, "path_escape_must_fail")
        except BlobError:
            pass
        # a tar that repeats a member is refused on unpack (must-fail) and a duplicate-free pack passes the pack-side check
        dupt = td / "dup.tar"
        with tarfile.open(dupt, "w") as tf:
            m = json.dumps({"files": {"a.txt": {"sha256": "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881", "size": 1}}}).encode()
            ti = tarfile.TarInfo(MANIFEST)
            ti.size = len(m)
            tf.addfile(ti, io.BytesIO(m))
            for _ in range(2):
                ti2 = tarfile.TarInfo("a.txt")
                ti2.size = 1
                tf.addfile(ti2, io.BytesIO(b"x"))
        try:
            unpack(dupt, td / "dd")
            ok(False, "duplicate_member_must_fail")
        except BlobError as e:
            ok(str(e) == "unexpected_member", "duplicate_member_refused")
        # a file changed after packing (hash vs manifest)
        t2 = td / "t2.tar"
        pack(src, t2)
        data = bytearray(t2.read_bytes())
        i = data.find(b"hello one")
        data[i] ^= 1
        t2.write_bytes(bytes(data))
        try:
            unpack(t2, td / "t2d")
            ok(False, "hash_mismatch_must_fail")
        except BlobError as e:
            ok(str(e) == "hash_mismatch", "manifest_hash_mismatch_fails")
        # key file: mode 600 only
        kf = td / "k" / "job.key"
        new_key_file(kf)
        ok(oct(kf.stat().st_mode & 0o777) == "0o600" and len(key_from_file(kf)) == 32, "key_file_600")
        os.chmod(kf, 0o644)
        try:
            key_from_file(kf)
            ok(False, "loose_key_file_must_fail")
        except BlobError:
            pass
        try:
            new_key_file(kf)
            ok(False, "key_never_overwritten")
        except FileExistsError:
            pass
    print(json.dumps({"status": "PASS" if not fails else "FAIL", "tool": "github_host/blob", "failed": fails}))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
