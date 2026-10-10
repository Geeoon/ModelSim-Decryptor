#!/usr/bin/env python3
"""
ModelSim IEEE 1735 (.svp) decryptor  --  CVE-2021-42023.

Decrypts IEEE 1735-2014 protected HDL produced by Siemens/Mentor ModelSim,
using the standard `cryptography` library and an RSA private key loaded from a
PEM file.

The bundled key (keys/mgc_verif_sim_rsa_1.pem) is ModelSim's built-in
"MGC-VERIF-SIM-RSA-1" key pair, recovered from the lightly mangled components
that ModelSim ships in its `vlog`/`vcom` binaries (see "How the key was
obtained" below).  Point --key at any other recovered ModelSim key to use it.

Envelope layout (IEEE 1735-2014, version 1)
-------------------------------------------
    key_block  : RSA(PKCS#1 v1.5) encryption of a 128-bit AES session key
    data_block : IV(16 bytes) || AES-128-CBC( source, key=session key, iv=IV )

How the key was obtained
------------------------
ModelSim hard-codes the IEEE 1735 RSA private keys inside the tool.  Each key
component is exposed by a `get_<name>_key_<part>` accessor (e.g.
`get_sim_1_key_mod`) and only lightly obscured with the byte transform::

    demangle(b) = rol8(b ^ 0x77, 7)

De-mangling the components and validating `n == p*q` and
`d*e == 1 (mod (p-1)(q-1))` recovers the plaintext key.  The PEM in `keys/` was
produced from those recovered components.

Requirements
------------
    pip install cryptography

Usage
-----
    python3 ms_decrypt.py file.svp
    python3 ms_decrypt.py --key keys/mgc_verif_sim_rsa_1.pem --outdir out rtl/*.svp
    python3 ms_decrypt.py --stdout file.svp
"""

from __future__ import annotations

import argparse
import base64
import glob
import os
import re
import sys

try:
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover - guidance for a missing dependency
    sys.exit(
        "This script requires the 'cryptography' package.\n"
        "Install it with:  pip install cryptography"
    )


DEFAULT_KEY_NAME = "mgc_verif_sim_rsa_1.pem"
_HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Envelope parsing
# ---------------------------------------------------------------------------

_PRAGMA_RE = re.compile(r"^\s*`pragma\s+protect\s+(.*)$", re.IGNORECASE)


class Envelope:
    """The pieces of an IEEE 1735 digital envelope we care about."""

    key_keyname: str | None = None
    data_method: str | None = None
    key_block: bytes = b""
    data_block: bytes = b""


def _collect(lines, start):
    """Return the base64 payload starting at `start` up to the next pragma."""
    out = []
    i = start
    while i < len(lines) and not _PRAGMA_RE.match(lines[i]):
        out.append(lines[i])
        i += 1
    return re.sub(r"\s+", "", "".join(out)), i


def parse_svp(text: str) -> Envelope:
    """Parse the first protected region of an IEEE 1735 file."""
    env = Envelope()
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = _PRAGMA_RE.match(lines[i])
        if not m:
            i += 1
            continue
        directive = m.group(1).strip()
        low = directive.lower()
        i += 1

        if low.startswith("key_keyname"):
            km = re.search(r'key_keyname\s*=\s*"([^"]+)"', directive)
            if km:
                env.key_keyname = km.group(1)
        elif low.startswith("data_method"):
            dm = re.search(r'data_method\s*=\s*"([^"]+)"', directive)
            if dm:
                env.data_method = dm.group(1)
        elif low.endswith("key_block"):
            payload, i = _collect(lines, i)
            env.key_block = base64.b64decode(payload)
        elif low.endswith("data_block"):
            payload, i = _collect(lines, i)
            env.data_block = base64.b64decode(payload)

        if env.key_block and env.data_block:
            break

    if not env.key_block or not env.data_block:
        raise ValueError("could not find both key_block and data_block")
    return env


# ---------------------------------------------------------------------------
# Key loading and decryption
# ---------------------------------------------------------------------------

def default_key_path() -> str:
    return os.path.normpath(os.path.join(_HERE, "..", "keys", DEFAULT_KEY_NAME))


def load_private_key(path: str):
    """Load an RSA private key from a PEM (PKCS#1 or PKCS#8) file."""
    with open(path, "rb") as fh:
        data = fh.read()
    return serialization.load_pem_private_key(data, password=None)


def decrypt_envelope(text: str, private_key) -> str:
    """Decrypt one IEEE 1735 protected file and return the plaintext source."""
    env = parse_svp(text)

    if env.data_method and env.data_method.lower() != "aes128-cbc":
        raise ValueError(f"unsupported data_method {env.data_method!r}")

    # 1. RSA / PKCS#1 v1.5 -> 128-bit AES session key
    session_key = private_key.decrypt(env.key_block, asym_padding.PKCS1v15())
    if len(session_key) not in (16, 24, 32):
        raise ValueError(f"unexpected session key length {len(session_key)}")

    # 2. AES-CBC; ModelSim prepends the IV to the ciphertext
    iv, ciphertext = env.data_block[:16], env.data_block[16:]
    if len(ciphertext) % 16:
        raise ValueError("data block is not a multiple of the AES block size")

    decryptor = Cipher(algorithms.AES(session_key), modes.CBC(iv)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # 3. strip PKCS#7 padding
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext) + unpadder.finalize()

    return plaintext.decode("latin1")


def decrypt_file(path: str, private_key) -> str:
    with open(path, "r", encoding="latin1") as fh:
        return decrypt_envelope(fh.read(), private_key)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Decrypt ModelSim IEEE 1735 (.svp) files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("files", nargs="+", help="protected .svp file(s), globs allowed")
    ap.add_argument("--key", default=default_key_path(),
                    help=f"RSA private key PEM (default: {DEFAULT_KEY_NAME})")
    ap.add_argument("--outdir", help="directory for decrypted output")
    ap.add_argument("--suffix", default=".decrypted", help="output suffix / extension")
    ap.add_argument("--stdout", action="store_true", help="print plaintext to stdout")
    args = ap.parse_args(argv)

    try:
        private_key = load_private_key(args.key)
    except FileNotFoundError:
        print(f"[!] key file not found: {args.key}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"[!] could not load key {args.key}: {exc}", file=sys.stderr)
        return 2

    paths: list[str] = []
    for pattern in args.files:
        hits = glob.glob(pattern)
        paths.extend(hits if hits else [pattern])

    rc = 0
    for path in paths:
        try:
            plain = decrypt_file(path, private_key)
        except Exception as exc:  # noqa: BLE001 - report and keep going
            print(f"[!] {path}: {exc}", file=sys.stderr)
            rc = 1
            continue

        if args.stdout:
            sys.stdout.write(plain)
            if not plain.endswith("\n"):
                sys.stdout.write("\n")
            continue

        if args.outdir:
            os.makedirs(args.outdir, exist_ok=True)
            dest = os.path.join(args.outdir, os.path.basename(path) + args.suffix)
        else:
            dest = path + args.suffix
        with open(dest, "w", encoding="latin1", newline="") as fh:
            fh.write(plain)
        print(f"[+] {path} -> {dest}", file=sys.stderr)

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
