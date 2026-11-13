#!/usr/bin/env python3
"""curvefish_unpacker.py — decrypt the stage-3 payload of an IBar2Double host sample.

The host embeds a Base91 string, a password and `LfdReader.dll`. This tool
reimplements `IBar2Double.ADXPlot.Benchmark()` offline to decrypt that string.
It never runs the decrypted buffer.

Algorithm:
  1. Pull the Base91 ciphertext, the password and `LfdReader.dll` out of the host.
  2. `crypto_obfuscator` reads `LfdReader.dll` and returns `ThreefishParams`:
     PBKDF2 iterations, salt/IV offsets, payload offset and length.
  3. Base91-decode the ciphertext into `raw`. Cut `salt`, `iv` and `payload` from it.
  4. Derive the key: PBKDF2-HMAC-SHA1(password, salt) -> SHA-256 -> `Donna32.Harden`
     (a custom Curve25519 field-arithmetic step, not the RFC 7748 clamp) ->
     `pub` = X25519(priv, 9) -> `shared` = X25519(priv, pub) -> SHA-256 = Threefish key.
  5. Decrypt `payload` with Threefish-256-CBC and remove the PKCS7 padding.

README.md has the byte layouts and the reasoning behind each step.

Usage:
  python curvefish_unpacker.py <host_file> [-o stage3.exe] [--password PW] [--save-config run.json] [-v]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

# Make the co-located `crypto_obfuscator.py` importable whether this file runs as a
# script or is imported as a deployed submodule (sys.path then holds the caller's
# directory, not this file's).
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import dnfile  # type: ignore
    _DNFILE_AVAILABLE = True
except ImportError:
    _DNFILE_AVAILABLE = False

from crypto_obfuscator import (
    TF_C240,
    ThreefishParams,
    extract_constant_table_from_lfdreader,
    constants_to_params,
    find_manifest_resource,
)

PROCESSING_NAME = "curvefish_unpacker"
VERSION = 1

logger = logging.getLogger(PROCESSING_NAME)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Fallback password for hosts with no "Benchmark" anchor.
HARDCODED_PASSWORD: str = "QPXqI*MRQO7%#XNH5MCE*#bC"
TF_BLOCK_SIZE: int = 32
TF_ROT: List[List[int]] = [
    [14, 16], [52, 57], [23, 40], [ 5, 37],
    [25, 33], [46, 12], [58, 22], [32, 32],
]
TF_ROUNDS: int = 72

# Curve25519 field prime and Montgomery A24 constant, shared by `donna32_harden`
# and `x25519_scalarmult`.
_CURVE25519_P: int = (1 << 255) - 19
_CURVE25519_A24: int = 121665


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DecryptionResult:
    plaintext: bytes
    sha256: str
    md5: str
    size: int
    looks_like_pe: bool


# ---------------------------------------------------------------------------
# Base91 decoder
# ---------------------------------------------------------------------------

# Alphabet of `LfdReader.dll`'s DecTab (read from its FieldRva): 91 characters, no
# hyphen. Used to decode the ciphertext and to recognise it among the #US strings.
_BASE91_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
)
assert len(_BASE91_ALPHABET) == 91, "Base91 alphabet must be exactly 91 characters"
_BASE91_DECODE_TABLE: dict = {ord(c): i for i, c in enumerate(_BASE91_ALPHABET)}


def base91_decode(encoded: str) -> bytes:
    out = bytearray()
    v, b, n = -1, 0, 0
    for ch in encoded:
        c = _BASE91_DECODE_TABLE.get(ord(ch), -1)
        if c == -1:
            continue
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            v = -1
            while True:
                out.append(b & 255)
                b >>= 8
                n -= 8
                if n <= 7:
                    break
    if v > -1:
        out.append((b | v << n) & 255)
    return bytes(out)


# ---------------------------------------------------------------------------
# Threefish-256 block cipher
# ---------------------------------------------------------------------------

def _ror64(v: int, rot: int) -> int:
    rot &= 63
    return ((v >> rot) | (v << (64 - rot))) & 0xFFFFFFFFFFFFFFFF


def _imix(x0: int, x1: int, rot: int) -> Tuple[int, int]:
    x1 = _ror64(x1 ^ x0, rot)
    x0 = (x0 - x1) & 0xFFFFFFFFFFFFFFFF
    return x0, x1


def _build_key_schedule(tf_key: bytes) -> List[List[int]]:
    assert len(tf_key) == 32
    k = [struct.unpack_from("<Q", tf_key, i * 8)[0] for i in range(4)]
    k.append(TF_C240 ^ k[0] ^ k[1] ^ k[2] ^ k[3])
    schedule: List[List[int]] = []
    for s in range(TF_ROUNDS // 4 + 1):
        schedule.append([
            k[s % 5],
            k[(s + 1) % 5],
            k[(s + 2) % 5],
            (k[(s + 3) % 5] + s) & 0xFFFFFFFFFFFFFFFF,
        ])
    return schedule


def threefish256_decrypt_block(tf_key: bytes, ct_block: bytes) -> bytes:
    assert len(ct_block) == TF_BLOCK_SIZE
    schedule = _build_key_schedule(tf_key)
    v = list(struct.unpack_from("<4Q", ct_block))
    sk = schedule[TF_ROUNDS // 4]
    for j in range(4):
        v[j] = (v[j] - sk[j]) & 0xFFFFFFFFFFFFFFFF
    for r in range(TF_ROUNDS - 1, -1, -1):
        v[1], v[3] = v[3], v[1]
        rot_row = TF_ROT[r % 8]
        v[0], v[1] = _imix(v[0], v[1], rot_row[0])
        v[2], v[3] = _imix(v[2], v[3], rot_row[1])
        if r % 4 == 0:
            sk = schedule[r // 4]
            for j in range(4):
                v[j] = (v[j] - sk[j]) & 0xFFFFFFFFFFFFFFFF
    return struct.pack("<4Q", *v)


def threefish256_cbc_decrypt(tf_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(iv) != TF_BLOCK_SIZE:
        raise ValueError(f"IV is {len(iv)} bytes, expected {TF_BLOCK_SIZE}")
    if len(ciphertext) % TF_BLOCK_SIZE != 0:
        raise ValueError(f"Ciphertext length {len(ciphertext)} not block-aligned")
    plaintext = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), TF_BLOCK_SIZE):
        ct_block = ciphertext[i:i + TF_BLOCK_SIZE]
        pt_block = threefish256_decrypt_block(tf_key, ct_block)
        plaintext.extend(a ^ b for a, b in zip(pt_block, prev))
        prev = ct_block
    return bytes(plaintext)


# ---------------------------------------------------------------------------
# PKCS7 unpadding
# ---------------------------------------------------------------------------

def pkcs7_unpad(data: bytes, block_size: int = TF_BLOCK_SIZE) -> bytes:
    if not data:
        raise ValueError("Cannot unpad empty buffer")
    pad_byte = data[-1]
    if pad_byte == 0 or pad_byte > block_size:
        raise ValueError(f"Invalid PKCS7 pad byte 0x{pad_byte:02X}")
    if any(b != pad_byte for b in data[-pad_byte:]):
        raise ValueError("Inconsistent PKCS7 padding bytes")
    return data[:-pad_byte]


# ---------------------------------------------------------------------------
# Curve25519 (X25519) primitives -- IBar2Double.Donna32 / IBar2Double.X25519
# ---------------------------------------------------------------------------

def _cswap(swap: int, x: int, y: int) -> Tuple[int, int]:
    return (y, x) if swap else (x, y)


def _rfc7748_clamp(scalar_int: int) -> int:
    """RFC 7748 scalar clamp. `Donna32.curve25519_mult` applies it itself, after `Harden`."""
    b = bytearray((scalar_int % (1 << 256)).to_bytes(32, "little"))
    b[0] &= 0xF8
    b[31] &= 0x7F
    b[31] |= 0x40
    return int.from_bytes(bytes(b), "little")


def x25519_scalarmult(scalar_int: int, u_int: int) -> int:
    """RFC 7748 Montgomery-ladder scalar multiplication on Curve25519.

    Matches ``Donna32.curve25519_mult``. The caller passes the raw scalar. The clamp
    is applied here. The base-point form is `u_int=9`.
    """
    k = _rfc7748_clamp(scalar_int)
    p = _CURVE25519_P
    x1 = u_int % p
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = k_t
        A = (x2 + z2) % p
        AA = (A * A) % p
        B = (x2 - z2) % p
        BB = (B * B) % p
        E = (AA - BB) % p
        C = (x3 + z3) % p
        D = (x3 - z3) % p
        DA = (D * A) % p
        CB = (C * B) % p
        x3 = pow((DA + CB) % p, 2, p)
        z3 = (x1 * pow((DA - CB) % p, 2, p)) % p
        x2 = (AA * BB) % p
        z2 = (E * (AA + _CURVE25519_A24 * E)) % p
    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    return (x2 * pow(z2, p - 2, p)) % p


def _fe_to_bytes(x: int) -> bytes:
    """Curve25519 field-element contract: canonical mod-p, 32 bytes little-endian."""
    return (x % _CURVE25519_P).to_bytes(32, "little")


def donna32_harden(key32: bytes) -> bytes:
    """Reimplementation of ``IBar2Double.Donna32.Harden``. It is not an RFC 7748 clamp.

    Field arithmetic mod p = 2**255 - 19, in the order of the IL:

        a = key32 as little-endian integer mod p
        b = a + a
        c = b - a            # = a
        d = b - c            # = a
        f = -a
        g = d - f            # = 2a
        t = g ** (2**252 - 3) mod p
        i = t * a
        j = i * i
        k = i + j
        return k as 32 bytes, little-endian

    The IL also computes `c + a`. Nothing uses it. The steps are kept as the IL has
    them, so they can be compared one by one.
    """
    p = _CURVE25519_P
    a = int.from_bytes(key32, "little") % p
    b = (a + a) % p
    c = (b - a) % p
    d = (b - c) % p
    f = (-a) % p
    g = (d - f) % p
    t = pow(g, (1 << 252) - 3, p)
    i = (t * a) % p
    j = (i * i) % p
    k = (i + j) % p
    return _fe_to_bytes(k)


def build_threefish_key(password: str, salt: bytes, iterations: int, dklen: int) -> bytes:
    """Derive the Threefish-256 key.

    PBKDF2-HMAC-SHA1 -> SHA-256 -> `donna32_harden` -> `pub` = X25519(priv, 9) ->
    `shared` = X25519(priv, pub) -> SHA-256. Stopping after the first SHA-256 gives a
    plausible 32-byte value that decrypts to garbage without any error.
    """
    raw_key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), salt, iterations, dklen)
    logger.debug("PBKDF2 raw_key: %s", raw_key.hex())
    hashed = hashlib.sha256(raw_key).digest()
    logger.debug("SHA-256(PBKDF2): %s", hashed.hex())
    priv_raw = donna32_harden(hashed)
    logger.debug("Donna32.Harden output: %s", priv_raw.hex())
    priv_int = int.from_bytes(priv_raw, "little")
    pub = x25519_scalarmult(priv_int, 9)          # ScalarBaseMult: basepoint u=9
    shared = x25519_scalarmult(priv_int, pub)     # DH self-agreement
    tf_key = hashlib.sha256(_fe_to_bytes(shared)).digest()
    logger.debug("Final Threefish key: %s", tf_key.hex())
    return tf_key


# ---------------------------------------------------------------------------
# Cipherdata header parsing
# ---------------------------------------------------------------------------

def parse_cipherdata_header(raw: bytes, params: ThreefishParams) -> Tuple[bytes, bytes, bytes]:
    p = params
    salt_end = p.salt_offset + p.salt_len
    iv_end = p.iv_offset + p.iv_len
    # ADXPlot.Benchmark: payload length = len(raw) - C(32) - C(36). The payload starts
    # at payload_offset and has exactly that length.
    payload_len = len(raw) - p.payload_len_sub
    payload_end = p.payload_offset + payload_len
    if salt_end > len(raw):
        raise ValueError(f"Salt [{p.salt_offset}:{salt_end}] out of bounds ({len(raw)} bytes)")
    if iv_end > len(raw):
        raise ValueError(f"IV [{p.iv_offset}:{iv_end}] out of bounds ({len(raw)} bytes)")
    if payload_len <= 0 or payload_end > len(raw):
        raise ValueError(
            f"Payload [{p.payload_offset}:{payload_end}] out of bounds or empty "
            f"({len(raw)} bytes total)"
        )
    salt = raw[p.salt_offset:salt_end]
    iv = raw[p.iv_offset:iv_end]
    payload = raw[p.payload_offset:payload_end]
    logger.info("Header: salt=%d B [%d:%d], IV=%d B [%d:%d], payload=%d B [%d:%d]",
                len(salt), p.salt_offset, salt_end,
                len(iv), p.iv_offset, iv_end,
                len(payload), p.payload_offset, payload_end)
    logger.debug("Salt: %s", salt.hex())
    logger.debug("IV:   %s", iv.hex())
    if len(payload) % TF_BLOCK_SIZE != 0:
        raise ValueError(
            f"Payload length {len(payload)} is not a multiple of the Threefish block "
            f"size ({TF_BLOCK_SIZE}). The Base91 decode most likely returned the wrong "
            f"byte count (wrong alphabet?)."
        )
    return salt, iv, payload


# ---------------------------------------------------------------------------
# Full decryption pipeline
# ---------------------------------------------------------------------------

def decrypt_from_binary(raw: bytes, password: str, params: ThreefishParams) -> DecryptionResult:
    salt, iv, payload_ct = parse_cipherdata_header(raw, params)
    logger.info("Key derivation: PBKDF2-SHA1(iters=%d, dklen=%d) -> SHA-256 -> "
                "Donna32.Harden -> X25519 scalar-base-mult -> X25519 DH -> SHA-256",
                params.pbkdf2_iters, params.pbkdf2_dklen)
    tf_key = build_threefish_key(password, salt, params.pbkdf2_iters, params.pbkdf2_dklen)
    logger.info("Threefish-256-CBC decrypting %d bytes...", len(payload_ct))
    decrypted = threefish256_cbc_decrypt(tf_key, iv, payload_ct)
    logger.info("Decrypted: %d bytes (pre-unpad)", len(decrypted))
    try:
        plaintext = pkcs7_unpad(decrypted)
        logger.info("PKCS7 unpadded: %d -> %d bytes", len(decrypted), len(plaintext))
    except ValueError as exc:
        logger.warning("PKCS7 unpad failed (%s) -- using raw buffer", exc)
        plaintext = decrypted
    looks_like_pe = plaintext[:2] == b"MZ"
    if looks_like_pe:
        logger.info("Output starts with 'MZ' -- PE recovered")
    else:
        logger.warning("Output does NOT start with 'MZ' (bytes 0-7: %s)", plaintext[:8].hex())
    sha256 = hashlib.sha256(plaintext).hexdigest()
    md5 = hashlib.md5(plaintext).hexdigest()
    return DecryptionResult(plaintext=plaintext, sha256=sha256, md5=md5,
                            size=len(plaintext), looks_like_pe=looks_like_pe)


def benchmark(ciphertext_b91: str, password: str, params: ThreefishParams) -> DecryptionResult:
    logger.info("Base91-decoding ciphertext (%d chars)...", len(ciphertext_b91))
    raw = base91_decode(ciphertext_b91)
    logger.info("Base91 decoded: %d bytes", len(raw))
    return decrypt_from_binary(raw, password, params)


# ---------------------------------------------------------------------------
# Extraction: pull LfdReader.dll + ciphertext + password off a host file
# ---------------------------------------------------------------------------

def extract_lfdreader_dll(pe: "dnfile.dnPE") -> bytes:
    """Return the `LfdReader.dll` manifest resource of the host. The bytes are still protected;
    `crypto_obfuscator` decodes them."""
    data, _name = find_manifest_resource(pe, {"LfdReader.dll"})
    return data


def _get_user_string_heap(pe: "dnfile.dnPE"):
    """Return the #US (user-string) heap of the assembly."""
    for s in pe.net.metadata.streams_list:
        if type(s).__name__ == "UserStringHeap":
            return s
    raise ValueError("No #US (user-string) heap found in this assembly")


def _iter_user_strings(pe: "dnfile.dnPE"):
    """Yield (heap_offset, string) for every #US entry, i.e. every `ldstr` literal."""
    heap = _get_user_string_heap(pe)
    heap_size = heap._data_size  # noqa: SLF001 -- no public size accessor exposed
    offset = 1  # offset 0 is always the reserved empty entry
    while offset < heap_size:
        res = heap.get_with_size(offset)
        if res is None:
            break
        data_bytes, raw_size = res
        if raw_size == 0:
            offset += 1
            continue
        try:
            s = data_bytes.decode("utf-16-le", errors="strict")
        except UnicodeDecodeError:
            s = None
        if s is not None:
            yield offset, s
        offset += raw_size


def _is_pure_base91(s: str) -> bool:
    return len(s) > 0 and all(ord(c) in _BASE91_DECODE_TABLE for c in s)


def extract_ciphertext_and_password(pe: "dnfile.dnPE") -> Tuple[str, str, list]:
    """Find the Base91 ciphertext and the password among the host's #US strings.

    Anchor: the literal `"Benchmark"`, which the host passes to `GetMethod` by reflection.
    The ciphertext is the longest pure-Base91 string after the anchor in heap order.
    The password is the closest printable string before it (6-128 chars, no space or backslash).

    The host also holds a decoy Base91 string. Without the anchor, the longest Base91
    string in the heap could be the decoy. If there is no anchor, the longest string
    and `HARDCODED_PASSWORD` are used, with a warning.

    Returns (ciphertext, password, all Base91 candidates as (offset, length)).
    """
    strings = sorted(_iter_user_strings(pe), key=lambda t: t[0])
    by_offset = dict(strings)
    base91_candidates = [(o, len(s)) for o, s in strings if _is_pure_base91(s)]

    anchor_offset = next((o for o, s in strings if s == "Benchmark"), None)

    if anchor_offset is not None:
        after = [(o, s) for o, s in strings if o > anchor_offset and _is_pure_base91(s)]
        before = [(o, s) for o, s in strings if o < anchor_offset]
        if not after:
            raise ValueError("Found 'Benchmark' anchor but no Base91-looking string after it")
        ciphertext_offset, ciphertext = max(after, key=lambda t: len(t[1]))
        pw_candidates = [
            (o, s) for o, s in before
            if 6 <= len(s) <= 128 and " " not in s and "\\" not in s
            and all(33 <= ord(c) <= 126 for c in s)
        ]
        if not pw_candidates:
            raise ValueError("Found 'Benchmark' anchor but no plausible password string before it")
        password_offset, password = max(pw_candidates, key=lambda t: t[0])  # closest preceding
        logger.info(
            "Anchor-based extraction: 'Benchmark' at offset %d, password at %d (%d chars), "
            "ciphertext at %d (%d chars)",
            anchor_offset, password_offset, len(password), ciphertext_offset, len(ciphertext),
        )
    else:
        logger.warning(
            "No literal 'Benchmark' string found in the #US heap -- falling back to "
            "'longest pure-Base91 string in the whole heap', which is NOT safe against "
            "decoy strings (at least one build in this family has one). Verify the "
            "extracted ciphertext manually if this path is taken."
        )
        if not base91_candidates:
            raise ValueError("No Base91-looking string found anywhere in this sample's user-string heap")
        ciphertext_offset = max(base91_candidates, key=lambda t: t[1])[0]
        ciphertext = by_offset[ciphertext_offset]
        password = HARDCODED_PASSWORD
        logger.warning("Using the known hardcoded fallback password -- may be wrong for this build")

    if len(base91_candidates) > 1:
        longest = sorted(base91_candidates, key=lambda t: -t[1])[:3]
        logger.warning(
            "%d Base91-looking strings in the heap. Only the selected one is used. "
            "Longest (offset, length): %s",
            len(base91_candidates), longest,
        )

    return ciphertext, password, base91_candidates


# ---------------------------------------------------------------------------
# Fully-automatic pipeline: given only a host loader file
# ---------------------------------------------------------------------------

def unpack_stage3(path: Path, password_override: Optional[str] = None) -> dict:
    """Run the whole pipeline on a host file: extract, derive the params, decrypt.

    Returns a JSON-serialisable record (hashes, password, Threefish params, result
    summary). The key `_result` holds the `DecryptionResult`. Pop it before `json.dump`.
    """
    if not _DNFILE_AVAILABLE:
        raise RuntimeError("dnfile required: pip install 'dnfile>=0.15.0'")

    logger.info("Loading host file: %s", path)
    exe_bytes = Path(path).read_bytes()
    exe_sha256 = hashlib.sha256(exe_bytes).hexdigest()
    pe = dnfile.dnPE(data=exe_bytes)
    if pe.net is None:
        # A native PE has no CLR metadata. Raise ValueError like every other "not this
        # family" rejection, so callers skip the file instead of crashing on `pe.net`.
        raise ValueError(f"{path} has no .NET/CLR metadata -- not an IBar2Double-chain sample")

    lfd_bytes = extract_lfdreader_dll(pe)
    lfd_sha256 = hashlib.sha256(lfd_bytes).hexdigest()
    logger.info("Extracted LfdReader.dll: %d bytes, SHA-256=%s", len(lfd_bytes), lfd_sha256)

    ciphertext, password, _ = extract_ciphertext_and_password(pe)
    if password_override is not None:
        logger.info("Overriding extracted password with --password argument")
        password = password_override
    logger.info("Extracted ciphertext: %d chars; password: %d chars", len(ciphertext), len(password))

    table = extract_constant_table_from_lfdreader(lfd_bytes)
    params = constants_to_params(table)

    result = benchmark(ciphertext, password, params)

    return {
        "source_host_file": {"path": str(path), "sha256": exe_sha256, "size": len(exe_bytes)},
        "lfdreader_dll": {"sha256": lfd_sha256, "size": len(lfd_bytes)},
        "ciphertext_len": len(ciphertext),
        "password": password,
        "threefish_params": params.to_config_dict(),
        "stage3": {
            "sha256": result.sha256,
            "md5": result.md5,
            "size": result.size,
            "looks_like_pe": result.looks_like_pe,
        },
        "_result": result,
    }


# Old name, still imported by the deployed karton worker.
unpack_22exe = unpack_stage3


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Decrypt the stage-3 payload of an IBar2Double host sample "
                    "(Threefish-256-CBC). See README.md.",
    )
    p.add_argument("host_file", type=Path,
                   help="Host .NET sample. LfdReader.dll, the Base91 ciphertext and the "
                        "password are extracted from it.")
    p.add_argument("-o", "--output", type=Path, default=Path("stage3.exe"),
                   help="Output path for the decrypted PE (default: stage3.exe).")
    p.add_argument("--password", metavar="PASSWORD",
                   help="Override the password extracted from the host.")
    p.add_argument("--save-config", metavar="JSON", type=Path,
                   help="Write a JSON record of the run: hashes, password, Threefish params, "
                        "result summary. The ciphertext is not saved.")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging.")
    return p


def _print_summary(result: DecryptionResult, output: Path) -> None:
    logger.info("--- Decryption summary ---")
    logger.info("  Output:  %s", output)
    logger.info("  Size:    %d bytes", result.size)
    logger.info("  SHA-256: %s", result.sha256)
    logger.info("  MD5:     %s", result.md5)
    logger.info("  Status:  %s",
                "PE recovered (starts with 'MZ')" if result.looks_like_pe
                else "WARNING: output does not start with 'MZ'")


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(name)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    if not args.host_file.is_file():
        logger.error("File not found: %s", args.host_file)
        return 1
    try:
        record = unpack_stage3(args.host_file, password_override=args.password)
    except (RuntimeError, ValueError) as exc:
        logger.error("Unpacking failed: %s", exc)
        return 1

    result: DecryptionResult = record.pop("_result")
    args.output.write_bytes(result.plaintext)
    _print_summary(result, args.output)
    if args.save_config is not None:
        args.save_config.write_text(json.dumps(record, indent=2), encoding="utf-8")
        logger.info("Run record written to %s", args.save_config)
    return 0 if result.looks_like_pe else 2


if __name__ == "__main__":
    sys.exit(main())
