"""crypto_obfuscator — read the Threefish parameters out of `LfdReader.dll`.

CryptoObfuscator is a commercial .NET protector. It hides the integer constants
of `LfdReader.dll` in a table stored as DES+Deflate-protected resources. This
module decodes that table and returns `ThreefishParams` for `curvefish_unpacker`,
its only caller. It decrypts no payload.

Algorithm (two layers, same decoder):
  1. Decode the `IBar2Double&&` resource of `LfdReader.dll`. The result is a
     nested .NET assembly.
  2. Decode the `IBar2Double%` resource of that assembly. The result is the flat
     constant table, read at byte offsets as `BitConverter.ToInt32/64`.
  3. `constants_to_params()` maps table offsets to PBKDF2 iterations, derived-key
     length, salt/IV offsets and lengths, and payload offset and length.

Resource stream format (`decode_obfuscator_resource_stream`):
  `[0:3]` ignored | `[3]` flags, stored inverted (bit 1 = DES, bit 3 = Deflate)
  `[4:12]` DES IV | `[12:20]` DES key | `[20:]` DES-CBC body, then raw Deflate.
  The IV comes first and the key second. IL call order suggests the reverse.

README.md has the full byte layout and the reasoning behind each step.
"""

from __future__ import annotations

import io
import logging
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

try:
    import dnfile  # type: ignore
    _DNFILE_AVAILABLE = True
except ImportError:
    _DNFILE_AVAILABLE = False

try:
    from Crypto.Cipher import DES  # type: ignore
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

PROCESSING_NAME = "crypto_obfuscator"
VERSION = 1

logger = logging.getLogger(PROCESSING_NAME)

# Threefish C240 key-schedule constant (Skein spec). Defined here and imported by
# curvefish_unpacker. It is also the sanity check for the constant table: the table
# holds it at byte offset 288 in every build seen.
TF_C240: int = 0x1BD11BDAA9FC1A22


# ---------------------------------------------------------------------------
# Threefish parameters -- this module's sole output type
# ---------------------------------------------------------------------------

@dataclass
class ThreefishParams:
    pbkdf2_iters: int
    pbkdf2_dklen: int
    salt_offset: int
    salt_len: int
    iv_offset: int
    iv_len: int
    payload_offset: int
    payload_len_sub: int
    description: str = ""

    def to_config_dict(self) -> dict:
        return dict(self.__dict__)


# ---------------------------------------------------------------------------
# DES+Deflate resource-stream decode (CryptoObfuscator's own mechanism)
# ---------------------------------------------------------------------------

def _read_exactly(stream: io.BytesIO, n: int) -> bytes:
    buf = stream.read(n)
    if len(buf) != n:
        raise ValueError(f"Stream ended early: wanted {n} bytes, got {len(buf)}")
    return buf


def _des_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """DES-CBC decrypt via pycryptodome (matches .NET DESCryptoServiceProvider CBC)."""
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError("pycryptodome required: pip install pycryptodome")
    return DES.new(key, DES.MODE_CBC, iv=iv).decrypt(ciphertext)


def decode_obfuscator_resource_stream(resource_bytes: bytes) -> bytes:
    """Decode one CryptoObfuscator protected resource (`IBar2Double&&`, `IBar2Double%`).

    Layout:
      [0:3]    ignored
      [3]      flags, stored inverted: real = ~stored & 0xFF (bit 1 = DES, bit 3 = Deflate)
      [4:12]   DES IV    (only if DES)
      [12:20]  DES key   (only if DES)
      [20:]    DES-CBC body, or raw Deflate data if the DES bit is not set (from [4:])
    The IV comes first and the key second. IL call order suggests the reverse.
    An all-zero IV would mean "derive it from the assembly's PublicKeyToken". No build seen needs it.
    """
    stream = io.BytesIO(resource_bytes)
    _read_exactly(stream, 3)
    stored_flags = _read_exactly(stream, 1)[0]
    flags = ~stored_flags & 0xFF
    has_des, has_deflate = bool(flags & 2), bool(flags & 8)
    logger.debug("Flags: stored=0x%02X real=0x%02X DES=%s Deflate=%s",
                 stored_flags, flags, has_des, has_deflate)
    if not has_deflate:
        raise ValueError(f"Unsupported flags 0x{flags:02X}: only DES+Deflate or Deflate alone are handled")

    if has_des:
        des_iv = _read_exactly(stream, 8)
        des_key = _read_exactly(stream, 8)
        if not any(des_iv):
            logger.warning("DES IV is all zero: the PublicKeyToken fallback is not implemented")
        body = stream.read()
        if not body or len(body) % 8 != 0:
            raise ValueError(f"DES-CBC body is {len(body)} bytes, expected a non-empty multiple of 8")
        logger.debug("DES-CBC decrypting %d bytes (key=%s iv=%s)", len(body), des_key.hex(), des_iv.hex())
        deflated = _des_cbc_decrypt(des_key, des_iv, body)
    else:
        deflated = stream.read()

    # .NET DeflateStream is raw Deflate (wbits=-15). The PKCS7 padding left after the
    # DES decrypt trails the end-of-stream marker, and zlib ignores it.
    try:
        result = zlib.decompress(deflated, wbits=-zlib.MAX_WBITS)
    except zlib.error as exc:
        raise ValueError(f"Deflate failed: {exc}. First 32 bytes: {deflated[:32].hex()}") from exc
    logger.debug("Deflate: %d -> %d bytes", len(deflated), len(result))
    return result


# ---------------------------------------------------------------------------
# Generic manifest-resource-by-name lookup
# ---------------------------------------------------------------------------

def find_manifest_resource(pe: "dnfile.dnPE", target_names: set) -> Tuple[bytes, str]:
    """Return (data, name) of the manifest resource called by one of `target_names`.

    Tries an exact name first, then a substring match.
    """
    all_rsrc = pe.net.resources or []
    for rsrc in all_rsrc:
        name = str(rsrc.name)
        if name in target_names and isinstance(rsrc.data, bytes):
            return rsrc.data, name
    for rsrc in all_rsrc:
        name = str(rsrc.name)
        if any(t in name for t in target_names) and isinstance(rsrc.data, bytes):
            logger.warning("Exact name not found; using '%s'", name)
            return rsrc.data, name
    raise ValueError(
        f"None of {target_names} found. Available: {[str(r.name) for r in all_rsrc]}"
    )


# ---------------------------------------------------------------------------
# Constant-table extraction and mapping
# ---------------------------------------------------------------------------

def extract_constant_table_from_lfdreader(lfd_source: "Path | bytes") -> bytes:
    """Return the flat constant table of `LfdReader.dll` (see the module docstring).

    `lfd_source` is a file path or the DLL bytes already in memory.
    """
    if not _DNFILE_AVAILABLE:
        raise RuntimeError("dnfile required: pip install 'dnfile>=0.15.0'")

    if isinstance(lfd_source, (bytes, bytearray)):
        logger.info("Loading LfdReader.dll from in-memory bytes (%d bytes)", len(lfd_source))
        outer_pe = dnfile.dnPE(data=bytes(lfd_source))
    else:
        logger.info("Loading LfdReader.dll: %s", lfd_source)
        outer_pe = dnfile.dnPE(str(lfd_source))
    outer_data, outer_name = find_manifest_resource(outer_pe, {"IBar2Double&&"})
    logger.info("Outer resource '%s': %d bytes", outer_name, len(outer_data))

    nested_assembly = decode_obfuscator_resource_stream(outer_data)
    logger.info("Decoded nested assembly: %d bytes", len(nested_assembly))
    if nested_assembly[:2] != b"MZ":
        raise ValueError(
            f"Decoded '{outer_name}' payload does not start with 'MZ' "
            f"(first bytes: {nested_assembly[:16].hex()}) -- expected a nested "
            f".NET assembly at this layer."
        )

    nested_pe = dnfile.dnPE(data=nested_assembly)
    percent_data, percent_name = find_manifest_resource(nested_pe, {"IBar2Double%"})
    logger.info("Nested resource '%s': %d bytes", percent_name, len(percent_data))

    table = decode_obfuscator_resource_stream(percent_data)
    logger.info("Constant table: %d bytes", len(table))
    logger.debug("First 64 bytes: %s", table[:64].hex())
    return table


def get_i32(table: bytes, offset: int) -> int:
    """BitConverter.ToInt32(table, offset) equivalent -- arbitrary byte offset."""
    return struct.unpack_from("<i", table, offset)[0]


def get_i64(table: bytes, offset: int) -> int:
    """BitConverter.ToInt64(table, offset) equivalent -- arbitrary byte offset."""
    return struct.unpack_from("<q", table, offset)[0]


def constants_to_params(table: bytes) -> ThreefishParams:
    """Map the constant table to ThreefishParams. `raw` is the Base91-decoded ciphertext.

        offset   meaning
        ------   -------------------------------------------------
        0        salt length (mirrored at 16)
        4        IV length (mirrored at 28)
        8        salt offset in `raw`
        20       IV offset in `raw`
        32, 36   two terms subtracted from len(raw) to get the payload length
        40       payload offset in `raw`
        84       PBKDF2 iteration count
        88       PBKDF2 derived-key length in bytes
        288      Threefish C240 constant (int64), used as a sanity check only
    """
    def c(offset: int) -> int:
        return get_i32(table, offset)

    params = ThreefishParams(
        pbkdf2_iters=c(84),
        pbkdf2_dklen=c(88),
        salt_offset=c(8),
        salt_len=c(0),
        iv_offset=c(20),
        iv_len=c(4),
        payload_offset=c(40),
        payload_len_sub=c(32) + c(36),
        description="IBar2Double% constant table (two-layer decode from IBar2Double&&)",
    )

    # A different value does not prove the extraction is wrong, since offsets can move
    # between builds. It is a warning to check the mapping above.
    try:
        c240 = get_i64(table, 288)
    except struct.error:
        logger.debug("Table too short for the C240 check at offset 288; skipping")
    else:
        if c240 & 0xFFFFFFFFFFFFFFFF != TF_C240:
            logger.warning("const[288] = 0x%016X, expected Threefish C240 = 0x%016X: "
                           "the offsets may have moved in this build",
                           c240 & 0xFFFFFFFFFFFFFFFF, TF_C240)
        else:
            logger.info("Sanity check OK: const[288] is the Threefish C240 constant")

    logger.info(
        "Params: iters=%d dklen=%d salt=[%d:%d] iv=[%d:%d] payload_offset=%d payload_len_sub=%d",
        params.pbkdf2_iters, params.pbkdf2_dklen,
        params.salt_offset, params.salt_offset + params.salt_len,
        params.iv_offset, params.iv_offset + params.iv_len,
        params.payload_offset, params.payload_len_sub,
    )
    return params
