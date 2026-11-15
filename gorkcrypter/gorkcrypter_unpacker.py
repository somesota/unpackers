"""gorkcrypter_unpacker — decode the embedded PE from the GorkCrypter Go packer.

The packer keeps its payload as an encrypted blob in `.rdata`. At startup
`main.main` copies the blob to the stack with `REP MOVSQ`, loads a 32-bit key
from an immediate into `EDI`, and calls the decoder. This tool finds that call
site by byte pattern, reads the blob and key from it, and runs the decoder.

Input buffer: `prefix || blob`. Some builds write an 8-byte literal first, and
the copy overwrites its bytes 2..7, so the 2 surviving bytes are the prefix.
Other builds have no literal and no prefix.

Decoder: six in-place passes, all mod 256, `i` = byte index:
  1. even `i`: `b[i] -= (key % 53) + 17*i`
  2. odd  `i`: `b[i] ^= (key % 97) ^ 31*i`
  3. reverse the whole buffer
  4. swap each adjacent byte pair
  5. `b[i] -= ((key >> 8) & 0xFF) + 3*i`
  6. `b[i] ^= (key & 0xFF) ^ 5*i`
(Passes 1 and 2 share one loop, so the code runs five steps.) The result is a
PE32+ image, mapped in memory by the packer and never written to disk.

Usage:
  gorkcrypter_unpacker.py <sample> [-o payload.exe] [--save-config cfg.json] [-v]
  gorkcrypter_unpacker.py <sample> --blob-offset 0x191d46 --length 0x4ba40 \
        --key 0xcfa97 --prefix 910d -o payload.exe        # manual mode

Exit codes: 0 = `MZ` recovered, 1 = error or call site not found,
2 = decoded but not `MZ`.

Reference builds: `21768f84…` (prefix, key `0xCFA97`) and `b10c774e…` (no prefix,
key `0x7E404`). Details are in `KB/gorkcrypter/README.md`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

import pefile

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROCESSING_NAME = "gorkcrypter_unpacker"
VERSION = 2  # v2: generalized to match both prefixed (MIX1) and no-prefix (MIX2) call sites

# The decoy sentence every obfuscated function in this loader family embeds.
FINGERPRINT_SENTENCE = b"go code counts words and go code logs every word"

logger = logging.getLogger(PROCESSING_NAME)

# Call-site signature. The leading literal-write is *optional* — present in
# prefixed builds (MIX1: main.main @ 0x4dd4b3), absent in no-prefix builds
# (MIX2: main.main @ 0x4f586c) — everything from the RDI/RSI pair onward is
# identical between the two shapes:
#
#   [ 48 B8 <imm64>              MOV  RAX, prefix_literal                  ]
#   [ 48 89 84 24 <disp32>       MOV  [RSP+const_off], RAX  (or disp8 form)]  } optional
#   48 8D BC 24 <disp32>       LEA  RDI, [RSP+copy_off]       (or 48 8D 7C 24 <disp8>)
#   48 8D 35 <rel32>           LEA  RSI, [rip + blob]
#   B9 <imm32>                 MOV  ECX, qword_count
#   F3 48 A5                   REP MOVSQ
#   48 8D 84 24 <disp32>       LEA  RAX, [RSP+buf_off]        (or 48 8D 44 24 <disp8>)
#   BB <imm32>                 MOV  EBX, buffer_len
#   48 89 D9                   MOV  RCX, RBX
#   BF <imm32>                 MOV  EDI, key
#
# disp8 and disp32 ModRM forms are both accepted for the three RSP-relative
# operands; the parser reads whichever form matched. When the optional
# leading block doesn't match, find_loader_params treats the build as
# no-prefix: prefix_literal=0, const_off=copy_off (the prefix's own `prefix`
# property then reduces to b"" automatically, see LoaderParams.prefix).
_DISP = rb"(?:\x84\x24(.{4})|\x44\x24(.))"
_DISP_RDI = rb"(?:\xbc\x24(.{4})|\x7c\x24(.))"
CALLSITE_RE = re.compile(
    rb"(?:\x48\xb8(.{8})\x48\x89" + _DISP + rb")?"  # 1/2/3: optional prefix literal + const_off
    rb"\x48\x8d" + _DISP_RDI +       # 4/5: copy_off
    rb"\x48\x8d\x35(.{4})"           # 6: rel32 -> blob
    rb"\xb9(.{4})"                   # 7: qword count
    rb"\xf3\x48\xa5"                 # rep movsq
    rb"\x48\x8d" + _DISP +           # 8/9: buf_off
    rb"\xbb(.{4})"                   # 10: buffer length
    rb"\x48\x89\xd9"                 # mov rcx, rbx
    rb"\xbf(.{4})",                  # 11: key
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class LoaderParams:
    """Everything needed to rebuild the decoder's input buffer and run it."""
    blob_rva: int            # RVA of the encrypted blob in the loader image
    blob_file_offset: int    # same, as a file offset
    blob_len: int            # bytes copied by REP MOVSQ (8 * count)
    prefix_literal: int      # the 64-bit constant written before the copy
    const_off: int           # stack offset the literal is written to
    copy_off: int            # stack offset REP MOVSQ writes to
    buf_off: int             # stack offset passed as the decoder's buffer
    buffer_len: int          # length passed to the decoder
    key: int                 # 32-bit key passed to the decoder
    callsite_file_offset: int | None = None

    @property
    def prefix(self) -> bytes:
        """Bytes of the literal that survive in front of the blob copy."""
        lit = self.prefix_literal.to_bytes(8, "little")
        keep = self.copy_off - self.const_off
        return lit[max(0, self.buf_off - self.const_off):max(0, keep)]


@dataclass
class UnpackResult:
    payload: bytes
    sha256: str
    md5: str
    size: int
    is_pe: bool
    params: LoaderParams


# ---------------------------------------------------------------------------
# Decoder (pure Python re-implementation of main.g9IzPQ)
# ---------------------------------------------------------------------------

def decode_blob(data: bytes, key: int) -> bytes:
    """Run the loader's six-pass in-place transform over ``data``.

    ``data`` must already be the exact buffer the loader passes to its
    decoder (prefix bytes + raw blob); see :func:`build_input_buffer`.
    """
    key &= 0xFFFFFFFF
    buf = bytearray(data)
    n = len(buf)

    k53 = key % 53
    k97 = key % 97
    k_hi = (key >> 8) & 0xFF
    k_lo = key & 0xFF

    # Pass 1: even/odd keyed subtract / XOR with position terms 17*i / 31*i.
    for i in range(n):
        if i & 1 == 0:
            buf[i] = (buf[i] - k53 - 17 * i) & 0xFF
        else:
            buf[i] = (buf[i] ^ k97 ^ (31 * i)) & 0xFF

    # Pass 2: full reversal.
    buf.reverse()

    # Pass 3: adjacent pair swap.
    for j in range(0, n - 1, 2):
        buf[j], buf[j + 1] = buf[j + 1], buf[j]

    # Pass 4: subtract key byte 1 and 3*i.
    for i in range(n):
        buf[i] = (buf[i] - k_hi - 3 * i) & 0xFF

    # Pass 5: XOR key byte 0 and 5*i.
    for i in range(n):
        buf[i] = (buf[i] ^ k_lo ^ (5 * i)) & 0xFF

    return bytes(buf)


def build_input_buffer(blob: bytes, params: LoaderParams) -> bytes:
    """Reproduce the stack buffer the loader hands to its decoder.

    The loader writes an 8-byte literal at ``const_off``, then ``REP MOVSQ``
    copies the blob to ``copy_off`` (overwriting part of that literal), and
    passes ``buf_off`` / ``buffer_len`` to the decoder. Simulating those
    three writes literally keeps the overlap semantics exact for any build.
    """
    lo = min(params.const_off, params.copy_off, params.buf_off)
    hi = max(params.const_off + 8,
             params.copy_off + len(blob),
             params.buf_off + params.buffer_len)
    stack = bytearray(hi - lo)
    stack[params.const_off - lo:params.const_off - lo + 8] = \
        params.prefix_literal.to_bytes(8, "little")
    stack[params.copy_off - lo:params.copy_off - lo + len(blob)] = blob
    start = params.buf_off - lo
    return bytes(stack[start:start + params.buffer_len])


# ---------------------------------------------------------------------------
# Call-site discovery
# ---------------------------------------------------------------------------

def _disp(g32: bytes | None, g8: bytes | None) -> int:
    if g32 is not None:
        return int.from_bytes(g32, "little", signed=True)
    return int.from_bytes(g8, "little", signed=True)


def find_loader_params(pe: pefile.PE, data: bytes) -> LoaderParams | None:
    """Scan executable sections for the blob-copy + decoder call site."""
    for section in pe.sections:
        if not section.Characteristics & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]:
            continue
        raw_start = section.PointerToRawData
        raw = data[raw_start:raw_start + section.SizeOfRawData]

        for m in CALLSITE_RE.finditer(raw):
            g = m.groups()
            copy_off = _disp(g[3], g[4])
            rel32 = int.from_bytes(g[5], "little", signed=True)
            qwords = int.from_bytes(g[6], "little")
            buf_off = _disp(g[7], g[8])
            buffer_len = int.from_bytes(g[9], "little")
            key = int.from_bytes(g[10], "little")

            if g[0] is not None:
                # Prefixed shape (e.g. MIX1): a real literal survives in front.
                prefix_literal = int.from_bytes(g[0], "little")
                const_off = _disp(g[1], g[2])
            else:
                # No-prefix shape (e.g. MIX2): nothing precedes the blob copy.
                # Setting const_off == copy_off makes LoaderParams.prefix
                # reduce to b"" and build_input_buffer's stack simulation
                # collapse to a verbatim copy of the blob — see their
                # docstrings.
                prefix_literal = 0
                const_off = copy_off

            # rel32 is relative to the end of the LEA RSI instruction
            # (group 6 = the rel32 operand, 1-based in re's numbering).
            lea_end_in_raw = m.start(6) + 4
            lea_end_rva = section.VirtualAddress + lea_end_in_raw
            blob_rva = lea_end_rva + rel32
            try:
                blob_off = pe.get_offset_from_rva(blob_rva)
            except pefile.PEFormatError:
                logger.debug("Signature hit at raw+0x%x points outside the image; skipping",
                             m.start())
                continue

            params = LoaderParams(
                blob_rva=blob_rva,
                blob_file_offset=blob_off,
                blob_len=qwords * 8,
                prefix_literal=prefix_literal,
                const_off=const_off,
                copy_off=copy_off,
                buf_off=buf_off,
                buffer_len=buffer_len,
                key=key,
                callsite_file_offset=raw_start + m.start(),
            )
            logger.info("Call site @ file 0x%x: blob RVA 0x%x (file 0x%x), %d bytes, "
                        "buffer %d bytes, prefix %s, key 0x%x",
                        params.callsite_file_offset, blob_rva, blob_off,
                        params.blob_len, buffer_len, params.prefix.hex(), key)
            return params

    return None


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def unpack_bytes(data: bytes, params: LoaderParams) -> UnpackResult:
    blob = data[params.blob_file_offset:params.blob_file_offset + params.blob_len]
    if len(blob) != params.blob_len:
        raise ValueError(f"blob truncated: wanted {params.blob_len} bytes at "
                         f"0x{params.blob_file_offset:x}, file has {len(blob)}")

    buf = build_input_buffer(blob, params)
    payload = decode_blob(buf, params.key)
    is_pe = payload[:2] == b"MZ"
    return UnpackResult(
        payload=payload,
        sha256=hashlib.sha256(payload).hexdigest(),
        md5=hashlib.md5(payload).hexdigest(),
        size=len(payload),
        is_pe=is_pe,
        params=params,
    )


def unpack_data(data: bytes, manual: LoaderParams | None = None) -> UnpackResult | None:
    """Unpack from raw bytes already in memory. Returns None if no call site
    could be found. This is the entry point the karton service uses (no temp
    file needed, unlike netzippacker_unpacker/fishcrypter_unpacker's dnfile-backed
    parsers) — :func:`unpack` is a thin file-reading wrapper around it.
    """
    if manual is not None:
        return unpack_bytes(data, manual)

    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        logger.error("Not a PE file: %s", exc)
        return None

    if FINGERPRINT_SENTENCE not in data:
        logger.info("Decoy sentence %r not present — known to vary across builds in "
                    "this family (present in MIX1, absent in MIX2); not by itself "
                    "evidence against a call-site match",
                    FINGERPRINT_SENTENCE.decode())

    params = find_loader_params(pe, data)
    if params is None:
        logger.error("Decoder call site signature not found; use the manual "
                     "--blob-offset/--length/--key/--prefix options")
        return None

    return unpack_bytes(data, params)


def unpack(filepath: str | Path, manual: LoaderParams | None = None) -> UnpackResult | None:
    """Unpack one loader file from disk. Returns None if no call site could be found."""
    return unpack_data(Path(filepath).read_bytes(), manual)


def manual_params(pe_data: bytes, blob_offset: int, length: int, key: int,
                  prefix: bytes) -> LoaderParams:
    """Build LoaderParams from CLI overrides (prefix bytes go before the blob)."""
    return LoaderParams(
        blob_rva=0,
        blob_file_offset=blob_offset,
        blob_len=length,
        prefix_literal=int.from_bytes(prefix.ljust(8, b"\x00"), "little"),
        const_off=0,
        copy_off=len(prefix),
        buf_off=0,
        buffer_len=length + len(prefix),
        key=key,
    )


def describe_payload(payload: bytes) -> dict:
    """Small PE summary for logs / --save-config."""
    info: dict = {}
    try:
        p = pefile.PE(data=payload, fast_load=True)
        p.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        info["machine"] = hex(p.FILE_HEADER.Machine)
        info["subsystem"] = p.OPTIONAL_HEADER.Subsystem
        info["entry_point"] = hex(p.OPTIONAL_HEADER.AddressOfEntryPoint)
        info["image_base"] = hex(p.OPTIONAL_HEADER.ImageBase)
        info["timestamp"] = hex(p.FILE_HEADER.TimeDateStamp)
        info["sections"] = [s.Name.rstrip(b"\x00").decode(errors="replace")
                            for s in p.sections]
        end = max(s.PointerToRawData + s.SizeOfRawData for s in p.sections)
        info["overlay_size"] = max(0, len(payload) - end)
        info["imports"] = {e.dll.decode(errors="replace"): len(e.imports)
                           for e in getattr(p, "DIRECTORY_ENTRY_IMPORT", [])}
    except pefile.PEFormatError as exc:
        info["error"] = str(exc)
    return info


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _int(s: str) -> int:
    return int(s, 0)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="gorkcrypter_unpacker — recover the embedded PE from the "
                    "'go code counts words' Go loader",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("sample", help="Path to the Go loader PE")
    parser.add_argument("-o", "--output", default=None,
                        help="Output file for the decoded payload "
                             "(default: <sample>.payload.bin)")
    parser.add_argument("--save-config", default=None, metavar="JSON",
                        help="Write the recovered loader parameters + payload hashes to JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    manual = parser.add_argument_group("manual mode (all four required together)")
    manual.add_argument("--blob-offset", type=_int, help="File offset of the encrypted blob")
    manual.add_argument("--length", type=_int, help="Blob length in bytes")
    manual.add_argument("--key", type=_int, help="32-bit decode key")
    manual.add_argument("--prefix", default=None,
                        help="Hex bytes prepended to the blob before decoding "
                             "(use '' for none)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(name)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    sample = Path(args.sample)
    if not sample.is_file():
        logger.error("Sample not found: %s", sample)
        return 1

    manual_given = [args.blob_offset, args.length, args.key, args.prefix]
    override = None
    if any(v is not None for v in manual_given):
        if any(v is None for v in manual_given):
            parser.error("--blob-offset, --length, --key and --prefix must be given together")
        override = manual_params(sample.read_bytes(), args.blob_offset, args.length,
                                 args.key, bytes.fromhex(args.prefix))

    logger.info("%s v%d — processing %s", PROCESSING_NAME, VERSION, sample.name)
    try:
        result = unpack(sample, override)
    except ValueError as exc:
        logger.error("%s", exc)
        return 1
    if result is None:
        return 1

    out = Path(args.output) if args.output else sample.with_name(sample.name + ".payload.bin")
    out.write_bytes(result.payload)
    logger.info("Wrote %d bytes to %s", result.size, out)
    logger.info("SHA-256 %s  MD5 %s  MZ=%s", result.sha256, result.md5, result.is_pe)

    info = describe_payload(result.payload) if result.is_pe else {}
    for k, v in info.items():
        logger.info("  payload %s: %s", k, v)

    if args.save_config:
        cfg = {
            "tool": PROCESSING_NAME,
            "version": VERSION,
            "loader_sha256": hashlib.sha256(sample.read_bytes()).hexdigest(),
            "params": {k: (hex(v) if isinstance(v, int) else v)
                       for k, v in asdict(result.params).items()},
            "prefix": result.params.prefix.hex(),
            "payload_sha256": result.sha256,
            "payload_md5": result.md5,
            "payload_size": result.size,
            "payload_is_pe": result.is_pe,
            "payload_info": info,
        }
        Path(args.save_config).write_text(json.dumps(cfg, indent=2))
        logger.info("Config written to %s", args.save_config)

    if not result.is_pe:
        logger.warning("Decoded buffer does not start with MZ — wrong key/order or a different build")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
