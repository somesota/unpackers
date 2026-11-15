#!/usr/bin/env python3
"""
arxcrypter_unpacker.py — offline decryptor for the custom RC4-KSA/AES-GF(2^8)
-inverse/SHA-256-IV-ARX stream cipher documented in
malware-kb/reports/5541bf99ebfee0f4c9ab33624b49e125348bf02280b9efbb8824919f53c8630c/reverse.md
(the crypter/packer that arrives as GCleaner's 64-bit "update" payload).

WHY THIS IS AN EMULATOR, NOT A HAND-PORTED REIMPLEMENTATION
-------------------------------------------------------------------------
reverse.md fully traced the cipher's five compiled helper functions, but two
of them decompile to code Ghidra's own type-propagation could not settle —
confirmed directly this session: FUN_140072110_derive_keystream_material
carries Ghidra's own "Type propagation algorithm not settling" warning, and
the top-level FUN_140073be0_stream_cipher_decrypt_stage2 decompiles a real
pointer computation as the literal nonsense expression
`*(byte *)(local_60 + 0x2800ee00)` — a stack-slot-reuse artifact, not real
program behavior. Hand-porting ~600 lines of this pseudocode byte-for-byte
risks silently baking in exactly this kind of decompiler mistranslation.

Instead, this tool loads the sample's own compiled machine code into a CPU
emulator (Unicorn) and calls the real, unmodified
FUN_140073be0_stream_cipher_decrypt_stage2 function directly — guaranteeing
byte-exact behavior because it *is* the sample's own code, not a
transcription of it. The only code this tool substitutes is two small,
purely mechanical OS-facing helpers the cipher calls internally
(an allocator and a matching "free", both gated behind this sample's
own PEB-walk/API-hash resolver — see Gotchas in README.md); every
cryptographic instruction actually executes as compiled. Nothing here
executes the sample's own entry point, its anti-analysis gates, or the
still-undecrypted stage-2 payload itself — only the isolated,
side-effect-free cipher subroutine and its pure-computation callees.

Usage
-----
    arxcrypter_unpacker.py <sample_path> [-o OUTPUT] [--save-config CONFIG.JSON] [-v]

Exit codes (matches this project's other unpackers): 0 = MZ recovered,
1 = error, 2 = decrypted but not MZ-headed.
"""

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pefile
from unicorn import (
    Uc,
    UC_ARCH_X86,
    UC_MODE_64,
    UC_HOOK_CODE,
    UC_PROT_ALL,
    UcError,
)
from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RSP,
    UC_X86_REG_RIP,
)

# ---------------------------------------------------------------------------
# Reference-build constants (5541bf99ebfee0f4c9ab33624b49e125348bf02280b9efbb8824919f53c8630c)
# All addresses re-verified against the live Ghidra project and the raw file
# via pefile this session — see README.md's "Verified addresses" section for
# the static.md discrepancy this caught (.data's real RVA is 0x7b000, not the
# 0x7ac00 static.md recorded — the latter isn't 0x1000-aligned and can't be
# a real section start).
# ---------------------------------------------------------------------------
REFERENCE_SHA256 = "5541bf99ebfee0f4c9ab33624b49e125348bf02280b9efbb8824919f53c8630c"
DEFAULT_CIPHER_FUNC_RVA = 0x73BE0      # FUN_140073be0_stream_cipher_decrypt_stage2
DEFAULT_KEY_RVA = 0x7B000              # DAT_14007b000_stage2_key (128 bytes)
DEFAULT_KEY_LEN = 0x80
DEFAULT_CIPHERTEXT_RVA = 0x7B100       # DAT_14007b100_stage2_ciphertext
DEFAULT_CIPHERTEXT_LEN = 0x11A800      # 1,157,120 bytes
DEFAULT_ALLOC_RVA = 0x75E80            # FUN_140075e80 — calloc-style wrapper (PEB-walk + VirtualAlloc-class hash)
DEFAULT_FREE_RVA = 0x75F10             # FUN_140075f10 — VirtualFree-style wrapper (PEB-walk + hash-resolved call)

PAGE = 0x1000
RETURN_SENTINEL = 0xFFFFFFFFDEAD0000   # unmapped, distinctive; emu_start halts here
HEAP_BASE = 0x0000700000000000
HEAP_SIZE = 0x100000                   # 1 MiB scratch bump-heap — real usage is ~0xC20 bytes total
STACK_BASE = 0x0000780000000000
STACK_SIZE = 0x100000                  # 1 MiB emulated stack


def align_up(value: int, align: int) -> int:
    return (value + align - 1) & ~(align - 1)


class BumpAllocator:
    """Stands in for FUN_140075e80's real VirtualAlloc-class call. The real
    function's own signature is calloc-style: (nmemb, size, &out_ptr,
    &out_size) -> 0 on success. We never need to actually free anything in a
    one-shot emulation, so FUN_140075f10 (the matching free) is stubbed as a
    pure no-op instead of tracked here."""

    def __init__(self, base: int, size: int):
        self.base = base
        self.size = size
        self.cursor = base

    def alloc(self, nbytes: int) -> int:
        nbytes = align_up(max(nbytes, 8), 8)
        if self.cursor + nbytes > self.base + self.size:
            raise RuntimeError(
                f"scratch heap exhausted (requested {nbytes} bytes, "
                f"{self.base + self.size - self.cursor} remaining)"
            )
        ptr = self.cursor
        self.cursor += nbytes
        return ptr


def load_image(uc: Uc, pe: pefile.PE, image_base: int) -> int:
    """Maps the PE's headers and every section at their real RVAs, mirroring
    how the Windows loader would have laid this file out in memory. Mapped
    RWX throughout — this is an isolated emulation sandbox, not a process,
    so there is no security property to preserve by tightening permissions,
    and the cipher's own tables/key/ciphertext all live in sections that
    need to be at least readable+writable regardless."""
    size_of_image = align_up(pe.OPTIONAL_HEADER.SizeOfImage, PAGE)
    uc.mem_map(image_base, size_of_image, UC_PROT_ALL)

    header_data = pe.__data__[: pe.OPTIONAL_HEADER.SizeOfHeaders]
    uc.mem_write(image_base, header_data)

    for section in pe.sections:
        rva = section.VirtualAddress
        raw = section.get_data()  # already zero-padded to VirtualSize by pefile
        if raw:
            uc.mem_write(image_base + rva, raw)

    return size_of_image


def make_alloc_hook(allocator: BumpAllocator, alloc_va: int, verbose: bool):
    def hook(uc: Uc, address: int, size: int, user_data):
        if address != alloc_va:
            return
        nmemb = uc.reg_read(UC_X86_REG_RCX)
        elem_size = uc.reg_read(UC_X86_REG_RDX)
        out_ptr_addr = uc.reg_read(UC_X86_REG_R8)
        out_size_addr = uc.reg_read(UC_X86_REG_R9)
        total = nmemb * elem_size
        ptr = allocator.alloc(total)
        uc.mem_write(ptr, b"\x00" * align_up(max(total, 8), 8))
        uc.mem_write(out_ptr_addr, struct.pack("<Q", ptr))
        uc.mem_write(out_size_addr, struct.pack("<Q", total))
        if verbose:
            print(f"    [alloc hook] {total} bytes -> 0x{ptr:x}", file=sys.stderr)
        uc.reg_write(UC_X86_REG_RAX, 0)  # success
        ret_addr = struct.unpack("<Q", uc.mem_read(uc.reg_read(UC_X86_REG_RSP), 8))[0]
        uc.reg_write(UC_X86_REG_RSP, uc.reg_read(UC_X86_REG_RSP) + 8)
        uc.reg_write(UC_X86_REG_RIP, ret_addr)

    return hook


def make_free_hook(free_va: int, verbose: bool):
    def hook(uc: Uc, address: int, size: int, user_data):
        if address != free_va:
            return
        if verbose:
            ptr = uc.reg_read(UC_X86_REG_RCX)
            print(f"    [free hook] 0x{ptr:x} (no-op)", file=sys.stderr)
        ret_addr = struct.unpack("<Q", uc.mem_read(uc.reg_read(UC_X86_REG_RSP), 8))[0]
        uc.reg_write(UC_X86_REG_RSP, uc.reg_read(UC_X86_REG_RSP) + 8)
        uc.reg_write(UC_X86_REG_RIP, ret_addr)

    return hook


def run_cipher(
    pe_source,
    cipher_func_rva: int,
    key_rva: int,
    key_len: int,
    ciphertext_rva: int,
    ciphertext_len: int,
    alloc_rva: int,
    free_rva: int,
    verbose: bool,
    timeout_seconds: float = 300,
) -> bytes:
    """``pe_source`` is either a filesystem Path (CLI usage) or raw bytes
    (in-process usage, e.g. the karton service, which never touches disk)."""
    pe = pefile.PE(str(pe_source)) if isinstance(pe_source, Path) else pefile.PE(data=pe_source)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    load_image(uc, pe, image_base)

    allocator = BumpAllocator(HEAP_BASE, HEAP_SIZE)
    uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)
    uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)

    func_va = image_base + cipher_func_rva
    alloc_va = image_base + alloc_rva
    free_va = image_base + free_rva
    key_va = image_base + key_rva
    ciphertext_va = image_base + ciphertext_rva

    uc.hook_add(UC_HOOK_CODE, make_alloc_hook(allocator, alloc_va, verbose), begin=alloc_va, end=alloc_va)
    uc.hook_add(UC_HOOK_CODE, make_free_hook(free_va, verbose), begin=free_va, end=free_va)

    # Win64 fastcall ABI: RSP % 16 == 8 at function entry (as if just
    # returned-to by a CALL from a 16-aligned RSP), RSP itself pointing at
    # the return address we'll halt on.
    rsp = align_up(STACK_BASE + STACK_SIZE // 2, 16) - 8
    uc.mem_write(rsp, struct.pack("<Q", RETURN_SENTINEL))

    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.reg_write(UC_X86_REG_RCX, ciphertext_va)     # param_1: buffer (ciphertext in, plaintext out)
    uc.reg_write(UC_X86_REG_RDX, ciphertext_len)    # param_2: length
    uc.reg_write(UC_X86_REG_R8, key_va)             # param_3: key pointer
    uc.reg_write(UC_X86_REG_R9, key_len)            # param_4: key length

    if verbose:
        print(f"  image base   0x{image_base:x}", file=sys.stderr)
        print(f"  cipher func  0x{func_va:x}", file=sys.stderr)
        print(f"  key          0x{key_va:x} ({key_len} bytes)", file=sys.stderr)
        print(f"  ciphertext   0x{ciphertext_va:x} ({ciphertext_len} bytes)", file=sys.stderr)
        print(f"  alloc hook   0x{alloc_va:x}", file=sys.stderr)
        print(f"  free hook    0x{free_va:x}", file=sys.stderr)
        print("  starting emulation...", file=sys.stderr)

    try:
        uc.emu_start(func_va, RETURN_SENTINEL, timeout=int(timeout_seconds * 1_000_000), count=0)
    except UcError as exc:
        rip = uc.reg_read(UC_X86_REG_RIP)
        raise RuntimeError(
            f"emulation faulted at RIP=0x{rip:x}: {exc}. This means either the "
            f"cipher touches memory this harness didn't map, or one of the "
            f"reference addresses (--cipher-func/--alloc/--free) no longer "
            f"matches this build — re-check them against a fresh reverse.md "
            f"before assuming the algorithm itself is wrong."
        ) from exc

    final_rip = uc.reg_read(UC_X86_REG_RIP)
    if final_rip != RETURN_SENTINEL:
        raise RuntimeError(
            f"emulation stopped at RIP=0x{final_rip:x}, not the expected "
            f"return sentinel 0x{RETURN_SENTINEL:x} — likely a timeout or an "
            f"infinite loop in the emulated code; treat the output buffer as "
            f"untrustworthy."
        )

    if verbose:
        print("  emulation completed cleanly", file=sys.stderr)

    return bytes(uc.mem_read(ciphertext_va, ciphertext_len))


@dataclass
class UnpackResult:
    plaintext: bytes
    sha256: str
    md5: str
    size: int
    is_pe: bool
    pe_valid: bool
    addresses: dict


def unpack_data(
    data: bytes,
    cipher_func_rva: int = DEFAULT_CIPHER_FUNC_RVA,
    key_rva: int = DEFAULT_KEY_RVA,
    key_len: int = DEFAULT_KEY_LEN,
    ciphertext_rva: int = DEFAULT_CIPHERTEXT_RVA,
    ciphertext_len: int = DEFAULT_CIPHERTEXT_LEN,
    alloc_rva: int = DEFAULT_ALLOC_RVA,
    free_rva: int = DEFAULT_FREE_RVA,
    verbose: bool = False,
    timeout_seconds: float = 300,
) -> Optional[UnpackResult]:
    """Unpack from raw bytes already in memory — the entry point the karton
    service uses (no temp file needed). Returns ``None`` if ``data`` isn't
    the exact reference build this unpacker targets: unlike this project's
    other unpackers, every address here is pinned to one specific compiled
    build (no signature scan, no per-family generalization attempted yet —
    see README.md), so an exact SHA256 gate is the only honest pre-filter
    until a second confirmed-compatible build exists. :func:`main` (the CLI)
    is a thin wrapper that also accepts a manual-override path and warns
    instead of refusing on a hash mismatch, for exploratory use against an
    unconfirmed sibling build.
    """
    sha256 = hashlib.sha256(data).hexdigest()
    if sha256 != REFERENCE_SHA256:
        return None

    plaintext = run_cipher(
        data,
        cipher_func_rva,
        key_rva,
        key_len,
        ciphertext_rva,
        ciphertext_len,
        alloc_rva,
        free_rva,
        verbose,
        timeout_seconds,
    )

    is_mz = plaintext[:2] == b"MZ"
    pe_valid = False
    if is_mz:
        try:
            recovered = pefile.PE(data=plaintext, fast_load=True)
            recovered.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            pe_valid = True
        except Exception:  # noqa: BLE001 - "not a valid PE" is a result, not a crash
            pe_valid = False

    return UnpackResult(
        plaintext=plaintext,
        sha256=hashlib.sha256(plaintext).hexdigest(),
        md5=hashlib.md5(plaintext).hexdigest(),
        size=len(plaintext),
        is_pe=is_mz and pe_valid,
        pe_valid=pe_valid,
        addresses={
            "cipher_func_rva": hex(cipher_func_rva),
            "key_rva": hex(key_rva),
            "key_len": key_len,
            "ciphertext_rva": hex(ciphertext_rva),
            "ciphertext_len": ciphertext_len,
            "alloc_rva": hex(alloc_rva),
            "free_rva": hex(free_rva),
        },
    )


def describe_payload(payload: bytes) -> dict:
    """Small PE summary for logs / config reporting."""
    info: dict = {}
    try:
        p = pefile.PE(data=payload, fast_load=True)
        info["machine"] = hex(p.FILE_HEADER.Machine)
        info["subsystem"] = p.OPTIONAL_HEADER.Subsystem
        info["entry_point"] = hex(p.OPTIONAL_HEADER.AddressOfEntryPoint)
        info["image_base"] = hex(p.OPTIONAL_HEADER.ImageBase)
        info["timestamp"] = hex(p.FILE_HEADER.TimeDateStamp)
        info["sections"] = [s.Name.rstrip(b"\x00").decode("ascii", "replace") for s in p.sections]
    except Exception as exc:  # noqa: BLE001
        info["error"] = str(exc)
    return info


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Emulation-based decryptor for the 5541bf99...8630c crypter's stage-2 cipher."
    )
    parser.add_argument("sample_path", type=Path, help="Path to the packed sample (PE32+ EXE)")
    parser.add_argument("-o", "--output", type=Path, default=None, help="Output file for the recovered buffer (default: <sample>_stage2.bin)")
    parser.add_argument("--cipher-func-rva", type=lambda x: int(x, 0), default=DEFAULT_CIPHER_FUNC_RVA)
    parser.add_argument("--key-rva", type=lambda x: int(x, 0), default=DEFAULT_KEY_RVA)
    parser.add_argument("--key-len", type=lambda x: int(x, 0), default=DEFAULT_KEY_LEN)
    parser.add_argument("--ciphertext-rva", type=lambda x: int(x, 0), default=DEFAULT_CIPHERTEXT_RVA)
    parser.add_argument("--ciphertext-len", type=lambda x: int(x, 0), default=DEFAULT_CIPHERTEXT_LEN)
    parser.add_argument("--alloc-rva", type=lambda x: int(x, 0), default=DEFAULT_ALLOC_RVA)
    parser.add_argument("--free-rva", type=lambda x: int(x, 0), default=DEFAULT_FREE_RVA)
    parser.add_argument("--save-config", type=Path, default=None, help="Write the addresses/hashes used to a JSON file")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if not args.sample_path.is_file():
        print(f"error: {args.sample_path} does not exist", file=sys.stderr)
        return 1

    sample_bytes = args.sample_path.read_bytes()
    sample_sha256 = hashlib.sha256(sample_bytes).hexdigest()

    using_defaults = (
        args.cipher_func_rva == DEFAULT_CIPHER_FUNC_RVA
        and args.key_rva == DEFAULT_KEY_RVA
        and args.ciphertext_rva == DEFAULT_CIPHERTEXT_RVA
    )
    if using_defaults and sample_sha256 != REFERENCE_SHA256:
        print(
            f"warning: input hash {sample_sha256} does not match the reference "
            f"build {REFERENCE_SHA256} this tool's default addresses were "
            f"pinned against. Proceeding anyway, but a different build's "
            f"cipher entry point / key / ciphertext addresses will very "
            f"likely differ — pass --cipher-func-rva/--key-rva/--ciphertext-rva "
            f"explicitly once they're known for this build, or expect the "
            f"emulation to fault or produce garbage.",
            file=sys.stderr,
        )

    try:
        plaintext = run_cipher(
            args.sample_path,
            args.cipher_func_rva,
            args.key_rva,
            args.key_len,
            args.ciphertext_rva,
            args.ciphertext_len,
            args.alloc_rva,
            args.free_rva,
            args.verbose,
        )
    except Exception as exc:  # noqa: BLE001 - surface any failure with full context
        print(f"error: {exc}", file=sys.stderr)
        return 1

    output_path = args.output or args.sample_path.with_name(args.sample_path.stem + "_stage2.bin")
    output_path.write_bytes(plaintext)

    is_mz = plaintext[:2] == b"MZ"
    plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()
    print(f"wrote {len(plaintext)} bytes to {output_path}")
    print(f"recovered-buffer SHA256: {plaintext_sha256}")

    pe_valid = False
    if is_mz:
        try:
            recovered = pefile.PE(data=plaintext, fast_load=True)
            recovered.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            pe_valid = True
            print(
                f"MZ/PE header present and parses cleanly — "
                f"machine=0x{recovered.FILE_HEADER.Machine:x}, "
                f"entrypoint RVA=0x{recovered.OPTIONAL_HEADER.AddressOfEntryPoint:x}, "
                f"sections={recovered.FILE_HEADER.NumberOfSections}"
            )
        except Exception as exc:  # noqa: BLE001
            print(f"MZ header present but PE parsing failed: {exc}")

    if args.save_config:
        config = {
            "source_sha256": sample_sha256,
            "cipher_func_rva": hex(args.cipher_func_rva),
            "key_rva": hex(args.key_rva),
            "key_len": args.key_len,
            "ciphertext_rva": hex(args.ciphertext_rva),
            "ciphertext_len": args.ciphertext_len,
            "alloc_rva": hex(args.alloc_rva),
            "free_rva": hex(args.free_rva),
            "recovered_sha256": plaintext_sha256,
            "recovered_is_mz": is_mz,
            "recovered_pe_valid": pe_valid,
        }
        args.save_config.write_text(json.dumps(config, indent=2))
        if args.verbose:
            print(f"  wrote config to {args.save_config}", file=sys.stderr)

    if is_mz and pe_valid:
        return 0
    if is_mz:
        return 2
    print("recovered buffer is NOT MZ-headed — treat as a failed/incorrect decryption", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
