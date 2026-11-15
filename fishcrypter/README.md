# fishcrypter_unpacker

Offline decryptor for the stage-3 PE embedded in an IBar2Double-chain host loader
reference samples: 
- `22.exe`, SHA-256 `64acf136e30d15f4ff8fe0eee978d30c249d28ca7578cf60d138aa79cb4e7632`. 
- `1TEST.file`, SHA256 `20082d2052d2d406bb4193990d933dc9b78bf2ccc3f2618144ada1fb7e0a995e` 

---

## Unpacking Process


Base91-encoded, Threefish-256-CBC-encrypted blob in a hardcoded string literal
inside `BigFloat.ParseWithBigInt`. At runtime it loads `LfdReader.dll` (70 KB,
embedded manifest resource), passes the blob and a hardcoded password to
`IBar2Double.ADXPlot.Benchmark()`, and gets back the stage-3 PE byte array which is
then injected into `MSBuild.exe`.

This tool reproduces that pipeline offline:

```
Base91.Decode(ciphertext)                      [91-char alphabet, no hyphen — see below]
  -> parse header: salt / IV / ciphertext payload
  -> PBKDF2-HMAC-SHA1(password, salt, iters, dklen) -> raw_key
  -> SHA-256(raw_key)
  -> Donna32.Harden(...)                        [custom curve25519 field-arithmetic step]
  -> X25519 scalar-base-mult -> X25519 DH self-agreement
  -> SHA-256(...) -> 32-byte Threefish-256 key
  -> Threefish-256-CBC decrypt
  -> PKCS7 unpad
  -> stage3.exe
```

---

## Prerequisites

```
pip install 'dnfile>=0.15.0' 'pycryptodome>=3.18.0'
```

---

## Usage

### Normal usage — just point it at 22.exe



```bash
python fishcrypter_unpacker.py 22.exe -o stage3.exe --save-config config.json
```

That's the whole workflow. On success it writes `stage3.exe` and logs:
```
Status:  PE recovered (starts with 'MZ')
SHA-256: <hash>
```

`config.json` records everything about the run *except* the ciphertext itself:
source file hashes, the extracted password, every Threefish parameter, and the
stage-3 result hash. The ciphertext (~277K characters) is deliberately **not**
persisted.

**How the extraction works** (pure PE/metadata parsing via `dnfile`, no IL
disassembly): `LfdReader.dll` is pulled straight out of `22.exe`'s own embedded
manifest resources. The ciphertext and password are both ordinary string literals
sitting in `22.exe`'s shared `#US` (user-string) metadata heap — found by anchoring
on the literal string `"Benchmark"` (the method name looked up via reflection in
the real code path): the password is the closest short, whitespace-free printable
string *before* that anchor in heap order, and the ciphertext is the **longest**
pure-Base91-alphabet string *after* it.

**Why not just grab the longest Base91-looking string?** The reference sample
carries a **decoy** — a second string in the heap, also composed entirely of valid
Base91 characters, 75,021 characters long vs. the real ciphertext's 277,141.
Almost certainly deliberate anti-analysis noise aimed at exactly that naive
heuristic. The `"Benchmark"`-anchor approach skips it here — but note what the
anchor actually buys: it restricts the "longest" choice to strings *after* the
anchor, so a future build whose decoy sits after the anchor **and** is longer than
the real ciphertext would still be picked wrongly. Every pure-Base91 candidate
found is logged (at warning level, no `-v` needed) whenever there is more than
one, so the choice can be sanity-checked if extraction ever looks off.

If the payload length isn't a multiple of the Threefish block size (32 bytes), the
tool raises an error instead of silently trimming — that has always turned out to
mean the Base91 decode produced the wrong byte count (usually a wrong alphabet),
not a real trailing-byte situation.

### What ends up in config.json

```json
{
  "source_host_file": {"path": "...", "sha256": "...", "size": 934912},
  "lfdreader_dll": {"sha256": "...", "size": 70656},
  "ciphertext_len": 277141,
  "password": "QPXqI*MRQO7%#XNH5MCE*#bC",
  "threefish_params": { "...": "every Threefish parameter, see config.json.template" },
  "stage3": {"sha256": "...", "md5": "...", "size": 225280, "looks_like_pe": true}
}
```

---

## Custom password, or a variant where automatic extraction doesn't apply

Override the extracted password with `--password`:

```bash
python fishcrypter_unpacker.py 22.exe --password "MY_NEW_PASSWORD" -o stage3_variant.exe
```

A different build may also use a different Base91 alphabet or different constant
byte offsets — don't assume this sample's values carry over automatically. What
the tool re-derives per sample and what it hardcodes are different things:

| Value | Where it comes from |
|---|---|
| Threefish parameters (salt/IV offsets, PBKDF2 iters/dklen, payload arithmetic) | Re-derived from the sample's own `LfdReader.dll` every run, via `crypto_obfuscator` |
| Ciphertext, password | Extracted from the sample's `#US` heap every run (anchor-based, see above) |
| Base91 alphabet | **Hardcoded** (`_BASE91_ALPHABET`). Derived once by a `dnfile` `FieldRva` read of this build's `Base91.DecTab`; the tool does not re-read it per sample |
| Fallback password | **Hardcoded** (`HARDCODED_PASSWORD`), used only on the fallback path below and in manual mode |

If the `"Benchmark"` anchor isn't found (e.g. that method got renamed too), the
tool does **not** stop: it falls back to "longest pure-Base91 string in the whole
heap" plus the hardcoded password — i.e. exactly the naive heuristic the decoy
above is built to defeat — and logs two warnings saying so. Treat a run that took
that path as unverified: check the warnings, and use the manual mode below to
supply the ciphertext and `--password` by hand if the result looks wrong.

## Manual/advanced mode

For workflows where you already have `LfdReader.dll` and/or a ciphertext string
separately (or automatic extraction from a variant fails and you need to supply a
piece by hand), the original two-step, lower-level interface is still available:

```bash
# 1) Extract constants from a standalone LfdReader.dll
python fishcrypter_unpacker.py \
    --extract-constants LfdReader.dll \
    --save-config config.json

# 2) Decrypt using a ciphertext obtained some other way
python fishcrypter_unpacker.py \
    -c config.json \
    --ciphertext-file ciphertext.txt \
    -o stage3.exe

# Or pass the Base91 string directly on the command line
python fishcrypter_unpacker.py \
    -c config.json \
    --ciphertext ":{pHKUAm27..." \
    -o stage3.exe

# Or from an already-decoded binary (e.g. from a hex dump or CAPE artifact)
python fishcrypter_unpacker.py \
    -c config.json \
    --ciphertext-file cipher.bin \
    -o stage3.exe
```

If you need to pull the ciphertext string by hand for some reason: it's a large
(**~277,000 characters** for the reference sample — not the ~8 KB originally
estimated) Base91 literal in `BigFloat.ParseWithBigInt`, starting
`:{pHKUAm27ZvY/E4Xf*gVfS%W{|iEtFb...`. In `#US` heap order it sits *after* the
`"Benchmark"` anchor, which in turn follows the `QPXqI*MRQO7%#XNH5MCE*#bC`
password literal — password, anchor, then ciphertext. Via RePython-NET,
`pythonnet_search_string` retrieves it in full — but `pythonnet_decompile_method`'s
C#-source rendering path has been observed to silently truncate very long string
literals (inserting a `[...string is too long...]` marker), so don't use that path
for this specifically; cross-check the extracted length against the `ldstr`
operand's length via `pythonnet_get_opcodes` if in doubt.

---

## Debug mode

Add `-v` / `--verbose` to see all intermediate values (salt hex, IV hex, and every
key-derivation stage's output; block-by-block cipher progress is deliberately not
logged, for performance). The list of Base91-looking heap candidates is logged
without `-v`, at warning level:

```bash
python fishcrypter_unpacker.py 22.exe -o out.exe -v
```

---

## Algorithm notes

### `IBar2Double&&` / `IBar2Double%` resource stream format
The obfuscated-resource decoder (`A.ResourceObfuscator_DesDeflateDecoder
.DecodeProtectedResourceStream`, IL-confirmed) is generic and reused for at least
two layers of nesting:

```
[0:3]     3 bytes discarded (loop i=1; i<4; i++ -> Read one byte each)
[3:4]     1 byte, stored bitwise-inverted; real_flags = ~stored & 0xFF
          (NOT a 2-byte ushort — IL shows a single-byte read, only the low
          byte of the inverted value is ever tested)
if (real_flags & 2):
  [4:12]  8-byte DES IV   (if all-zero, the malware replaces it with a
          PublicKeyToken-derived value — this tool only logs that case, it does
          not implement the fallback; no build has needed it so far)
  [12:20] 8-byte DES key  (set on DESCryptoServiceProvider.Key)
  [20..]  DES-CBC encrypted body — starts immediately here, NO stored offset field.
if (real_flags & 8):
  DeflateStream(decrypted_body, CompressionMode.Decompress) -> payload bytes
```

Decoding `IBar2Double&&` this way does **not** yield a flat constant table — it
yields a complete, loadable, strong-name-signed .NET assembly (a nested
"ResourceAssembly", a CryptoObfuscator-style resource-protection artifact). That
assembly embeds two further manifest resources: `IBar2Double%` (the real flat
int32/int64/etc. constant table, decoded with this exact same routine and byte
layout again) and `IBar2Double$` (a small string table, same routine).
`IBar2Double*` (method-body encryption) may also be present but is not exercised
on this code path.

### Key/IV assignment — the reverse of what naive IL tracing suggests
Empirically verified (not just IL-read): the first 8-byte field after the header
is the DES **IV**, the second is the DES **key** — the reverse of what naive IL
call-order tracing on the two structurally-identical setter-proxy delegates
suggests (they're indistinguishable `MulticastDelegate` wrappers by shape alone).
Confirmed by landing on the exact standard Threefish `C240` constant byte-for-byte
after decoding a second resource layer down with this assignment, and by the full
pipeline successfully decrypting real ciphertext to a valid PE.

### Base91 alphabet — NOT the plain reference alphabet
This build's compiled-in `Base91.DecTab` — read once out of the PE via `dnfile`'s
`FieldRva` table rather than assumed, then baked into the tool as
`_BASE91_ALPHABET` (it is not re-read per sample) — is the standard basE91
alphabet **with the `-` (hyphen) removed** — 91 characters, not 92:

```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"
```

An earlier version of this tool carried the 92-character alphabet (hyphen
included); that extra character silently shifts the decoded *value* of every
character from `.` onward by one, desynchronizing the bit-accumulator. The result
was a decoded byte count that was consistently, non-obviously wrong (not
block-aligned to 32 bytes) with **no decode error raised at any point** — this was
the single hardest bug in this tool to find, because everything else (offsets, DES
key/IV, key derivation) could be independently correct and it would still fail. If
a future build turns out to use yet another permutation, re-extract it the same
way (dnfile `FieldRva` read of the `Base91.DecTab` field, sorted by decoded value)
rather than guessing.

### The Threefish key is NOT plain SHA-256(PBKDF2(...))
`ADXPlot.Benchmark` calls a single method (`BuildThreefishKey_X25519Hardened`,
IL-confirmed) that additionally runs the SHA-256(PBKDF2) output through a custom
curve25519 field-arithmetic transform (`Donna32.Harden` — **not** an RFC 7748
scalar clamp, despite superficially playing the same role), then an X25519
scalar-base-multiplication and a self-Diffie-Hellman agreement (both of which apply
the *real* RFC 7748 clamp internally, inside `curve25519_mult` itself — easy to
miss since `Harden` looks like it should be "the" clamp step and isn't), and
finally one more SHA-256 over the raw DH output. Every one of these five sub-steps
(PBKDF2, SHA-256, Harden, X25519×2, final SHA-256) has to be present and in the
right order — this tool's Curve25519 implementation (`x25519_scalarmult`,
`donna32_harden`) is a from-scratch pure-Python reimplementation, not a call into a
generic X25519 library, specifically because a generic library's own clamp would
double-apply / misapply relative to `Harden`'s output.

### PBKDF2 PRF
.NET `Rfc2898DeriveBytes` without an explicit `HashAlgorithmName` parameter uses
**HMAC-SHA1** as the PRF (not SHA-256). This tool correctly uses
`hashlib.pbkdf2_hmac("sha1", ...)` for the PBKDF2 step.

### Threefish-256 key schedule
Standard zero-tweak Threefish-256: 4-word key extended with a 5th word
`C240 ^ k0 ^ k1 ^ k2 ^ k3` (C240 = `0x1BD11BDAA9FC1A22`), 19 subkeys, standard
rotation constants from Skein v1.3 Table 3. This part was correct from the start
and needed no changes — only the *key* fed into it was wrong.

### Exit codes
- `0` — success, output starts with `MZ`
- `1` — error (bad config, missing input, decryption exception)
- `2` — decrypted but output does NOT start with `MZ` (wrong params or corrupt input)

---

## Files

| File | Description |
|---|---|
| `fishcrypter_unpacker.py` | Main script — the stage-3 cipher (layer 3) |
| `crypto_obfuscator.py` | Internal dependency, no CLI of its own — layer 2, defeats CryptoObfuscator's protection on `LfdReader.dll` to produce this tool's `ThreefishParams` |
| `requirements.txt` | Python dependencies |
| `config.json.template` | Template config for manual `--extract-constants` mode |
| `README.md` | This file |

---

## Reference sample

| Field | Value |
|---|---|
| SHA-256 (22.exe) | `64acf136e30d15f4ff8fe0eee978d30c249d28ca7578cf60d138aa79cb4e7632` |
| SHA-256 (LfdReader.dll) | `2f11f4c64635677b83d5452a1ab385c0bd24feca1b678d1c2ed26297325dc849` |
| SHA-256 (recovered stage-3) | `a0889124e151d08725f6ffe9b84b274cf157cc52ca305f9b66aa228ddb30ba7e` |
| Family | IBar2Double Stage-2 loader (`mixthree` campaign) |
| Hardcoded password | `QPXqI*MRQO7%#XNH5MCE*#bC` |
| Ciphertext prefix | `:{pHKUAm27ZvY/E4Xf*gVfS%W{|iEtFb...` (277,141 chars Base91) |
| Helper DLL | `LfdReader.dll` (70,656 bytes, embedded manifest resource; internal module name `IBar2Double.dll`) |
| Decryption entry | `IBar2Double.ADXPlot.Benchmark(string, string)` |
| Recovered stage-3 type | PE32+ (x86-64), GUI subsystem, 4 sections, 225,280 bytes, native imports only (KERNEL32/USER32/ADVAPI32/GDI32/OLE32/OLEAUT32). What it *is* is out of scope for this tool — see its own report in `malware-kb/reports/a0889124e151d08725f6ffe9b84b274cf157cc52ca305f9b66aa228ddb30ba7e/` |
| Injection target | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe` |
| Stage-3 entry | `R4.Hollow::Run(byte[], string)` |
