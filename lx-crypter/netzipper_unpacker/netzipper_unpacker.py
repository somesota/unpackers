"""netzipper_unpacker — extract the ZIP payload from a NetZipper-wrapped .NET sample.

NetZipper is the outer wrapper of the IBar2Double family. It has no cipher.
It carries the payload as a ZIP in a .NET manifest resource (e.g. `22.exe`),
extracts it with `ZipFile.ExtractToDirectory` and starts it with `Process.Start`.
This tool pulls that ZIP out and writes its files.

It is independent of `curvefish_unpacker`, which handles the other delivery path
(a Threefish-256-CBC blob embedded as a Base91 string). Neither tool needs the other.

How to recognise a build: the PDB path contains `LX_CRYPTER\\Temp\\<token>\\`,
with a new random token per build.

Reference samples:
  SHA-256  20082d2052d2d406bb4193990d933dc9b78bf2ccc3f2618144ada1fb7e0a995e
           32-bit stage-2 sample, build `LX_S0C00pWGHy5bmOt`
  SHA-256  64acf136e30d15f4ff8fe0eee978d30c249d28ca7578cf60d138aa79cb4e7632
           64-bit sibling that delivers `22.exe`, build `LX_KK050mhlf5`
  Chain    CryptOne -> GCleaner PPI -> GCleaner update DLL -> IBar2Double

Usage:
  python netzipper_unpacker.py <sample_path> [-o output_dir] [-v]
"""

from __future__ import annotations

import argparse
import hashlib
import io
import logging
import sys
import zipfile  # stdlib: opens the ZIP payload from the resource bytes
from dataclasses import dataclass
from pathlib import Path

import dnfile  # parses .NET metadata; `pe.net.resources` lists the manifest resources

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROCESSING_NAME = "netzipper_unpacker"
VERSION = 2  # v2: renamed from ibar2double_unpacker.py to correctly identify
             # this as the NetZipper (not CryptoObfuscator) delivery layer.
             # No functional change -- ZIP extraction only, same as before.

logger = logging.getLogger(PROCESSING_NAME)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ExtractedPayload:
    """Result of extracting a payload from the sample."""
    member_name: str
    data: bytes
    sha256: str
    md5: str
    size: int
    source_resource: str


# ---------------------------------------------------------------------------
# .NET manifest resource enumeration
# ---------------------------------------------------------------------------

def get_raw_resources(pe: dnfile.dnPE) -> list[tuple[str, bytes]]:
    """Return (name, data) pairs for all embedded manifest resources.

    Uses ``pe.net.resources`` which parses the ManifestResource metadata
    table and reads data from the CLR Resources directory (fields
    ``pe.net.struct.ResourcesRva`` / ``ResourcesSize``).  Each embedded
    resource entry is prefixed with a 4-byte LE length in the CLR section;
    dnfile handles this transparently.

    Resources whose data was parsed into a ``ResourceSet`` (i.e. .resources
    files used for WinForms localization) are skipped — we only want raw
    binary blobs (ZIPs, DLLs, etc.).
    """
    results: list[tuple[str, bytes]] = []

    # A native (non-.NET) PE parses fine under dnfile but has no CLR metadata,
    # so pe.net is None and pe.net.resources would raise AttributeError. This
    # is the common case (most runnable samples are native) — an NetZipper
    # sample is always .NET — so decline cleanly instead of crashing the task.
    if getattr(pe, "net", None) is None:
        logger.info("no .NET/CLR metadata — not an NetZipper (.NET) sample")
        return results

    clr_resources = pe.net.resources
    if not clr_resources:
        logger.warning("pe.net.resources is empty — no embedded manifest resources")
        return results

    for rsrc in clr_resources:
        name = str(rsrc.name)
        data = rsrc.data

        # After InternalResource.parse(), .data is either raw bytes
        # or a ResourceSet object (for *.resources files).  We want bytes.
        if isinstance(data, bytes):
            results.append((name, data))
            logger.debug("Raw resource: %-55s  %d bytes", name, len(data))
        else:
            logger.debug("Skipping ResourceSet: %s", name)

    logger.info("Found %d raw embedded resources (out of %d total)",
                len(results), len(clr_resources))
    return results


# ---------------------------------------------------------------------------
# ZIP payload extraction
# ---------------------------------------------------------------------------

def find_zip_resources(resources: list[tuple[str, bytes]]) -> list[tuple[str, bytes]]:
    """Filter raw resources that are ZIP archives.

    Detection: name ends with ``.zip`` OR data starts with PK\\x03\\x04.
    """
    zips: list[tuple[str, bytes]] = []
    for name, data in resources:
        is_zip_name = name.lower().endswith(".zip")
        is_zip_magic = len(data) >= 4 and data[:4] == b"PK\x03\x04"

        if is_zip_name or is_zip_magic:
            zips.append((name, data))
            logger.info("ZIP resource: '%s' (%d bytes, name=%s, magic=%s)",
                        name, len(data), is_zip_name, is_zip_magic)

    if not zips:
        logger.warning("No ZIP resources found among %d raw resources", len(resources))

    return zips


def extract_zip_payloads(zip_resources: list[tuple[str, bytes]],
                         output_dir: Path) -> list[ExtractedPayload]:
    """Extract all members from ZIP resources to disk.

    Returns a list of ``ExtractedPayload`` with hashes for each extracted file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    payloads: list[ExtractedPayload] = []

    for res_name, res_data in zip_resources:
        try:
            zf = zipfile.ZipFile(io.BytesIO(res_data))
        except zipfile.BadZipFile as exc:
            logger.error("Resource '%s' is not a valid ZIP: %s", res_name, exc)
            continue

        for member_info in zf.infolist():
            if member_info.is_dir():
                continue

            member_data = zf.read(member_info.filename)
            sha256 = hashlib.sha256(member_data).hexdigest()
            md5 = hashlib.md5(member_data).hexdigest()

            out_path = output_dir / member_info.filename
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(member_data)

            payload = ExtractedPayload(
                member_name=member_info.filename,
                data=member_data,
                sha256=sha256,
                md5=md5,
                size=len(member_data),
                source_resource=res_name,
            )
            payloads.append(payload)
            logger.info("Extracted: %-20s  %d bytes  SHA-256=%s",
                        member_info.filename, len(member_data), sha256)

        zf.close()

    return payloads


# ---------------------------------------------------------------------------
# Main unpacker pipeline
# ---------------------------------------------------------------------------

def unpack(filepath: str | Path, output_dir: str | Path | None = None) -> list[ExtractedPayload]:
    """Run the NetZipper ZIP-extraction path on a sample.

    Extracts a ZIP archive delivered as a manifest resource (e.g. containing
    ``22.exe``).

    Args:
        filepath: Path to the NetZipper-wrapped .NET PE sample.
        output_dir: Directory for extracted payloads.  Defaults to
                     ``<sample_dir>/unpacked/``.

    Returns:
        List of extracted payloads with hashes.
    """
    filepath = Path(filepath)
    if not filepath.is_file():
        logger.error("Sample not found: %s", filepath)
        return []

    if output_dir is None:
        output_dir = filepath.parent / "unpacked"
    output_dir = Path(output_dir)

    logger.info("netzipper_unpacker v%d — processing %s", VERSION, filepath.name)
    logger.info("Output directory: %s", output_dir)

    # Step 1: Parse .NET PE
    try:
        pe = dnfile.dnPE(str(filepath))
    except Exception as exc:
        logger.error("Failed to parse PE: %s", exc)
        return []

    # Step 2: Enumerate embedded manifest resources (raw bytes only)
    resources = get_raw_resources(pe)
    if not resources:
        logger.error("No raw embedded resources found — is this an NetZipper sample?")
        return []

    # Step 3: Find ZIP resources
    zip_resources = find_zip_resources(resources)
    if not zip_resources:
        logger.error("No ZIP payload found in manifest resources")
        return []

    # Step 4: Extract ZIP contents
    payloads = extract_zip_payloads(zip_resources, output_dir)

    # Summary
    if payloads:
        logger.info("--- Extraction complete ---")
        for p in payloads:
            logger.info("  %-20s  %d bytes  SHA-256 %s  MD5 %s",
                        p.member_name, p.size, p.sha256, p.md5)
    else:
        logger.warning("No payloads extracted from ZIP resources")

    return payloads


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="netzipper_unpacker — extract embedded ZIP payloads from "
                    "NetZipper-wrapped .NET loaders",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("sample", help="Path to the NetZipper-wrapped .NET PE sample")
    parser.add_argument("-o", "--output", default=None,
                        help="Output directory for extracted payloads "
                             "(default: <sample_dir>/unpacked/)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(name)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    payloads = unpack(args.sample, args.output)

    if not payloads:
        logger.error("Unpacking failed — no payloads extracted")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
