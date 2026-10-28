"""CPE helpers. Nmap reports CPE 2.2 URIs ('cpe:/a:apache:http_server:2.2.8');
the NVD API wants CPE 2.3 formatted strings."""
from __future__ import annotations

import re


def to_cpe23(cpe: str) -> str | None:
    """Convert a CPE 2.2 URI (or pass a 2.3 string through) to 11-field CPE 2.3."""
    cpe = (cpe or "").strip()
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")[2:]
    elif cpe.startswith("cpe:/"):
        parts = cpe[len("cpe:/"):].split(":")
    else:
        return None
    if len(parts) < 3 or parts[0] not in ("a", "o", "h"):
        return None
    parts = [p or "*" for p in parts][:11]
    parts += ["*"] * (11 - len(parts))
    return "cpe:2.3:" + ":".join(parts)


def usable_cpe(cpe: str) -> str | None:
    """Return a CPE 2.3 string fit for a CVE lookup, or None.

    Requirements:
    - application CPE (part 'a');
    - a concrete version: an unversioned CPE would match every CVE of the product;
    - distro suffixes are stripped from the version ('5.0.51a-3ubuntu5' -> '5.0.51a'),
      because NVD knows upstream versions only.
    """
    cpe23 = to_cpe23(cpe)
    if cpe23 is None:
        return None
    parts = cpe23.split(":")          # ['cpe','2.3',part,vendor,product,version,...]
    if parts[2] != "a":
        return None
    version = re.split(r"[-~+]", parts[5], maxsplit=1)[0]
    if version in ("", "*", "-"):
        return None
    parts[5] = version
    return ":".join(parts)
