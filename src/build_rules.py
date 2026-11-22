#!/usr/bin/env python3
"""Build native Egern rule sets (rules/*.yaml) from the classical lists in config/rules.json."""

import argparse
import ipaddress
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config" / "rules.json"
RULE_DIR = ROOT / "rules"

FIELDS = {
    "DOMAIN": "domain_set",
    "DOMAIN-SUFFIX": "domain_suffix_set",
    "DOMAIN-KEYWORD": "domain_keyword_set",
    "DOMAIN-WILDCARD": "domain_wildcard_set",
    "DOMAIN-REGEX": "domain_regex_set",
    "IP-CIDR": "ip_cidr_set",
    "IP-CIDR6": "ip_cidr6_set",
    "IP-ASN": "asn_set",
}
IP_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN"}
IGNORED_TYPES = {"PROCESS-NAME"}


class BuildError(RuntimeError):
    pass


def convert(text, name, skip_types=()):
    """Convert classical `TYPE,VALUE[,options]` lines to an Egern rule set; return (rules, skipped)."""
    fields, skipped, no_resolve = {}, {}, set()
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "//", ";")):
            continue
        where = f"{name}:{number}: {line!r}"
        kind, _, rest = (part.strip() for part in line.partition(","))
        kind = kind.upper()
        if kind in IGNORED_TYPES or kind in skip_types:
            skipped[kind] = skipped.get(kind, 0) + 1
            continue
        if kind not in FIELDS:
            raise BuildError(f"{where}: unsupported rule type {kind}")
        # A regex may contain commas, so it takes the rest of the line and has no options.
        value, *options = [rest] if kind == "DOMAIN-REGEX" else [p.strip() for p in rest.split(",")]
        if not value:
            raise BuildError(f"{where}: missing value")
        if any(option != "no-resolve" for option in options) or (options and kind not in IP_TYPES):
            raise BuildError(f"{where}: unsupported options {options}")
        field = FIELDS[kind]
        if kind in ("IP-CIDR", "IP-CIDR6"):
            try:
                version = ipaddress.ip_network(value, strict=False).version
            except ValueError:
                raise BuildError(f"{where}: invalid IP network") from None
            if kind == "IP-CIDR6" and version != 6:
                raise BuildError(f"{where}: IP-CIDR6 with an IPv4 network")
            field = "ip_cidr6_set" if version == 6 else "ip_cidr_set"  # Bett writes IPv6 as IP-CIDR.
        elif kind == "IP-ASN" and not re.fullmatch(r"(?:AS)?\d+", value, re.IGNORECASE):
            raise BuildError(f"{where}: invalid ASN")
        if kind == "IP-ASN":
            value = re.sub(r"^AS", "", value, flags=re.IGNORECASE)  # Egern expects bare digits.
        if kind in IP_TYPES:
            no_resolve.add("no-resolve" in options)
        fields.setdefault(field, {})[value] = None  # dict keeps first-occurrence order, drops duplicates
    if not fields:
        raise BuildError(f"{name}: no rules left after conversion")
    if len(no_resolve) > 1:
        raise BuildError(f"{name}: some IP rules use no-resolve and some do not")
    rules = {field: list(values) for field, values in fields.items()}
    if no_resolve == {True}:
        rules["no_resolve"] = True
    return rules, skipped


def resolve(entry, sources):
    """Return (url, skip_types) for a manifest entry: "prefix:path", a full URL, or {"source": ..., "skip_types": [...]}."""
    options = entry if isinstance(entry, dict) else {"source": entry}
    source = options["source"]
    prefix, _, path = source.partition(":")
    if prefix in sources:
        url = sources[prefix]["base"] + urllib.parse.quote(path)  # quotes "@" and "!" in Bett names
        skip = sources[prefix].get("skip_types", [])
    elif source.startswith("https://"):
        url, skip = source, []
    else:
        raise BuildError(f"Unknown source {source!r}")
    return url, set(options.get("skip_types", skip))


def download(url):
    request = urllib.request.Request(url, headers={"User-Agent": "egern-rules-builder/2"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read().decode("utf-8-sig")
    except urllib.error.HTTPError as exc:
        raise BuildError(f"Download failed: {url}: HTTP {exc.code} {exc.reason}") from None
    except urllib.error.URLError as exc:
        raise BuildError(f"Download failed: {url}: {exc.reason}") from None


def dump(rules):
    return yaml.safe_dump(rules, allow_unicode=True, sort_keys=False, width=1000).encode("utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", nargs="+", metavar="NAME", help="build only these files (with or without .yaml)")
    parser.add_argument("--check", action="store_true", help="exit 1 if any output would change; write nothing")
    args = parser.parse_args(argv)

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    entries = manifest["rules"]
    if args.only:
        wanted = [name if name.endswith(".yaml") else name + ".yaml" for name in args.only]
        missing = [name for name in wanted if name not in entries]
        if missing:
            raise BuildError(f"Not in manifest: {', '.join(missing)}")
        entries = {name: entries[name] for name in wanted}

    outputs = {}  # convert everything before touching rules/
    for filename, entry in entries.items():
        url, skip_types = resolve(entry, manifest["sources"])
        rules, skipped = convert(download(url), filename, skip_types)
        outputs[filename] = dump(rules)
        counts = ", ".join(f"{k}={len(v)}" for k, v in rules.items() if isinstance(v, list))
        extra = "".join(f", skipped {k}={n}" for k, n in skipped.items())
        flag = ", no_resolve" if rules.get("no_resolve") else ""
        print(f"{filename}: {counts}{flag}{extra}", flush=True)

    changed = [name for name, data in outputs.items()
               if not (RULE_DIR / name).is_file() or (RULE_DIR / name).read_bytes() != data]
    if args.check:
        print(f"{len(changed)} of {len(outputs)} files would change: {', '.join(changed) or '-'}")
        return 1 if changed else 0
    RULE_DIR.mkdir(exist_ok=True)
    for name in changed:
        (RULE_DIR / name).write_bytes(outputs[name])
    print(f"Wrote {len(changed)} of {len(outputs)} files.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BuildError as exc:
        sys.exit(f"error: {exc}")
