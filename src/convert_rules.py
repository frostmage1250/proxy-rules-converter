#!/usr/bin/env python3
"""Convert reviewed upstream rules without deleting, replacing, or reordering them."""

from __future__ import annotations

import argparse
import collections
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCES = ROOT / "config" / "sources.json"
DEFAULT_STEAM_ALLOWLIST = ROOT / "config" / "steam-cn-download-allowlist.txt"
USER_AGENT = (
    "rules-converter-action/2.0 "
    "(+https://github.com/frostmage1250/proxy-rules-converter)"
)
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$", re.I)
STATIC_OUTPUTS = frozenset({"dist/shadowrocket/bilibili-pcdn.list"})
EXTERNALLY_MANAGED_OUTPUTS = frozenset(
    {
        "dist/mihomo/geolocation-cn.list",
        "dist/shadowrocket/geolocation-cn.domain-set",
        "reports/geolocation-cn.json",
    }
)
MANAGED_OUTPUT_ROOTS = (ROOT / "dist", ROOT / "reports")


class ConversionError(RuntimeError):
    """Raised when conversion cannot preserve the reviewed source exactly."""


@dataclass(frozen=True)
class DomainRule:
    """A validated domain rule whose source spelling is already canonical."""

    kind: str
    value: str

    def __post_init__(self) -> None:
        if self.kind not in {"exact", "suffix", "subdomain_suffix"}:
            raise ConversionError(f"Unsupported domain rule kind: {self.kind}")

    def mihomo(self) -> str:
        if self.kind == "suffix":
            return f"+.{self.value}"
        if self.kind == "subdomain_suffix":
            return f".{self.value}"
        return self.value

    def shadowrocket(self) -> str:
        if self.kind in {"suffix", "subdomain_suffix"}:
            return f".{self.value}"
        return self.value


def normalize_domain(value: str) -> str:
    """Return a canonical spelling for validation; callers must not rewrite to it."""

    value = value.strip().rstrip(".").lower()
    if not value or "," in value or "://" in value:
        raise ConversionError(f"Invalid domain value: {value!r}")
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ConversionError(f"Invalid IDN domain: {value!r}") from exc
    if len(ascii_value) > 253:
        raise ConversionError(f"Domain is longer than 253 bytes: {ascii_value!r}")
    labels = ascii_value.split(".")
    if any(not DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        raise ConversionError(f"Invalid hostname syntax: {ascii_value!r}")
    return ascii_value


def rule_lines(text: str, source: str) -> list[str]:
    """Read rule lines while refusing invisible source normalization."""

    probe = text.lstrip().lower()
    if probe.startswith("<!doctype") or probe.startswith("<html"):
        raise ConversionError(f"Upstream returned HTML instead of rules: {source}")
    lines: list[str] = []
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.lstrip("\ufeff") if line_number == 1 else raw
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line != line.strip():
            raise ConversionError(
                f"Rule has leading or trailing whitespace in {source}:{line_number}: {line!r}"
            )
        lines.append(line)
    if not lines:
        raise ConversionError(f"Upstream returned no usable rules: {source}")
    return lines


def clean_lines(text: str, source: str) -> list[str]:
    """Compatibility alias for validated non-comment rule lines."""

    return rule_lines(text, source)


def validate_canonical_domain(value: str, source: str, line: str) -> str:
    canonical = normalize_domain(value)
    if value != canonical:
        raise ConversionError(
            f"Domain would require normalization in {source}: {line!r} -> {canonical!r}"
        )
    return value


def parse_domain_text(text: str, source: str) -> list[DomainRule]:
    """Parse domain text without changing order, spelling, or multiplicity."""

    result: list[DomainRule] = []
    for line in rule_lines(text, source):
        if line.startswith("+."):
            value = validate_canonical_domain(line[2:], source, line)
            result.append(DomainRule("suffix", value))
        elif line.startswith("."):
            value = validate_canonical_domain(line[1:], source, line)
            result.append(DomainRule("subdomain_suffix", value))
        elif "*" in line or "?" in line or "," in line:
            raise ConversionError(f"Unsupported domain rule in {source}: {line}")
        else:
            value = validate_canonical_domain(line, source, line)
            result.append(DomainRule("exact", value))
    return result


def parse_ipcidr_text(
    text: str, source: str, expected_version: int
) -> tuple[list[str], int]:
    entries, duplicates = parse_mixed_ipcidr_text(text, source)
    for entry in entries:
        version = ipaddress.ip_network(entry, strict=True).version
        if version != expected_version:
            raise ConversionError(
                f"Unexpected IPv{version} CIDR in IPv{expected_version} source {source}: {entry}"
            )
    return entries, duplicates


def parse_mixed_ipcidr_text(text: str, source: str) -> tuple[list[str], int]:
    """Validate CIDRs while retaining their original order and multiplicity."""

    entries: list[str] = []
    for line in rule_lines(text, source):
        try:
            canonical = str(ipaddress.ip_network(line, strict=True))
        except ValueError as exc:
            raise ConversionError(f"Invalid CIDR in {source}: {line}") from exc
        if line != canonical:
            raise ConversionError(
                f"CIDR would require normalization in {source}: {line!r} -> {canonical!r}"
            )
        entries.append(line)
    counts = collections.Counter(entries)
    duplicates = sum(count - 1 for count in counts.values())
    return entries, duplicates


def duplicate_counts(values: Iterable[str]) -> dict[str, int]:
    return {
        value: count
        for value, count in collections.Counter(values).items()
        if count > 1
    }


def rule_covers_domain(rule: DomainRule, domain: str) -> bool:
    canonical = normalize_domain(domain)
    if domain != canonical:
        raise ConversionError(f"Noncanonical lookup domain: {domain!r}")
    if rule.kind == "exact":
        return domain == rule.value
    if rule.kind == "suffix":
        return domain == rule.value or domain.endswith("." + rule.value)
    return domain != rule.value and domain.endswith("." + rule.value)


def load_allowlist(path: Path) -> list[str]:
    entries = rule_lines(path.read_text(encoding="utf-8"), str(path))
    for entry in entries:
        validate_canonical_domain(entry, str(path), entry)
    if duplicate_counts(entries):
        raise ConversionError(f"Local reviewed allowlist contains duplicates: {path}")
    return entries


def fetch_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            status = getattr(response, "status", 200)
            if status != 200:
                raise ConversionError(f"HTTP {status} while downloading {url}")
            data = response.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ConversionError(f"Failed to download {url}: {exc}") from exc
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConversionError(f"Upstream is not UTF-8 text: {url}") from exc


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def render_rules(rules: Sequence[DomainRule], target: str) -> str:
    """Render one output line per input rule, in exactly the same order."""

    if target == "mihomo":
        lines = [rule.mihomo() for rule in rules]
    elif target == "shadowrocket":
        lines = [rule.shadowrocket() for rule in rules]
        projections: dict[str, set[str]] = collections.defaultdict(set)
        for source_rule, output in zip(rules, lines):
            projections[output].add(source_rule.mihomo())
        collisions = {
            output: sorted(sources)
            for output, sources in projections.items()
            if len(sources) > 1
        }
        if collisions:
            raise ConversionError(
                "Distinct source rules collapse to the same Shadowrocket rule: "
                + json.dumps(collisions, ensure_ascii=False, sort_keys=True)
            )
    else:
        raise ConversionError(f"Unknown render target: {target}")
    if len(lines) != len(rules):
        raise ConversionError(f"Rendering changed the {target} rule count")
    return "\n".join(lines) + "\n"


def render_shadowrocket_ip_rules(networks: Sequence[str]) -> str:
    lines: list[str] = []
    for value in networks:
        network = ipaddress.ip_network(value, strict=True)
        rule_type = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
        lines.append(f"{rule_type},{value}")
    if len(lines) != len(networks):
        raise ConversionError("Rendering changed the Shadowrocket IP rule count")
    return "\n".join(lines) + "\n"


def join_url(base: str, leaf: str) -> str:
    return base.rstrip("/") + "/" + leaf.lstrip("/")


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", dir=path.parent, delete=False
    ) as handle:
        handle.write(content)
        temp_name = handle.name
    os.replace(temp_name, path)


def is_externally_managed_output(path: Path) -> bool:
    relative = path.relative_to(ROOT).as_posix()
    return (
        path.parent == ROOT / "dist" / "mihomo" and path.suffix == ".mrs"
    ) or relative in EXTERNALLY_MANAGED_OUTPUTS


def managed_files() -> set[str]:
    files: set[str] = set()
    for output_root in MANAGED_OUTPUT_ROOTS:
        if not output_root.exists():
            continue
        files.update(
            relative
            for path in output_root.rglob("*")
            if path.is_file()
            for relative in [path.relative_to(ROOT).as_posix()]
            if relative not in STATIC_OUTPUTS
            if not is_externally_managed_output(path)
        )
    return files


def build(sources_path: Path, allowlist_path: Path) -> Mapping[str, str]:
    config = json.loads(sources_path.read_text(encoding="utf-8"))
    outputs: dict[str, str] = {}
    report_sources: dict[str, dict[str, object]] = {}

    def download(name: str, url: str) -> str:
        text = fetch_text(url)
        report_sources[name] = {
            "url": url,
            "sha256": sha256_text(text),
            "bytes": len(text.encode("utf-8")),
        }
        return text

    bett = config["bett"]
    domain_stats: dict[str, dict[str, object]] = {}
    for output_name, source_leaf in bett["shadowrocket_domains"].items():
        url = join_url(bett["geosite_base"], source_leaf)
        text = download(f"bett/geosite/{output_name}", url)
        rules = parse_domain_text(text, url)
        duplicates = duplicate_counts([rule.mihomo() for rule in rules])
        rendered = render_rules(rules, "shadowrocket")
        if len(rendered.splitlines()) != len(rules):
            raise ConversionError(f"Rule count changed while converting {url}")
        outputs[f"dist/shadowrocket/{output_name}.domain-set"] = rendered
        domain_stats[output_name] = {
            "source_entries": len(rules),
            "output_entries": len(rules),
            "order_preserved": True,
            "exact_duplicates_preserved": duplicates,
        }

    ip_stats: dict[str, dict[str, object]] = {}
    for category, base_key in (
        ("shadowrocket_ips", "geoip_base"),
        ("shadowrocket_asns", "asn_base"),
    ):
        for output_name, source_leaf in bett[category].items():
            url = join_url(bett[base_key], source_leaf)
            text = download(f"bett/{category}/{output_name}", url)
            networks, _ = parse_mixed_ipcidr_text(text, url)
            duplicates = duplicate_counts(networks)
            rendered = render_shadowrocket_ip_rules(networks)
            outputs[f"dist/shadowrocket/{output_name}.list"] = rendered
            ip_stats[output_name] = {
                "source_entries": len(networks),
                "output_entries": len(networks),
                "order_preserved": True,
                "exact_duplicates_preserved": duplicates,
            }

    game_url = join_url(
        bett["geosite_base"], bett["steam_cn_download_validation"]
    )
    game_text = download("bett/geosite/steam-cn-download-validation", game_url)
    game_rules = parse_domain_text(game_text, game_url)
    game_duplicates = duplicate_counts([rule.mihomo() for rule in game_rules])
    reviewed = load_allowlist(allowlist_path)
    missing = [
        domain
        for domain in reviewed
        if not any(rule_covers_domain(rule, domain) for rule in game_rules)
    ]
    if missing:
        raise ConversionError(
            "Reviewed Steam-China rules disappeared from Bett: "
            + ", ".join(missing)
        )
    steam_rules = [DomainRule("exact", domain) for domain in reviewed]
    outputs["dist/mihomo/steam-cn-download.list"] = render_rules(
        steam_rules, "mihomo"
    )
    outputs["dist/shadowrocket/steam-cn-download.domain-set"] = render_rules(
        steam_rules, "shadowrocket"
    )

    reviewed_set = set(reviewed)
    steam_named_not_reviewed = [
        rule.mihomo()
        for rule in game_rules
        if "steam" in rule.value and rule.value not in reviewed_set
    ]
    outputs["reports/steam-named-not-reviewed.txt"] = (
        "\n".join(steam_named_not_reviewed) + "\n"
        if steam_named_not_reviewed
        else ""
    )

    summary = {
        "schema_version": 7,
        "conversion_policy": {
            "syntax_only": True,
            "source_order_preserved": True,
            "source_rule_count_preserved": True,
            "semantic_minimization": False,
            "upstream_exact_duplicates": "preserve",
            "unsupported_or_noncanonical_rules": "fail",
        },
        "sources": report_sources,
        "shadowrocket_domains": domain_stats,
        "shadowrocket_ip_and_asn": ip_stats,
        "steam_cn_download": {
            "canonical_source": allowlist_path.relative_to(ROOT).as_posix(),
            "validation_source": game_url,
            "source_entries": len(reviewed),
            "output_entries": len(steam_rules),
            "order_preserved": True,
            "validation_source_exact_duplicates": game_duplicates,
        },
    }
    outputs["reports/summary.json"] = (
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )

    report_lines = [
        "# Generated rule report",
        "",
        "- Conversion policy: syntax only; no semantic minimization or sorting.",
        "- Every generated provider preserves source rule order and count.",
        "- Upstream exact duplicates are preserved; unsupported syntax and required normalization fail the build.",
        "",
        "## Bett Shadowrocket domain providers",
        "",
    ]
    for name, stats in domain_stats.items():
        report_lines.append(
            f"- `{name}`: {stats['source_entries']} source rules -> "
            f"{stats['output_entries']} output rules; order preserved."
        )
    report_lines.extend(
        ["", "## Bett Shadowrocket IP and ASN providers", ""]
    )
    for name, stats in ip_stats.items():
        report_lines.append(
            f"- `{name}`: {stats['source_entries']} source rules -> "
            f"{stats['output_entries']} output rules; order preserved."
        )
    report_lines.extend(
        [
            "",
            "## Steam China download",
            "",
            f"- Canonical allowlist rules: {len(reviewed)}.",
            "- Bett coverage validation passed.",
            "- Mihomo and Shadowrocket outputs preserve allowlist order and count.",
            "",
        ]
    )
    outputs["reports/update-report.md"] = "\n".join(report_lines)
    return outputs


def write_outputs(outputs: Mapping[str, str], check: bool) -> tuple[list[str], list[str]]:
    existing = managed_files()
    expected = set(outputs)
    stale = sorted(existing - expected)
    changed: list[str] = []
    for relative, content in sorted(outputs.items()):
        path = ROOT / relative
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current != content:
            changed.append(relative)
            if not check:
                atomic_write(path, content)
    if not check:
        for relative in stale:
            (ROOT / relative).unlink()
    return changed, stale


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--steam-allowlist", type=Path, default=DEFAULT_STEAM_ALLOWLIST)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if generated files differ; do not write anything.",
    )
    args = parser.parse_args()
    try:
        outputs = build(args.sources.resolve(), args.steam_allowlist.resolve())
        changed, stale = write_outputs(outputs, args.check)
        if args.check and (changed or stale):
            print("Generated files are out of date:", file=sys.stderr)
            for relative in changed:
                print(f"  changed: {relative}", file=sys.stderr)
            for relative in stale:
                print(f"  stale: {relative}", file=sys.stderr)
            return 1
        verb = "checked" if args.check else "generated"
        print(
            f"Generated files {verb}: {len(outputs)}; "
            f"changed {len(changed)}, removed {len(stale)} stale files."
        )
        return 0
    except (ConversionError, OSError, json.JSONDecodeError) as exc:
        print(f"Conversion failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
