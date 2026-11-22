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
MCDN_BLOCK_LIST = ROOT / "config" / "mcdn-block.list"
PRON_SITES = ROOT / "config" / "pron-sites.json"
CLAUDE_SUPPLEMENT = ROOT / "config" / "claude-supplement.list"
DEFAULT_BUILD_DIR = ROOT / "build" / "mihomo"
USER_AGENT = (
    "rules-converter-action/2.0 "
    "(+https://github.com/frostmage1250/proxy-rules-converter)"
)
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$", re.I)
# Written by later workflow steps, so convert_rules.py must never treat them as stale.
EXTERNALLY_MANAGED_OUTPUTS = frozenset({"dist/classical/geolocation-cn.list"})
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


CLAUDE_PROCESS_RULE = "PROCESS-NAME,claude.exe"
CLAUDE_SUPPLEMENT_RE = re.compile(
    r"(?:DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD),[^,\s]+"
    r"|(?:IP-CIDR|IP-CIDR6|IP-ASN),[^,\s]+(?:,no-resolve)?"
)


def validate_claude_classical_rule(line: str, source: str) -> str:
    """Accept only the supplement rule types Mihomo classical providers need."""

    if not CLAUDE_SUPPLEMENT_RE.fullmatch(line):
        raise ConversionError(f"Unsupported Claude rule in {source}: {line}")
    kind, value = line.split(",")[:2]
    if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        validate_canonical_domain(value, source, line)
    elif kind == "DOMAIN-KEYWORD":
        if value != value.lower():
            raise ConversionError(f"Invalid Claude keyword in {source}: {line}")
    elif kind in {"IP-CIDR", "IP-CIDR6"}:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ConversionError(f"Invalid Claude CIDR in {source}: {line}") from exc
        expected_version = 4 if kind == "IP-CIDR" else 6
        if network.version != expected_version or str(network) != value:
            raise ConversionError(f"Noncanonical Claude CIDR in {source}: {line}")
    elif kind == "IP-ASN":
        if not value.isascii() or not value.isdecimal() or int(value) <= 0:
            raise ConversionError(f"Invalid Claude ASN in {source}: {line}")
    return line


def parse_claude_supplement(text: str, source: str) -> list[str]:
    """Read the editable supplement; comments and blank lines are ignored."""

    return [validate_claude_classical_rule(line, source) for line in rule_lines(text, source)]


def domain_rule_to_classical(rule: DomainRule) -> str:
    if rule.kind == "exact":
        return f"DOMAIN,{rule.value}"
    if rule.kind == "suffix":
        return f"DOMAIN-SUFFIX,{rule.value}"
    raise ConversionError(
        "Subdomain-only suffix cannot be expressed as a classical rule: "
        f"{rule.mihomo()}"
    )


def build_claude_rules(
    bett_rules: Sequence[DomainRule], supplement: Sequence[str]
) -> list[str]:
    """Bett first, then the supplement; drop identical lines; process rule last."""

    candidates = [domain_rule_to_classical(rule) for rule in bett_rules]
    candidates.extend(supplement)
    return [*dict.fromkeys(candidates), CLAUDE_PROCESS_RULE]


def render_classical_text(lines: Sequence[str]) -> str:
    """Render Mihomo classical text: one rule per line, no YAML payload."""

    if not lines:
        raise ConversionError("Classical provider would be empty")
    return "\n".join(lines) + "\n"


def render_classical_rules(rules: Sequence[DomainRule]) -> str:
    return render_classical_text([domain_rule_to_classical(rule) for rule in rules])


def parse_mcdn_adguard(
    text: str, source: str, excluded_rules: Sequence[str] = ()
) -> list[DomainRule]:
    """Convert AdGuard hostname blocks, skipping only explicitly excluded rules."""

    rules: list[DomainRule] = []
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.lstrip("\ufeff") if line_number == 1 else raw
        if not line.strip() or line.startswith("!"):
            continue
        if line in excluded_rules:
            continue
        match = re.fullmatch(r"\|\|([a-z0-9_.-]+)\^(?:\$important)?", line)
        if match is None:
            raise ConversionError(
                f"Unsupported MCDN AdGuard rule in {source}:{line_number}: {line!r}"
            )
        hostname = validate_canonical_domain(match.group(1), source, line)
        rules.append(DomainRule("suffix", hostname))
    if not rules:
        raise ConversionError(f"MCDN source returned no hostname blocks: {source}")
    return rules


def merge_mcdn_rules(
    local_rules: Sequence[DomainRule], upstream_rules: Sequence[DomainRule]
) -> list[DomainRule]:
    """Deduplicate identical rules, retaining each first occurrence."""

    return list(dict.fromkeys([*local_rules, *upstream_rules]))


def parse_porn_source(text: str, source: str) -> tuple[list[DomainRule], int]:
    """Keep category-porn domain rules and explicitly exclude every regex."""
    rules: list[DomainRule] = []
    excluded_regex = 0
    for line in rule_lines(text, source):
        kind, separator, value = line.partition(",")
        if not separator or not value:
            raise ConversionError(f"Invalid category-porn rule in {source}: {line}")
        if kind == "DOMAIN-REGEX":
            excluded_regex += 1
            continue
        if kind not in {"DOMAIN", "DOMAIN-SUFFIX"}:
            raise ConversionError(f"Unsupported category-porn rule in {source}: {line}")
        domain = validate_canonical_domain(value, source, line)
        rules.append(DomainRule("exact" if kind == "DOMAIN" else "suffix", domain))
    if not rules:
        raise ConversionError(f"category-porn has no non-regex domain rules: {source}")
    return rules, excluded_regex


def select_pron_rules(
    rules: Sequence[DomainRule], selection: Mapping[str, object]
) -> list[DomainRule]:
    """Select only reviewed domains already present in category-porn."""
    sites = selection.get("sites")
    if selection.get("schema_version") != 1 or not isinstance(sites, list) or not sites:
        raise ConversionError("Invalid pron site selection")
    allowed: set[str] = set()
    for site in sites:
        if not isinstance(site, dict) or not isinstance(site.get("name"), str):
            raise ConversionError("Invalid pron site record")
        for field in ("domains", "cdn_domains"):
            domains = site.get(field)
            if not isinstance(domains, list) or any(not isinstance(domain, str) for domain in domains):
                raise ConversionError(f"Invalid pron {field} for {site['name']}")
            for domain in domains:
                validate_canonical_domain(domain, str(PRON_SITES), domain)
                allowed.add(domain)
    excluded = selection.get("excluded_domains", [])
    if not isinstance(excluded, list) or any(not isinstance(domain, str) for domain in excluded):
        raise ConversionError("Invalid pron exclusions")
    for domain in allowed:
        if any(domain == root or domain.endswith("." + root) for root in excluded):
            raise ConversionError(f"Excluded E-Hentai domain entered pron selection: {domain}")
    missing = sorted(allowed - {rule.value for rule in rules})
    if missing:
        raise ConversionError("Selected pron domains disappeared from category-porn: " + ", ".join(missing))
    selected = [rule for rule in rules if rule.value in allowed]
    if not selected:
        raise ConversionError("pron selection contains no category-porn rules")
    return selected


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
    """Render one Mihomo output line per input rule, preserving order."""

    if target != "mihomo":
        raise ConversionError(f"Unknown render target: {target}")
    lines = [rule.mihomo() for rule in rules]
    if len(lines) != len(rules):
        raise ConversionError("Rendering changed the Mihomo rule count")
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
    ) or path.parent == ROOT / "dist" / "egern" or relative in EXTERNALLY_MANAGED_OUTPUTS


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
            if not is_externally_managed_output(path)
        )
    return files


def build(
    sources_path: Path,
    mcdn_source_path: Path | None = None, porn_source_path: Path | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    """Return (published outputs under dist/ and reports/, intermediate MRS sources)."""

    config = json.loads(sources_path.read_text(encoding="utf-8"))
    outputs: dict[str, str] = {}
    intermediates: dict[str, str] = {}
    report_sources: dict[str, dict[str, object]] = {}

    def record(name: str, url: str, text: str) -> None:
        report_sources[name] = {
            "url": url,
            "sha256": sha256_text(text),
            "bytes": len(text.encode("utf-8")),
        }

    def download(name: str, url: str) -> str:
        text = fetch_text(url)
        record(name, url, text)
        return text

    bett = config["bett"]

    porn_url = config["porn"]["url"]
    if porn_source_path is None:
        porn_text = download("bett/geosite/category-porn", porn_url)
    else:
        porn_text = porn_source_path.read_text(encoding="utf-8-sig")
        record("bett/geosite/category-porn", porn_url, porn_text)
    porn_upstream_rules, porn_regex_excluded = parse_porn_source(porn_text, porn_url)
    porn_selection = json.loads(PRON_SITES.read_text(encoding="utf-8"))
    porn_selected_rules = select_pron_rules(porn_upstream_rules, porn_selection)
    porn_rules = list(dict.fromkeys(porn_selected_rules))
    intermediates["porn.list"] = render_rules(porn_rules, "mihomo")
    outputs["dist/classical/porn.list"] = render_classical_rules(porn_rules)

    mcdn_source = MCDN_BLOCK_LIST.read_text(encoding="utf-8")
    mcdn_rules = parse_domain_text(mcdn_source, str(MCDN_BLOCK_LIST))
    if mcdn_rules != [
        DomainRule("suffix", "mcdn.bilivideo.com"),
        DomainRule("suffix", "mcdn.bilivideo.cn"),
        DomainRule("suffix", "edge.mountaintoys.cn"),
        DomainRule("suffix", "h2.smtcdns.net"),
    ]:
        raise ConversionError("MCDN block source must contain the four reviewed suffixes in order")
    mcdn_config = config["mcdn_block"]
    mcdn_url = mcdn_config["url"]
    if mcdn_source_path is None:
        mcdn_upstream = download("mcdn/adguard", mcdn_url)
    else:
        mcdn_upstream = mcdn_source_path.read_text(encoding="utf-8-sig")
        record("mcdn/adguard", mcdn_url, mcdn_upstream)
    mcdn_adguard_rules = parse_mcdn_adguard(
        mcdn_upstream, mcdn_url, mcdn_config["excluded_rules"]
    )
    mcdn_merged_rules = merge_mcdn_rules(mcdn_rules, mcdn_adguard_rules)
    intermediates["mcdn-block.list"] = render_rules(mcdn_merged_rules, "mihomo")
    outputs["dist/classical/mcdn-block.list"] = render_classical_rules(mcdn_merged_rules)

    anthropic_url = join_url(bett["geosite_base"], bett["anthropic"])
    anthropic_text = download("bett/geosite/anthropic", anthropic_url)
    anthropic_rules = parse_domain_text(anthropic_text, anthropic_url)
    claude_supplement_text = CLAUDE_SUPPLEMENT.read_text(encoding="utf-8")
    claude_supplement = parse_claude_supplement(
        claude_supplement_text, str(CLAUDE_SUPPLEMENT)
    )
    claude_rules = build_claude_rules(anthropic_rules, claude_supplement)
    claude_duplicates = len(anthropic_rules) + len(claude_supplement) + 1 - len(claude_rules)
    outputs["dist/mihomo/claude.list"] = render_classical_text(claude_rules)

    supplement_source = CLAUDE_SUPPLEMENT.relative_to(ROOT).as_posix()
    summary = {
        "schema_version": 15,
        "conversion_policy": {
            "syntax_only": True,
            "source_order_preserved": True,
            "semantic_minimization": False,
            "deduplication": "identical rules only; first occurrence retained",
            "unsupported_or_noncanonical_rules": "fail",
        },
        "sources": report_sources,
        "porn": {
            "policy_group": "pron",
            "upstream_source": porn_url,
            "selection_source": PRON_SITES.relative_to(ROOT).as_posix(),
            "source_scope": "category-porn only; no external domains",
            "selected_sites": [site["name"] for site in porn_selection["sites"]],
            "upstream_domain_entries": len(porn_upstream_rules),
            "selected_domain_entries": len(porn_selected_rules),
            "regex_entries_excluded": porn_regex_excluded,
            "duplicates_removed": len(porn_selected_rules) - len(porn_rules),
            "entries": len(porn_rules),
            "outputs": ["dist/mihomo/porn.mrs", "dist/classical/porn.list"],
        },
        "mcdn_block": {
            "name": "mcdn屏蔽",
            "canonical_source": MCDN_BLOCK_LIST.relative_to(ROOT).as_posix(),
            "source_sha256": sha256_text(mcdn_source),
            "upstream_source": mcdn_url,
            "excluded_rules": mcdn_config["excluded_rules"],
            "local_entries": len(mcdn_rules),
            "upstream_entries": len(mcdn_adguard_rules),
            "duplicates_removed": len(mcdn_rules) + len(mcdn_adguard_rules) - len(mcdn_merged_rules),
            "entries": len(mcdn_merged_rules),
            "outputs": ["dist/mihomo/mcdn-block.mrs", "dist/classical/mcdn-block.list"],
        },
        "claude": {
            "bett_source": anthropic_url,
            "supplement_source": supplement_source,
            "supplement_sha256": sha256_text(claude_supplement_text),
            "bett_entries": len(anthropic_rules),
            "supplement_entries": len(claude_supplement),
            "duplicates_removed": claude_duplicates,
            "process_rule": CLAUDE_PROCESS_RULE,
            "entries": len(claude_rules),
            "outputs": ["dist/mihomo/claude.list"],
            "format": "mihomo-classical-text",
        },
        "geolocation_cn": {
            "outputs": ["dist/mihomo/geolocation-cn.mrs", "dist/classical/geolocation-cn.list"],
            "built_by": "workflow (V2Fly + MetaCubeX meta-rules-converter, decoded by Mihomo)",
        },
    }
    outputs["reports/summary.json"] = (
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )

    report_lines = [
        "# Generated rule report",
        "",
        "- Conversion policy: syntax only; source order kept; only identical rules are deduplicated.",
        "- Unsupported syntax and required normalization fail the build.",
        "",
        "## pron",
        "",
        f"- category-porn domain rules: {len(porn_upstream_rules)}; regex rules excluded: {porn_regex_excluded}.",
        f"- Selected websites: {len(porn_selection['sites'])}; selected domain rules: {len(porn_selected_rules)}.",
        "- Source scope: category-porn only; E-Hentai and ExHentai excluded.",
        f"- Output rules: {len(porn_rules)} (dist/mihomo/porn.mrs, dist/classical/porn.list).",
        "",
        "## MCDN block",
        "",
        f"- Local rules: {len(mcdn_rules)}; accepted AdGuard rules: {len(mcdn_adguard_rules)}.",
        f"- Identical duplicates removed: {len(mcdn_rules) + len(mcdn_adguard_rules) - len(mcdn_merged_rules)}.",
        "- The user-excluded *pcdn*.biliapi.net wildcard is omitted.",
        f"- Output rules: {len(mcdn_merged_rules)} (dist/mihomo/mcdn-block.mrs, dist/classical/mcdn-block.list).",
        "",
        "## Claude",
        "",
        f"- Bett Anthropic rules: {len(anthropic_rules)}; supplement rules ({supplement_source}): {len(claude_supplement)}.",
        f"- Identical duplicates removed: {claude_duplicates}.",
        f"- Output rules: {len(claude_rules)}, ending with {CLAUDE_PROCESS_RULE} (dist/mihomo/claude.list).",
        "",
    ]
    outputs["reports/update-report.md"] = "\n".join(report_lines)
    return outputs, intermediates


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


def write_intermediates(intermediates: Mapping[str, str], build_dir: Path) -> None:
    """Write the +. domain text that convert_mrs.py compiles; never published."""

    build_dir.mkdir(parents=True, exist_ok=True)
    for path in build_dir.glob("*.list"):
        if path.name not in intermediates:
            path.unlink()
    for name, content in intermediates.items():
        atomic_write(build_dir / name, content)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--mcdn-source", type=Path, help="Already fetched AdGuard snapshot")
    parser.add_argument("--porn-source", type=Path, help="Already fetched category-porn snapshot")
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=DEFAULT_BUILD_DIR,
        help="Scratch directory for the intermediate MRS source text (always written).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if files in dist/ or reports/ differ; do not write them.",
    )
    args = parser.parse_args()
    try:
        outputs, intermediates = build(
            args.sources.resolve(), args.mcdn_source, args.porn_source
        )
        write_intermediates(intermediates, args.build_dir.resolve())
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
            f"changed {len(changed)}, removed {len(stale)} stale files; "
            f"intermediates {len(intermediates)} in {args.build_dir}."
        )
        return 0
    except (ConversionError, OSError, json.JSONDecodeError) as exc:
        print(f"Conversion failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
