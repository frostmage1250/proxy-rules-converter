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
from html.parser import HTMLParser
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
EXTERNALLY_MANAGED_OUTPUTS = frozenset(
    {
        "dist/mihomo/geolocation-cn.list",
        "reports/geolocation-cn.json",
        "reports/ai.json",
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



CLAUDE_SITE_REQUIRED_TYPED_RULES = frozenset(
    {
        "DOMAIN-SUFFIX,anthropic.com",
        "DOMAIN-SUFFIX,claude.ai",
        "DOMAIN-SUFFIX,claude.com",
        "DOMAIN-SUFFIX,clau.de",
        "DOMAIN-SUFFIX,claudemcpclient.com",
        "DOMAIN-SUFFIX,claudemcpcontent.com",
        "DOMAIN-SUFFIX,claudeusercontent.com",
        "DOMAIN,servd-anthropic-website.b-cdn.net",
        "DOMAIN,anthropic.com.cdn.cloudflare.net",
        "DOMAIN,anthropic.auth0.com",
        "DOMAIN,anthropic-com.ghost.io",
        "DOMAIN-SUFFIX,sentry.io",
        "DOMAIN-SUFFIX,statsigapi.net",
        "DOMAIN,browser-intake-us5-datadoghq.com",
        "DOMAIN-KEYWORD,datadog",
        "DOMAIN-KEYWORD,sift",
        "DOMAIN-SUFFIX,intercom.io",
        "DOMAIN-SUFFIX,intercomcdn.com",
        "DOMAIN,cdn.usefathom.com",
        "IP-CIDR,160.79.104.0/21,no-resolve",
        "IP-CIDR6,2607:6bc0::/32,no-resolve",
        "IP-ASN,399358,no-resolve",
    }
)
CLAUDE_SITE_REQUIRED_KEYWORDS = ("datadog", "sentry", "sift")
CLAUDE_CLASSICAL_RE = re.compile(
    r"^(?:DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD),[^,]+$"
    r"|^(?:IP-CIDR|IP-CIDR6|IP-ASN),[^,]+,no-resolve$"
)


class CodeBlockHTMLParser(HTMLParser):
    """Collect visible text from preformatted blocks without third-party HTML packages."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.blocks: list[str] = []
        self._pre_depth = 0
        self._current: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        del attrs
        if tag.lower() == "pre":
            if self._pre_depth == 0:
                self._current = []
            self._pre_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "pre" or self._pre_depth == 0:
            return
        self._pre_depth -= 1
        if self._pre_depth == 0:
            self.blocks.append("".join(self._current))
            self._current = []

    def handle_data(self, data: str) -> None:
        if self._pre_depth:
            self._current.append(data)


def validate_claude_classical_rule(line: str, source: str) -> str:
    if not CLAUDE_CLASSICAL_RE.fullmatch(line):
        raise ConversionError(f"Unsupported Claude rule in {source}: {line}")
    parts = line.split(",")
    kind = parts[0]
    value = parts[1]
    if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        validate_canonical_domain(value, source, line)
    elif kind == "DOMAIN-KEYWORD":
        if not value or value != value.lower() or value.strip() != value:
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


def extract_claude_site_rules(text: str, source: str) -> list[str]:
    """Extract the site's typed Mihomo rules plus all keyword fallbacks, excluding NTP."""

    probe = text.lstrip().lower()
    if not probe.startswith("<!doctype") and not probe.startswith("<html"):
        raise ConversionError(f"Claude site did not return HTML: {source}")

    parser = CodeBlockHTMLParser()
    parser.feed(text)
    parser.close()

    typed_candidates: list[list[str]] = []
    fallback_keywords: list[str] = []
    for block in parser.blocks:
        normalized: list[str] = []
        for raw in block.splitlines():
            line = raw.strip()
            if line.startswith("- "):
                line = line[2:].strip()
            if not line or line.startswith("#"):
                continue
            normalized.append(line)
            match = re.fullmatch(r"keyword:\s*([a-z0-9_-]+)", line, re.I)
            if match:
                fallback_keywords.append(match.group(1).lower())
        typed = [line for line in normalized if CLAUDE_CLASSICAL_RE.fullmatch(line)]
        if CLAUDE_SITE_REQUIRED_TYPED_RULES.issubset(typed):
            typed_candidates.append(typed)

    if not typed_candidates:
        raise ConversionError(
            "Claude site no longer contains the reviewed complete typed rule block"
        )

    rules: list[str] = []
    seen: set[str] = set()
    for line in typed_candidates[0]:
        validated = validate_claude_classical_rule(line, source)
        if validated not in seen:
            rules.append(validated)
            seen.add(validated)

    keyword_set = set(fallback_keywords)
    missing_keywords = [
        keyword
        for keyword in CLAUDE_SITE_REQUIRED_KEYWORDS
        if keyword not in keyword_set
    ]
    if missing_keywords:
        raise ConversionError(
            "Claude site keyword fallbacks disappeared: " + ", ".join(missing_keywords)
        )
    for keyword in CLAUDE_SITE_REQUIRED_KEYWORDS:
        line = f"DOMAIN-KEYWORD,{keyword}"
        if line not in seen:
            rules.append(line)
            seen.add(line)

    if any("ntp" in rule.lower() for rule in rules):
        raise ConversionError("NTP must not enter the Claude provider")
    return rules


def domain_rule_to_classical(rule: DomainRule) -> str:
    if rule.kind == "exact":
        return f"DOMAIN,{rule.value}"
    if rule.kind == "suffix":
        return f"DOMAIN-SUFFIX,{rule.value}"
    raise ConversionError(
        "Claude Bett source contains a subdomain-only suffix that classical rules "
        f"cannot preserve: {rule.mihomo()}"
    )


def merge_claude_rules(
    bett_rules: Sequence[DomainRule], site_rules: Sequence[str]
) -> list[str]:
    """Keep Bett first and append every site rule that adds matching coverage."""

    merged = [domain_rule_to_classical(rule) for rule in bett_rules]
    seen = set(merged)
    for line in site_rules:
        if line in seen:
            continue
        kind, value, *_ = line.split(",")
        if kind == "DOMAIN" and any(
            rule_covers_domain(rule, value) for rule in bett_rules
        ):
            continue
        if kind == "DOMAIN-SUFFIX" and any(
            rule.kind == "suffix" and rule_covers_domain(rule, value)
            for rule in bett_rules
        ):
            continue
        merged.append(line)
        seen.add(line)

    if any("ntp" in rule.lower() for rule in merged):
        raise ConversionError("NTP must not enter the merged Claude provider")
    return merged


def render_classical_yaml(rules: Sequence[str]) -> str:
    if not rules:
        raise ConversionError("Claude provider would be empty")
    return "payload:\n" + "".join(f"  - {rule}\n" for rule in rules)


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

    anthropic_url = join_url(bett["geosite_base"], bett["anthropic"])
    anthropic_text = download("bett/geosite/anthropic", anthropic_url)
    anthropic_rules = parse_domain_text(anthropic_text, anthropic_url)

    claude_site_url = config["claude_site"]["url"]
    claude_site_text = download("ip.net.coffee/claude/site", claude_site_url)
    claude_site_rules = extract_claude_site_rules(
        claude_site_text, claude_site_url
    )
    claude_rules = merge_claude_rules(anthropic_rules, claude_site_rules)
    outputs["dist/mihomo/claude.yaml"] = render_classical_yaml(claude_rules)

    summary = {
        "schema_version": 8,
        "conversion_policy": {
            "syntax_only": True,
            "source_order_preserved": True,
            "source_rule_count_preserved": True,
            "semantic_minimization": False,
            "upstream_exact_duplicates": "preserve",
            "unsupported_or_noncanonical_rules": "fail",
        },
        "sources": report_sources,
        "steam_cn_download": {
            "canonical_source": allowlist_path.relative_to(ROOT).as_posix(),
            "validation_source": game_url,
            "source_entries": len(reviewed),
            "output_entries": len(steam_rules),
            "order_preserved": True,
            "validation_source_exact_duplicates": game_duplicates,
        },
        "claude": {
            "bett_source": anthropic_url,
            "site_source": claude_site_url,
            "bett_entries": len(anthropic_rules),
            "site_entries": len(claude_site_rules),
            "output_entries": len(claude_rules),
            "bett_precedence": True,
            "ntp_excluded": True,
            "includes_ip_cidr": True,
            "includes_ip_cidr6": True,
            "includes_asn": 399358,
            "format": "mihomo-classical-yaml",
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
        "## Steam China download",
        "",
        f"- Canonical allowlist rules: {len(reviewed)}.",
        "- Bett coverage validation passed.",
        "- Mihomo output preserves allowlist order and count.",
        "",
        "## Claude",
        "",
        f"- Bett Anthropic rules: {len(anthropic_rules)} (primary source).",
        f"- Claude site rules: {len(claude_site_rules)}.",
        f"- Merged classical rules: {len(claude_rules)}.",
        "- Authentication, telemetry, risk-control keywords, IPv4, IPv6, and AS399358 are retained.",
        "- NTP rules are explicitly excluded.",
        "",
    ]
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
