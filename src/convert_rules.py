#!/usr/bin/env python3
"""Build Mihomo and Shadowrocket domain rule sets from pinned public sources.

The converter intentionally uses only Python's standard library. All downloads are
validated and all outputs are assembled in memory before any existing file is
replaced, so a failed update leaves the last successful generated rules untouched.
"""

from __future__ import annotations

import argparse
import hashlib
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
    "rules-converter-action/1.0 "
    "(+https://github.com/frostmage1250/proxy-rules-converter)"
)
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$", re.I)
SUKKA_ATTRIBUTION_MARKER = "7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe"
MICROSOFT_KEYWORDS = frozenset({"1drv", "microsoft", "hotmail"})
GLOBAL_EXPANDED_KEYWORDS = frozenset(
    {"google", "facebook", "whatsapp", "discord", "dropbox", "pinterest"}
)
GLOBAL_DROPPED_KEYWORDS = frozenset({"blogspot", "sci-hub", "browserleaks"})
GLOBAL_KEYWORDS = GLOBAL_EXPANDED_KEYWORDS | GLOBAL_DROPPED_KEYWORDS
STATIC_OUTPUTS = frozenset(
    {
        "dist/shadowrocket/bilibili-direct.list",
        "dist/shadowrocket/bilibili-pcdn.list",
    }
)
MANAGED_OUTPUT_ROOTS = (ROOT / "dist", ROOT / "reports")


class ConversionError(RuntimeError):
    """Raised when an upstream rule cannot be converted without guesswork."""


@dataclass(frozen=True, order=True)
class DomainRule:
    """Canonical domain rule.

    exact: matches only the exact hostname.
    suffix: matches the hostname and every subdomain (Mihomo `+.` semantics).
    subdomain_suffix: matches subdomains but not the apex (Mihomo `.` semantics).
    """

    kind: str
    value: str

    def __post_init__(self) -> None:
        if self.kind not in {"exact", "suffix", "subdomain_suffix"}:
            raise ConversionError(f"Unsupported canonical rule kind: {self.kind}")

    def mihomo(self) -> str:
        if self.kind == "suffix":
            return f"+.{self.value}"
        if self.kind == "subdomain_suffix":
            return f".{self.value}"
        return self.value

    def shadowrocket(self) -> str:
        # Shadowrocket/Surge DOMAIN-SET uses a leading dot for suffix entries.
        if self.kind in {"suffix", "subdomain_suffix"}:
            return f".{self.value}"
        return self.value


def normalize_domain(value: str) -> str:
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


def clean_lines(text: str, source: str) -> list[str]:
    probe = text.lstrip().lower()
    if probe.startswith("<!doctype") or probe.startswith("<html"):
        raise ConversionError(f"Upstream returned HTML instead of rules: {source}")
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    if not lines:
        raise ConversionError(f"Upstream returned no usable rules: {source}")
    return lines


def parse_domain_text(text: str, source: str) -> list[DomainRule]:
    """Parse MetaCubeX/Mihomo non-classical domain text."""
    result: list[DomainRule] = []
    for line in clean_lines(text, source):
        if line.startswith("+."):
            result.append(DomainRule("suffix", normalize_domain(line[2:])))
        elif line.startswith("."):
            result.append(DomainRule("subdomain_suffix", normalize_domain(line[1:])))
        elif "*" in line or "?" in line or "," in line:
            raise ConversionError(
                f"Unsupported wildcard/classical rule in domain source {source}: {line}"
            )
        else:
            result.append(DomainRule("exact", normalize_domain(line)))
    return result


def is_droppable_domestic_wildcard(pattern: str) -> bool:
    """Return true only for the explicitly reviewed, nonessential Qihoo image rule."""
    return pattern.lower() == "*.qhimgs?.com"


def parse_domestic_classical(text: str, source: str) -> tuple[list[DomainRule], int]:
    result: list[DomainRule] = []
    dropped_wildcards = 0
    for line in clean_lines(text, source):
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 2:
            raise ConversionError(f"Malformed classical rule in {source}: {line}")
        rule_type, value = parts[0].upper(), parts[1]
        if rule_type == "DOMAIN":
            result.append(DomainRule("exact", normalize_domain(value)))
        elif rule_type == "DOMAIN-SUFFIX":
            result.append(DomainRule("suffix", normalize_domain(value)))
        elif rule_type == "DOMAIN-WILDCARD":
            if not is_droppable_domestic_wildcard(value):
                raise ConversionError(
                    "New DOMAIN-WILDCARD requires an explicit reviewed conversion: "
                    + value
                )
            dropped_wildcards += 1
        else:
            raise ConversionError(
                f"Non-domain rule appeared in domestic source {source}: {line}"
            )
    return result, dropped_wildcards


def parse_classical_domains(
    text: str,
    source: str,
    *,
    allowed_keywords: frozenset[str] = frozenset(),
    ignored_rule_types: frozenset[str] = frozenset(),
) -> tuple[list[DomainRule], list[str], dict[str, int]]:
    """Extract domain rules from a classical source with an explicit policy.

    Unknown keywords and rule types fail the build. This prevents an upstream format
    change from silently broadening or weakening the generated domain providers.
    """

    result: list[DomainRule] = []
    keywords: list[str] = []
    ignored: dict[str, int] = {}
    for line in clean_lines(text, source):
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 2:
            raise ConversionError(f"Malformed classical rule in {source}: {line}")
        rule_type, value = parts[0].upper(), parts[1]
        if rule_type == "DOMAIN":
            result.append(DomainRule("exact", normalize_domain(value)))
        elif rule_type == "DOMAIN-SUFFIX":
            result.append(DomainRule("suffix", normalize_domain(value)))
        elif rule_type == "DOMAIN-KEYWORD":
            keyword = value.strip().lower()
            if keyword not in allowed_keywords:
                raise ConversionError(
                    f"Unreviewed DOMAIN-KEYWORD in {source}: {value}"
                )
            keywords.append(keyword)
        elif rule_type in ignored_rule_types:
            ignored[rule_type] = ignored.get(rule_type, 0) + 1
        else:
            raise ConversionError(f"Unsupported rule in {source}: {line}")
    return result, keywords, ignored


def drop_sukka_marker(rules: Iterable[DomainRule]) -> tuple[list[DomainRule], int]:
    """Remove Sukka's attribution/probe hostname from client matching data."""

    materialized = list(rules)
    kept = [
        rule
        for rule in materialized
        if not (rule.kind == "exact" and rule.value == SUKKA_ATTRIBUTION_MARKER)
    ]
    return kept, len(materialized) - len(kept)


def drop_domain_fragments(
    rules: Iterable[DomainRule], fragments: Iterable[str]
) -> tuple[list[DomainRule], dict[str, int]]:
    """Drop domains containing explicitly excluded case-normalized fragments."""

    excluded = sorted({fragment.strip().lower() for fragment in fragments})
    counts = {fragment: 0 for fragment in excluded}
    kept: list[DomainRule] = []
    for rule in rules:
        matches = [fragment for fragment in excluded if fragment in rule.value]
        if matches:
            for fragment in matches:
                counts[fragment] += 1
            continue
        kept.append(rule)
    return kept, counts


def expand_domain_keywords(
    keywords: Iterable[str], reference_rules: Iterable[DomainRule]
) -> tuple[list[DomainRule], dict[str, int]]:
    """Expand reviewed keywords only with finite rules from a reference domain set."""

    references = list(reference_rules)
    expanded: set[DomainRule] = set()
    counts: dict[str, int] = {}
    for keyword in sorted(set(keywords)):
        matches = [rule for rule in references if keyword in rule.value]
        if not matches:
            raise ConversionError(
                f"Microsoft keyword {keyword!r} has no MetaCubeX expansion"
            )
        counts[keyword] = len(matches)
        expanded.update(matches)
    return sorted(expanded), counts


def rule_covers_domain(rule: DomainRule, domain: str) -> bool:
    domain = normalize_domain(domain)
    if rule.kind == "exact":
        return domain == rule.value
    if rule.kind == "suffix":
        return domain == rule.value or domain.endswith("." + rule.value)
    return domain != rule.value and domain.endswith("." + rule.value)


def rule_covers_rule(cover: DomainRule, candidate: DomainRule) -> bool:
    if cover == candidate:
        return True
    if cover.kind == "exact":
        return False
    if candidate.kind == "exact":
        return rule_covers_domain(cover, candidate.value)
    if cover.kind == "suffix":
        return candidate.value == cover.value or candidate.value.endswith("." + cover.value)
    if candidate.kind == "subdomain_suffix":
        return candidate.value == cover.value or candidate.value.endswith("." + cover.value)
    return candidate.value.endswith("." + cover.value)


def semantic_minimize(rules: Iterable[DomainRule]) -> tuple[list[DomainRule], int, int]:
    raw = list(rules)
    unique = sorted(set(raw), key=lambda rule: (rule.value, rule.kind))
    kept: list[DomainRule] = []
    for candidate in unique:
        if any(
            other != candidate and rule_covers_rule(other, candidate)
            for other in unique
        ):
            continue
        kept.append(candidate)
    kept.sort(key=lambda rule: (rule.kind != "exact", rule.value, rule.kind))
    return kept, len(raw) - len(unique), len(unique) - len(kept)


def load_allowlist(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return [normalize_domain(line) for line in clean_lines(text, str(path))]


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
    if target == "mihomo":
        lines = [rule.mihomo() for rule in rules]
    elif target == "shadowrocket":
        lines = [rule.shadowrocket() for rule in rules]
    else:
        raise ConversionError(f"Unknown render target: {target}")
    if len(lines) != len(set(lines)):
        raise ConversionError(f"Rendering introduced duplicate {target} entries")
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

    domestic_url = config["sukka"]["domestic"]
    domestic_text = download("sukka/domestic", domestic_url)
    domestic_raw, dropped_wildcard_count = parse_domestic_classical(
        domestic_text, domestic_url
    )
    domestic_raw, domestic_marker_removed = drop_sukka_marker(domestic_raw)
    domestic, domestic_duplicates, domestic_redundant = semantic_minimize(domestic_raw)
    outputs["dist/mihomo/domestic.list"] = render_rules(domestic, "mihomo")
    outputs["dist/shadowrocket/domestic.domain-set"] = render_rules(
        domestic, "shadowrocket"
    )

    meta_base = config["metacubex"]["base"]

    global_url = config["sukka"]["global"]
    global_text = download("sukka/global", global_url)
    global_base_raw, global_keywords, global_ignored = parse_classical_domains(
        global_text,
        global_url,
        allowed_keywords=GLOBAL_KEYWORDS,
    )
    if global_ignored:
        raise ConversionError("Sukka Global contains an unexpected ignored rule")
    if set(global_keywords) != GLOBAL_KEYWORDS:
        raise ConversionError(
            "Sukka Global keyword set changed; expected exactly "
            + ", ".join(sorted(GLOBAL_KEYWORDS))
        )
    global_base_raw, global_marker_removed = drop_sukka_marker(global_base_raw)
    global_base_raw, global_base_excluded = drop_domain_fragments(
        global_base_raw, GLOBAL_DROPPED_KEYWORDS
    )

    configured_global_branches = config["metacubex"]["global_keyword_branches"]
    if set(configured_global_branches) != GLOBAL_EXPANDED_KEYWORDS:
        raise ConversionError(
            "MetaCubeX Global branch mapping must contain exactly "
            + ", ".join(sorted(GLOBAL_EXPANDED_KEYWORDS))
        )
    global_branch_raw_count = 0
    global_branch_rules: list[DomainRule] = []
    global_branch_stats: dict[str, dict[str, object]] = {}
    for keyword in sorted(GLOBAL_EXPANDED_KEYWORDS):
        branch_url = join_url(meta_base, configured_global_branches[keyword])
        branch_text = download(f"metacubex/global/{keyword}", branch_url)
        branch_raw = parse_domain_text(branch_text, branch_url)
        global_branch_raw_count += len(branch_raw)
        branch_kept, branch_excluded = drop_domain_fragments(
            branch_raw, GLOBAL_DROPPED_KEYWORDS
        )
        global_branch_rules.extend(branch_kept)
        global_branch_stats[keyword] = {
            "source_entries": len(branch_raw),
            "entries_after_exclusions": len(branch_kept),
            "excluded_fragments": branch_excluded,
        }

    global_rules, global_duplicates, global_redundant = semantic_minimize(
        [*global_base_raw, *global_branch_rules]
    )
    outputs["dist/mihomo/global.list"] = render_rules(global_rules, "mihomo")

    shadowrocket_stats: dict[str, dict[str, int]] = {}
    for output_name, source_leaf in config["metacubex"]["shadowrocket"].items():
        url = join_url(meta_base, source_leaf)
        text = download(f"metacubex/{output_name}", url)
        raw_rules = parse_domain_text(text, url)
        rules, duplicates, redundant = semantic_minimize(raw_rules)
        outputs[f"dist/shadowrocket/{output_name}.domain-set"] = render_rules(
            rules, "shadowrocket"
        )
        shadowrocket_stats[output_name] = {
            "source_entries": len(raw_rules),
            "output_entries": len(rules),
            "duplicates_removed": duplicates,
            "semantically_redundant_removed": redundant,
        }

    apple_cdn_url = config["sukka"]["apple_cdn"]
    apple_services_url = config["sukka"]["apple_services"]
    apple_cdn_text = download("sukka/apple-cdn", apple_cdn_url)
    apple_services_text = download("sukka/apple-services", apple_services_url)
    apple_cdn_raw = parse_domain_text(apple_cdn_text, apple_cdn_url)
    apple_services_raw, apple_keywords, apple_ignored = parse_classical_domains(
        apple_services_text,
        apple_services_url,
        ignored_rule_types=frozenset({"PROCESS-NAME", "IP-CIDR"}),
    )
    if apple_keywords:
        raise ConversionError("Apple Services unexpectedly produced domain keywords")
    apple_cdn_raw, apple_cdn_marker_removed = drop_sukka_marker(apple_cdn_raw)
    apple_services_raw, apple_services_marker_removed = drop_sukka_marker(
        apple_services_raw
    )
    apple_direct, apple_duplicates, apple_redundant = semantic_minimize(
        [*apple_cdn_raw, *apple_services_raw]
    )
    outputs["dist/mihomo/apple-direct.list"] = render_rules(
        apple_direct, "mihomo"
    )
    outputs["dist/shadowrocket/apple-direct.domain-set"] = render_rules(
        apple_direct, "shadowrocket"
    )

    microsoft_cdn_url = config["sukka"]["microsoft_cdn"]
    microsoft_url = config["sukka"]["microsoft"]
    meta_microsoft_url = join_url(meta_base, config["metacubex"]["microsoft"])
    microsoft_cdn_text = download("sukka/microsoft-cdn", microsoft_cdn_url)
    microsoft_text = download("sukka/microsoft", microsoft_url)
    meta_microsoft_text = download("metacubex/microsoft", meta_microsoft_url)
    microsoft_cdn_raw, microsoft_cdn_keywords, microsoft_cdn_ignored = (
        parse_classical_domains(microsoft_cdn_text, microsoft_cdn_url)
    )
    if microsoft_cdn_keywords or microsoft_cdn_ignored:
        raise ConversionError("Microsoft CDN contains an unexpected non-domain rule")
    microsoft_base_raw, microsoft_keywords, microsoft_ignored = (
        parse_classical_domains(
            microsoft_text,
            microsoft_url,
            allowed_keywords=MICROSOFT_KEYWORDS,
        )
    )
    if microsoft_ignored:
        raise ConversionError("Microsoft contains an unexpected ignored rule")
    if set(microsoft_keywords) != MICROSOFT_KEYWORDS:
        raise ConversionError(
            "Sukka Microsoft keyword set changed; expected exactly "
            + ", ".join(sorted(MICROSOFT_KEYWORDS))
        )
    microsoft_cdn_raw, microsoft_cdn_marker_removed = drop_sukka_marker(
        microsoft_cdn_raw
    )
    microsoft_base_raw, microsoft_marker_removed = drop_sukka_marker(
        microsoft_base_raw
    )
    meta_microsoft = parse_domain_text(meta_microsoft_text, meta_microsoft_url)
    microsoft_expanded, microsoft_expansion_counts = expand_domain_keywords(
        microsoft_keywords, meta_microsoft
    )
    microsoft_cdn, microsoft_cdn_duplicates, microsoft_cdn_redundant = (
        semantic_minimize(microsoft_cdn_raw)
    )
    microsoft_proxy, microsoft_duplicates, microsoft_redundant = semantic_minimize(
        [*microsoft_base_raw, *microsoft_expanded]
    )
    outputs["dist/mihomo/microsoft-cdn.list"] = render_rules(
        microsoft_cdn, "mihomo"
    )
    outputs["dist/mihomo/microsoft.list"] = render_rules(
        microsoft_proxy, "mihomo"
    )

    microsoft_cdn_proxy_overlaps = [
        {
            "cdn_rule": cdn_rule.mihomo(),
            "covered_by_proxy": [
                proxy_rule.mihomo()
                for proxy_rule in microsoft_proxy
                if rule_covers_rule(proxy_rule, cdn_rule)
            ],
        }
        for cdn_rule in microsoft_cdn
        if any(rule_covers_rule(proxy_rule, cdn_rule) for proxy_rule in microsoft_proxy)
    ]

    sukka_game_url = config["sukka"]["game_download"]
    meta_game_url = join_url(meta_base, config["metacubex"]["game_download"])
    sukka_game_text = download("sukka/game-download", sukka_game_url)
    meta_game_text = download("metacubex/game-download", meta_game_url)
    sukka_game = parse_domain_text(sukka_game_text, sukka_game_url)
    sukka_game, sukka_game_marker_removed = drop_sukka_marker(sukka_game)
    meta_game = parse_domain_text(meta_game_text, meta_game_url)
    game_pool = sorted(set(sukka_game) | set(meta_game))

    reviewed = load_allowlist(allowlist_path)
    source_missing: list[str] = []
    covered_by_domestic: list[dict[str, object]] = []
    final_steam: list[DomainRule] = []
    for domain in reviewed:
        source_matches = [rule for rule in game_pool if rule_covers_domain(rule, domain)]
        if not source_matches:
            source_missing.append(domain)
            continue
        domestic_matches = [rule for rule in domestic if rule_covers_domain(rule, domain)]
        if domestic_matches:
            covered_by_domestic.append(
                {
                    "domain": domain,
                    "covered_by": [rule.mihomo() for rule in domestic_matches],
                }
            )
            continue
        final_steam.append(DomainRule("exact", domain))

    final_steam, steam_duplicates, steam_redundant = semantic_minimize(final_steam)
    outputs["dist/mihomo/steam-cn-download.list"] = render_rules(
        final_steam, "mihomo"
    )

    reviewed_set = set(reviewed)
    steam_named_not_reviewed = sorted(
        {
            rule.mihomo()
            for rule in game_pool
            if "steam" in rule.value and rule.value not in reviewed_set
        }
    )
    outputs["reports/steam-named-not-reviewed.txt"] = (
        "\n".join(steam_named_not_reviewed) + "\n"
        if steam_named_not_reviewed
        else ""
    )

    summary = {
        "schema_version": 3,
        "sources": report_sources,
        "domestic": {
            "converted_source_entries": len(domestic_raw),
            "output_entries": len(domestic),
            "sukka_marker_removed": domestic_marker_removed,
            "wildcard_rules_dropped": dropped_wildcard_count,
            "duplicates_removed": domestic_duplicates,
            "semantically_redundant_removed": domestic_redundant,
        },
        "global": {
            "source_scope": [
                global_url,
                *[
                    join_url(meta_base, configured_global_branches[keyword])
                    for keyword in sorted(GLOBAL_EXPANDED_KEYWORDS)
                ],
            ],
            "base_domain_entries": len(global_base_raw),
            "expanded_keywords": sorted(GLOBAL_EXPANDED_KEYWORDS),
            "dropped_keywords": sorted(GLOBAL_DROPPED_KEYWORDS),
            "base_excluded_fragments": global_base_excluded,
            "branch_source_entries": global_branch_raw_count,
            "branches": global_branch_stats,
            "duplicates_removed": global_duplicates,
            "semantically_redundant_removed": global_redundant,
            "sukka_marker_removed": global_marker_removed,
            "output_entries": len(global_rules),
        },
        "apple_direct": {
            "source_scope": [apple_cdn_url, apple_services_url],
            "apple_cdn_domain_entries": len(apple_cdn_raw),
            "apple_services_domain_entries": len(apple_services_raw),
            "ignored_non_domain_rules": apple_ignored,
            "sukka_markers_removed": (
                apple_cdn_marker_removed + apple_services_marker_removed
            ),
            "duplicates_removed": apple_duplicates,
            "semantically_redundant_removed": apple_redundant,
            "output_entries": len(apple_direct),
        },
        "microsoft": {
            "cdn_source": microsoft_cdn_url,
            "proxy_sources": [microsoft_url, meta_microsoft_url],
            "cdn_source_domain_entries": len(microsoft_cdn_raw),
            "cdn_output_entries": len(microsoft_cdn),
            "proxy_base_domain_entries": len(microsoft_base_raw),
            "keyword_expansion_matches": microsoft_expansion_counts,
            "keyword_expansion_unique_entries": len(microsoft_expanded),
            "proxy_output_entries": len(microsoft_proxy),
            "cdn_duplicates_removed": microsoft_cdn_duplicates,
            "cdn_semantically_redundant_removed": microsoft_cdn_redundant,
            "proxy_duplicates_removed": microsoft_duplicates,
            "proxy_semantically_redundant_removed": microsoft_redundant,
            "sukka_markers_removed": (
                microsoft_cdn_marker_removed + microsoft_marker_removed
            ),
            "cdn_rules_also_covered_by_proxy": microsoft_cdn_proxy_overlaps,
            "required_rule_order": ["microsoft-cdn", "microsoft"],
            "shadowrocket_output_generated": False,
        },
        "steam_cn_download": {
            "source_scope": [sukka_game_url, meta_game_url],
            "reviewed_allowlist_entries": len(reviewed),
            "allowlist_missing_from_sources": source_missing,
            "removed_as_domestic_covered": covered_by_domestic,
            "output_entries": [rule.mihomo() for rule in final_steam],
            "duplicates_removed": steam_duplicates,
            "semantically_redundant_removed": steam_redundant,
            "steam_named_unreviewed_count": len(steam_named_not_reviewed),
            "sukka_marker_removed": sukka_game_marker_removed,
        },
        "shadowrocket": shadowrocket_stats,
    }
    outputs["reports/summary.json"] = json.dumps(
        summary, ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"

    report_lines = [
        "# Generated rule report",
        "",
        "This report is deterministic; no build timestamp is embedded.",
        "",
        "## Domestic",
        "",
        f"- Output entries: {len(domestic)}",
        f"- Nonessential classical wildcard rules dropped: {dropped_wildcard_count}",
        f"- Exact duplicates removed: {domestic_duplicates}",
        f"- Semantically redundant entries removed: {domestic_redundant}",
        "",
        "## Apple direct",
        "",
        f"- Apple CDN domain entries: {len(apple_cdn_raw)}",
        f"- Apple Services domain entries: {len(apple_services_raw)}",
        f"- Ignored process rules: {apple_ignored.get('PROCESS-NAME', 0)}",
        f"- Ignored IP rules: {apple_ignored.get('IP-CIDR', 0)}",
        f"- Final combined output entries: {len(apple_direct)}",
        "- MetaCubeX Apple and Apple@CN are intentionally not used.",
        "- The Apple 17.0.0.0/8 rule is intentionally not emitted.",
        "",
        "## Global (Mihomo only)",
        "",
        f"- Sukka explicit domain entries: {len(global_base_raw)}",
        f"- MetaCubeX branch entries before exclusions: {global_branch_raw_count}",
        f"- Final output entries: {len(global_rules)}",
        f"- Exact duplicates removed: {global_duplicates}",
        f"- Semantically redundant entries removed: {global_redundant}",
        "- Expanded branches: " + ", ".join(sorted(GLOBAL_EXPANDED_KEYWORDS)) + ".",
        "- Dropped completely: " + ", ".join(sorted(GLOBAL_DROPPED_KEYWORDS)) + ".",
        "- No Shadowrocket Global provider is generated.",
        "",
        "## Microsoft (Mihomo only)",
        "",
        f"- CDN direct output entries: {len(microsoft_cdn)}",
        f"- Microsoft proxy output entries: {len(microsoft_proxy)}",
        f"- Finite MetaCubeX keyword expansion entries: {len(microsoft_expanded)}",
        f"- CDN rules also covered by the proxy set: {len(microsoft_cdn_proxy_overlaps)}",
        "- Required order: microsoft-cdn (DIRECT), then microsoft (proxy).",
        "- No Microsoft rule is generated for Shadowrocket.",
        "",
        "## Steam China download",
        "",
        f"- Reviewed candidates: {len(reviewed)}",
        f"- Removed because domestic already covers them: {len(covered_by_domestic)}",
        f"- Missing from both permitted game-download sources: {len(source_missing)}",
        f"- Final output entries: {len(final_steam)}",
        "",
    ]
    if final_steam:
        report_lines.extend(["Final entries:", ""])
        report_lines.extend(f"- `{rule.mihomo()}`" for rule in final_steam)
        report_lines.append("")
    if source_missing:
        report_lines.extend(["Missing reviewed entries:", ""])
        report_lines.extend(f"- `{domain}`" for domain in source_missing)
        report_lines.append("")
    report_lines.extend(
        [
            "## Shadowrocket",
            "",
            f"- Generated domain sets: {len(shadowrocket_stats) + 2}",
            f"- Static hand-maintained domain sets: {len(STATIC_OUTPUTS)}",
            "- APNS and IP rule sets are intentionally not generated by this project.",
            "",
        ]
    )
    outputs["reports/update-report.md"] = "\n".join(report_lines)
    return outputs


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--steam-allowlist", type=Path, default=DEFAULT_STEAM_ALLOWLIST)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero when generated files differ; do not write them.",
    )
    args = parser.parse_args(argv)

    try:
        generated = build(args.sources, args.steam_allowlist)
        stale = sorted(managed_files() - set(generated))
        changed: list[str] = []
        for relative, content in sorted(generated.items()):
            destination = ROOT / relative
            old = destination.read_text(encoding="utf-8") if destination.exists() else None
            if old != content:
                changed.append(relative)
                if not args.check:
                    atomic_write(destination, content)
        if not args.check:
            for relative in stale:
                (ROOT / relative).unlink()
        if args.check and (changed or stale):
            print("Generated files are out of date:", file=sys.stderr)
            for relative in changed:
                print(f"  changed: {relative}", file=sys.stderr)
            for relative in stale:
                print(f"  stale: {relative}", file=sys.stderr)
            return 1
        print(
            f"Generated {len(generated)} files; changed {len(changed)}, "
            f"removed {len(stale)} stale files."
            if not args.check
            else f"Generated files are current ({len(generated)} checked)."
        )
        return 0
    except (ConversionError, OSError, json.JSONDecodeError) as exc:
        print(f"conversion failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
