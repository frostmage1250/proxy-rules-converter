#!/usr/bin/env python3
"""Extend Bett's AI MRS with three reviewed domain rules using Mihomo itself."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from convert_mrs import resolve_mihomo
from convert_rules import DomainRule, parse_domain_text, render_rules, rule_covers_domain

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCES = ROOT / "config" / "sources.json"
DEFAULT_OUTPUT = ROOT / "dist" / "mihomo" / "ai.mrs"
DEFAULT_TEXT_OUTPUT = ROOT / "dist" / "mihomo" / "ai.list"
DEFAULT_REPORT = ROOT / "reports" / "ai.json"
USER_AGENT = "rules-converter-action/2.0 (+https://github.com/frostmage1250/proxy-rules-converter)"
AI_SUPPLEMENTS = (
    DomainRule("suffix", "webpubsub.azure.com"),
    DomainRule("exact", "client-api.arkoselabs.com"),
    DomainRule("exact", "openai-api.arkoselabs.com"),
)


class AIConversionError(RuntimeError):
    """The upstream MRS could not be decoded or safely extended."""


def merge_ai_rules(upstream: list[DomainRule]) -> tuple[list[DomainRule], list[DomainRule]]:
    """Keep every decoded upstream rule and append only uncovered supplements."""

    added = [
        rule
        for rule in AI_SUPPLEMENTS
        if not any(rule_covers_domain(source_rule, rule.value) for source_rule in upstream)
    ]
    return [*upstream, *added], added


def convert(mihomo: Path, source_format: str, source: Path, destination: Path) -> None:
    result = subprocess.run(
        [str(mihomo), "convert-ruleset", "domain", source_format, str(source), str(destination)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0 or not destination.is_file() or not destination.stat().st_size:
        detail = (result.stderr or result.stdout).strip()
        raise AIConversionError(
            f"Mihomo could not convert {source.name} from {source_format}: {detail or 'empty output'}"
        )


def download_mrs(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=45) as response:
        if getattr(response, "status", 200) != 200:
            raise AIConversionError(f"HTTP {response.status} while downloading {url}")
        content = response.read()
    if not content:
        raise AIConversionError(f"Empty upstream MRS: {url}")
    return content


def covers(rule: DomainRule, candidate: list[DomainRule]) -> bool:
    probes = [rule.value]
    if rule.kind != "exact":
        probes.append("subdomain-probe." + rule.value)
    if rule.kind == "subdomain_suffix":
        probes = probes[1:]
    return all(any(rule_covers_domain(item, domain) for item in candidate) for domain in probes)


def build(
    mihomo: Path,
    source_url: str,
    output: Path,
    text_output: Path,
    report_path: Path,
    check: bool,
) -> bool:
    upstream_bytes = download_mrs(source_url)
    with tempfile.TemporaryDirectory(prefix="ai-mrs-") as directory:
        temp = Path(directory)
        upstream_mrs = temp / "upstream.mrs"
        upstream_text = temp / "upstream.txt"
        merged_text = temp / "merged.txt"
        candidate_mrs = temp / "ai.mrs"
        candidate_text = temp / "candidate.txt"
        upstream_mrs.write_bytes(upstream_bytes)
        convert(mihomo, "mrs", upstream_mrs, upstream_text)
        upstream_rules = parse_domain_text(upstream_text.read_text(encoding="utf-8"), source_url)
        merged_rules, added = merge_ai_rules(upstream_rules)
        merged_text.write_text(render_rules(merged_rules, "mihomo"), encoding="utf-8", newline="\n")
        convert(mihomo, "text", merged_text, candidate_mrs)
        convert(mihomo, "mrs", candidate_mrs, candidate_text)
        candidate_rules = parse_domain_text(candidate_text.read_text(encoding="utf-8"), str(candidate_mrs))

        if not all(covers(rule, candidate_rules) for rule in merged_rules):
            raise AIConversionError("Recompiled AI MRS lost an upstream or supplemental rule")
        if any(rule.mihomo() not in [item.mihomo() for item in candidate_rules] for rule in added):
            raise AIConversionError("Recompiled AI MRS changed a requested suffix or exact rule")

        candidate_bytes = candidate_mrs.read_bytes()
        candidate_list_text = render_rules(candidate_rules, "mihomo")
        report = {
            "schema_version": 1,
            "source": source_url,
            "source_sha256": hashlib.sha256(upstream_bytes).hexdigest(),
            "source_bytes": len(upstream_bytes),
            "decoded_upstream_rules": len(upstream_rules),
            "added_rules": [rule.mihomo() for rule in added],
            "output_rules": len(candidate_rules),
            "output_sha256": hashlib.sha256(candidate_bytes).hexdigest(),
            "output_text_sha256": hashlib.sha256(candidate_list_text.encode("utf-8")).hexdigest(),
        }
        report_text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        old_bytes = output.read_bytes() if output.exists() else None
        old_report = report_path.read_text(encoding="utf-8") if report_path.exists() else None
        old_text = text_output.read_text(encoding="utf-8") if text_output.exists() else None
        changed = old_bytes != candidate_bytes or old_text != candidate_list_text or old_report != report_text
        if changed and not check:
            output.parent.mkdir(parents=True, exist_ok=True)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            os.replace(candidate_mrs, output)
            text_output.parent.mkdir(parents=True, exist_ok=True)
            text_output.write_text(candidate_list_text, encoding="utf-8", newline="\n")
            report_path.write_text(report_text, encoding="utf-8", newline="\n")
        return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--text-output", type=Path, default=DEFAULT_TEXT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--mihomo", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        config = json.loads(args.sources.read_text(encoding="utf-8"))
        bett = config["bett"]
        source_url = bett["geosite_base"].rstrip("/") + "/" + bett["ai_mrs"].lstrip("/")
        changed = build(
            resolve_mihomo(args.mihomo), source_url, args.output, args.text_output, args.report, args.check
        )
        if args.check and changed:
            raise AIConversionError("Generated AI MRS or provenance report is out of date")
        print(f"AI MRS {'checked' if args.check else 'generated'}; changed: {changed}")
        return 0
    except (AIConversionError, OSError, ValueError, KeyError, urllib.error.URLError) as exc:
        print(f"AI MRS build failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
