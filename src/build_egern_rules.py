#!/usr/bin/env python3
"""Publish Egern-native rule sets from the Mihomo provider model."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any

import yaml

from convert_rules import ConversionError, merge_apple_rules, parse_domain_text, render_rules

ROOT = Path(__file__).resolve().parents[1]
RULE_DIR = ROOT / "dist" / "egern"
REPORT_PATH = ROOT / "reports" / "egern-source.json"
MIHOMO_REPO = "frostmage1250/mihomo-script"
BETT_REPO = "appshubcc/bett-rules"
CONVERTER_REPO = "frostmage1250/proxy-rules-converter"
CONVERTER_GEOLOCATION_LIST_PATH = "dist/mihomo/geolocation-cn.list"
CONVERTER_GEOLOCATION_REPORT_PATH = "reports/geolocation-cn.json"
CONVERTER_CLAUDE_RULE_PATH = "dist/mihomo/claude.yaml"
APNS_REPO = "ttyyss2233/Tool"
APNS_PATH = "shadowrocket/rules/apns.list"
APNS_FILENAME = "apns.yaml"
NON_SERVICE_IP_PROVIDERS = {"cn_ip", "private_ip"}

class BuildError(RuntimeError):
    pass


def slug(name: str) -> str:
    aliases = {
        "geolocation-!cn": "geolocation-non-cn",
        "mcdn屏蔽": "mcdn-block",
        "private_ip": "private-ip",
        "cn_ip": "cn-ip",
        "google_ip": "google-ip",
        "microsoft_ip": "microsoft-ip",
        "apple_ip": "apple-ip",
        "telegram_ip": "telegram-ip",
        "steam_ip": "steam-ip",
        "tiktok_ip": "tiktok-ip",
        "twitter_ip": "twitter-ip",
        "facebook_ip": "facebook-ip",
        "fakeip_filter": "fakeip-filter",
    }
    value = aliases.get(name, name.replace("_", "-").replace("!", "not-"))
    value = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-").lower()
    if not value:
        raise BuildError(f"Provider name cannot become a file name: {name!r}")
    return value


def resolve_provider_source(
    provider: dict[str, Any],
    *,
    bett_commit: str,
    converter_commit: str,
) -> dict[str, str]:
    provider_url = provider.get("url")
    if not isinstance(provider_url, str) or not provider_url:
        raise BuildError(f"Provider has no final URL: {provider}")

    parsed = urlsplit(provider_url)
    repository: str
    ref: str
    published_path: str
    if parsed.netloc == "fastly.jsdelivr.net":
        match = re.fullmatch(
            r"/gh/([^/]+/[^/@]+)@([^/]+)/(.+\.mrs)",
            parsed.path,
        )
        if not match:
            raise BuildError(f"Unsupported jsDelivr provider URL: {provider_url}")
        repository, ref, published_path = match.groups()
    elif parsed.netloc == "raw.githubusercontent.com":
        match = re.fullmatch(
            r"/([^/]+/[^/]+)/([^/]+)/(.+)",
            parsed.path,
        )
        if not match:
            raise BuildError(f"Unsupported raw GitHub provider URL: {provider_url}")
        repository, ref, published_path = match.groups()
    else:
        raise BuildError(f"Unsupported provider URL host: {provider_url}")

    if published_path.endswith(".mrs"):
        source_path = published_path.removesuffix(".mrs") + ".list"
    elif published_path.endswith(".yaml"):
        source_path = published_path
    else:
        raise BuildError(f"Unsupported provider artifact: {provider_url}")

    if repository == BETT_REPO and ref == "meta":
        if not published_path.endswith(".mrs"):
            raise BuildError(f"Unsupported bett-rules provider artifact: {provider_url}")
        commit = bett_commit
    elif repository == CONVERTER_REPO and ref == "main":
        allowed = {
            "dist/mihomo/geolocation-cn.mrs": CONVERTER_GEOLOCATION_LIST_PATH,
            "dist/mihomo/ai.mrs": "dist/mihomo/ai.list",
            "dist/mihomo/apple-merged.mrs": "dist/mihomo/apple-merged.list",
            "dist/mihomo/bypass-japan.mrs": "dist/mihomo/bypass-japan.list",
            "dist/mihomo/mcdn-block.mrs": "dist/mihomo/mcdn-block.list",
            CONVERTER_CLAUDE_RULE_PATH: CONVERTER_CLAUDE_RULE_PATH,
        }
        expected_source = allowed.get(published_path)
        if expected_source is None:
            raise BuildError(
                f"Unsupported proxy-rules-converter provider path: {published_path}"
            )
        source_path = expected_source
        commit = converter_commit
    else:
        raise BuildError(
            f"Unsupported provider source {repository}@{ref}: {provider_url}"
        )

    return {
        "provider_url": provider_url,
        "repository": repository,
        "ref": ref,
        "commit": commit,
        "path": source_path,
        "url": (
            f"https://raw.githubusercontent.com/{repository}/{commit}/{source_path}"
        ),
    }


def download_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "egern-config-builder/1"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if getattr(response, "status", 200) != 200:
                raise BuildError(f"HTTP error while fetching {url}")
            return response.read().decode("utf-8-sig")
    except urllib.error.URLError as exc:
        raise BuildError(f"Failed to download {url}: {exc}") from exc


def merge_privaterelay_sources(
    bett_text: str, sukka_text: str, excluded_domains: list[str]
) -> tuple[str, dict[str, Any]]:
    """Retain Bett rules and append only uncovered Sukka endpoint scopes."""
    if not bett_text.strip() or not sukka_text.strip():
        raise BuildError("Private Relay upstream domain sets must be nonempty")
    primary = parse_domain_text(bett_text, "Bett iCloud Private Relay")
    excluded = set(excluded_domains)
    supplement = [
        rule for rule in parse_domain_text(sukka_text, "Sukka iCloud Private Relay")
        if rule.value not in excluded
    ]
    if not primary or not supplement:
        raise BuildError("Private Relay upstream domain sets must be nonempty")
    merged = merge_apple_rules(primary, supplement)
    return render_rules(merged, "mihomo"), {
        "bett_entries": len(primary),
        "sukka_eligible_entries": len(supplement),
        "supplemented_entries": len(merged) - len(primary),
        "supplemented_rules": [rule.mihomo() for rule in merged[len(primary):]],
        "bett_order_and_duplicates_preserved": True,
        "excluded_domains": excluded_domains,
    }


def source_rule_count(text: str) -> int:
    return sum(
        1
        for raw in text.splitlines()
        if (line := raw.strip()) and not line.startswith(("#", ";", "//"))
    )


def output_rule_count(rules: list[dict[str, Any]]) -> int:
    return sum(
        len(values)
        for rule in rules
        for values in rule.values()
        if isinstance(values, list)
    )


def merge_ordered_rules(segments: list[dict[str, Any]]) -> dict[str, Any]:
    """Collect native Egern fields without changing count or per-type order."""
    native: dict[str, Any] = {}
    has_ip = False
    for segment in segments:
        fields = [(field, values) for field, values in segment.items() if isinstance(values, list)]
        if len(fields) != 1:
            raise BuildError("Source segment must contain exactly one rule type")
        field, values = fields[0]
        if not values:
            raise BuildError(f"Empty source segment: {field}")
        native.setdefault(field, []).extend(values)
        if field in {"ip_cidr_set", "ip_cidr6_set", "asn_set"}:
            if segment.get("no_resolve") is not True:
                raise BuildError(f"IP/ASN source must use no_resolve: {field}")
            has_ip = True
    if not native:
        raise BuildError("Source produced an empty Egern rule set")
    if has_ip:
        native["no_resolve"] = True
    return native


def rule_sequence(rule: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        (field, value)
        for field, values in rule.items()
        if isinstance(values, list)
        for value in values
    ]


def source_lines(text: str) -> list[str]:
    return [
        line
        for raw in text.splitlines()
        if (line := raw.strip()) and not line.startswith(("#", ";", "//"))
    ]


def append_ordered_rule(
    segments: list[dict[str, Any]], field: str, value: str, *, no_resolve: bool = False
) -> None:
    if not value:
        raise BuildError(f"Empty {field} rule")
    if segments and field in segments[-1] and segments[-1].get("no_resolve", False) == no_resolve:
        segments[-1][field].append(value)
        return
    segment: dict[str, Any] = {field: [value]}
    if no_resolve:
        segment["no_resolve"] = True
    segments.append(segment)


def parse_domain_list(text: str) -> list[dict[str, Any]]:
    segments: list[dict[str, Any]] = []
    for line in source_lines(text):
        if line.startswith("+."):
            field, value = "domain_suffix_set", line[2:]
        elif line.startswith("full:"):
            field, value = "domain_set", line[5:]
        elif line.startswith("domain:"):
            field, value = "domain_suffix_set", line[7:]
        elif line.startswith("keyword:"):
            field, value = "domain_keyword_set", line[8:]
        elif line.startswith(("regexp:", "regex:")):
            field, value = "domain_regex_set", line.split(":", 1)[1]
        elif "*" in line or "?" in line:
            field, value = "domain_wildcard_set", line
        else:
            field, value = "domain_set", line
        append_ordered_rule(segments, field, value)
    if not segments:
        raise BuildError("Domain source produced an empty rule set")
    return segments


def parse_ip_list(text: str) -> list[dict[str, Any]]:
    segments: list[dict[str, Any]] = []
    for line in source_lines(text):
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError as exc:
            raise BuildError(f"Invalid IP network {line!r}") from exc
        field = "ip_cidr_set" if network.version == 4 else "ip_cidr6_set"
        append_ordered_rule(segments, field, line, no_resolve=True)
    if not segments:
        raise BuildError("IP source produced an empty rule set")
    return segments


def parse_classical_rule_list(text: str) -> list[dict[str, Any]]:
    segments: list[dict[str, Any]] = []
    for line in source_lines(text):
        parts = [part.strip() for part in line.split(",")]
        kind = parts[0]
        if len(parts) < 2 or not parts[1]:
            raise BuildError(f"Invalid classical rule: {line!r}")
        value = parts[1]
        fields = {
            "DOMAIN": "domain_set",
            "DOMAIN-KEYWORD": "domain_keyword_set",
            "DOMAIN-SUFFIX": "domain_suffix_set",
            "IP-CIDR": "ip_cidr_set",
            "IP-CIDR6": "ip_cidr6_set",
            "IP-ASN": "asn_set",
        }
        field = fields.get(kind)
        if field is None:
            raise BuildError(f"Unsupported classical rule: {line!r}")
        is_ip = kind in {"IP-CIDR", "IP-CIDR6", "IP-ASN"}
        if is_ip and "no-resolve" not in parts[2:]:
            raise BuildError(f"Classical IP/ASN rule must use no-resolve: {line!r}")
        if kind in {"IP-CIDR", "IP-CIDR6"}:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise BuildError(f"Invalid classical IP network {value!r}") from exc
            if network.version != (4 if kind == "IP-CIDR" else 6):
                raise BuildError(f"{kind} has the wrong address family: {value!r}")
        elif kind == "IP-ASN" and not re.fullmatch(r"(?:AS)?[1-9][0-9]*", value, re.I):
            raise BuildError(f"Invalid classical ASN {value!r}")
        append_ordered_rule(segments, field, value, no_resolve=is_ip)
    if not segments:
        raise BuildError("Classical source produced an empty rule set")
    return segments


def parse_classical_yaml_provider(text: str) -> tuple[list[dict[str, Any]], int]:
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise BuildError("Classical provider is not valid YAML") from exc
    if not isinstance(document, dict) or set(document) != {"payload"}:
        raise BuildError("Classical YAML provider must contain only payload")
    payload = document["payload"]
    if (
        not isinstance(payload, list)
        or not payload
        or any(not isinstance(line, str) or not line.strip() for line in payload)
    ):
        raise BuildError("Classical YAML payload must be a non-empty string list")
    lines = [line.strip() for line in payload]
    return parse_classical_rule_list("\n".join(lines)), len(lines)


def referenced_providers(model: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for rule in model["rules"]:
        parts = rule.split(",")
        if parts[0] == "RULE-SET" and len(parts) >= 3:
            result.append(parts[1])
    for key in model.get("dns", {}).get("nameserver-policy", {}):
        if isinstance(key, str) and key.startswith("rule-set:"):
            result.append(key.removeprefix("rule-set:"))
    return list(dict.fromkeys(result))


def validate_business_ip_pairs(model: dict[str, Any]) -> None:
    rules = model["rules"]
    providers = model["providers"]
    for index, raw in enumerate(rules):
        parts = raw.split(",")
        if parts[0] != "RULE-SET" or len(parts) < 3:
            continue
        provider = parts[1]
        definition = providers.get(provider, {})
        if (
            definition.get("behavior") != "ipcidr"
            or provider in NON_SERVICE_IP_PROVIDERS
        ):
            continue
        if parts[-1] != "no-resolve":
            raise BuildError(
                f"Business IP provider must use no-resolve: {provider}"
            )
        if index == 0:
            raise BuildError(f"Business IP provider has no domain pair: {provider}")
        previous = rules[index - 1].split(",")
        previous_no_resolve = previous[-1] == "no-resolve"
        previous_policy = previous[-2] if previous_no_resolve else previous[-1]
        policy = parts[-2]
        if (
            previous[0] != "RULE-SET"
            or len(previous) < 3
            or providers.get(previous[1], {}).get("behavior") != "domain"
            or previous_policy != policy
        ):
            raise BuildError(
                f"Business IP provider must immediately follow its domain pair: {provider}"
            )



def write_or_check(path: Path, content: str, check: bool) -> bool:
    current = path.read_text(encoding="utf-8") if path.exists() else None
    changed = current != content
    if changed and not check:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--mihomo-commit", required=True)
    parser.add_argument("--bett-commit", required=True)
    parser.add_argument("--apns-commit", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    try:
        model = json.loads(args.model.read_text(encoding="utf-8"))
        providers = model["providers"]
        validate_business_ip_pairs(model)
        wanted = referenced_providers(model)
        # Publish the reviewed local set before consumers begin referencing it.
        mcdn_source = (ROOT / "dist/mihomo/mcdn-block.list").read_text(encoding="utf-8")
        mcdn_native = merge_ordered_rules(parse_domain_list(mcdn_source))
        generated: dict[str, str] = {
            "mcdn-block.yaml": yaml.safe_dump(
                mcdn_native, allow_unicode=True, sort_keys=False, width=1000
            )
        }
        apple_source = (ROOT / "dist/mihomo/apple-merged.list").read_text(encoding="utf-8")
        generated["apple-merged.yaml"] = yaml.safe_dump(
            merge_ordered_rules(parse_domain_list(apple_source)),
            allow_unicode=True, sort_keys=False, width=1000,
        )
        source_records: list[dict[str, Any]] = []

        geo_report_text = (ROOT / CONVERTER_GEOLOCATION_REPORT_PATH).read_text(encoding="utf-8")
        geo_report = json.loads(geo_report_text)
        geo_expected_entries = geo_report.get("mrs_compatible_entries")
        geo_expected_sha256 = geo_report.get("sha256", {}).get("domain_list")
        if (
            not isinstance(geo_expected_entries, int)
            or geo_expected_entries <= 0
            or not isinstance(geo_expected_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", geo_expected_sha256)
        ):
            raise BuildError("Invalid geolocation-cn report")

        def register(
            name: str,
            behavior: str,
            source: str,
            segments: list[dict[str, Any]],
            source_entries: int,
            metadata: dict[str, Any],
        ) -> None:
            entries = output_rule_count(segments)
            if entries != source_entries:
                raise BuildError(
                    f"{name} conversion changed the rule count: {source_entries} -> {entries}"
                )
            source_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
            if name == "geolocation-cn" and (
                entries != geo_expected_entries or source_sha256 != geo_expected_sha256
            ):
                raise BuildError("geolocation-cn disagrees with the converter report")
            filename = (
                "apple-merged.yaml"
                if name == "apple" and metadata.get("source_path") == "dist/mihomo/apple-merged.list"
                else slug(name) + ".yaml"
            )
            output = f"dist/egern/{filename}"
            native_rule = merge_ordered_rules(segments)
            if output_rule_count([native_rule]) != source_entries:
                raise BuildError(f"{name} native YAML changed the rule count")
            source_sequence = [
                (field, value)
                for segment in segments
                for field, values in segment.items()
                if isinstance(values, list)
                for value in values
            ]
            rule_text = yaml.safe_dump(
                native_rule, allow_unicode=True, sort_keys=False, width=1000
            )
            generated[filename] = rule_text
            record: dict[str, Any] = {
                "provider": name,
                "behavior": behavior,
                **metadata,
                "source_entries": source_entries,
                "entries": entries,
                "source_sha256": source_sha256,
                "source_order_sha256": hashlib.sha256(
                    json.dumps(source_sequence, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                ).hexdigest(),
                "native_entries_sha256": hashlib.sha256(
                    json.dumps(rule_sequence(native_rule), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                ).hexdigest(),
                "output": output,
                "output_sha256": hashlib.sha256(rule_text.encode("utf-8")).hexdigest(),
            }
            if name == "geolocation-cn":
                record["expected_entries"] = geo_expected_entries
            source_records.append(record)

        apns_url = (
            f"https://raw.githubusercontent.com/{APNS_REPO}/{args.apns_commit}/{APNS_PATH}"
        )
        apns_source = download_text(apns_url)
        register(
            "apns", "classical", apns_source,
            parse_classical_rule_list(apns_source), source_rule_count(apns_source),
            {
                "source_repository": APNS_REPO,
                "source_ref": "main",
                "source_commit": args.apns_commit,
                "source_path": APNS_PATH,
                "source_url": apns_url,
            },
        )

        for name in wanted:
            provider = providers.get(name)
            if provider is None:
                raise BuildError(f"Mihomo model is missing provider {name}")
            source_info = resolve_provider_source(
                provider, bett_commit=args.bett_commit, converter_commit="main"
            )
            if source_info["repository"] == CONVERTER_REPO:
                source = (ROOT / source_info["path"]).read_text(encoding="utf-8")
            else:
                source = download_text(source_info["url"])
            behavior = provider.get("behavior")
            if behavior == "domain":
                segments = parse_domain_list(source)
                source_entries = source_rule_count(source)
            elif behavior == "ipcidr":
                segments = parse_ip_list(source)
                source_entries = source_rule_count(source)
            elif behavior == "classical":
                segments, source_entries = parse_classical_yaml_provider(source)
            else:
                raise BuildError(f"Unsupported provider behavior {behavior!r} for {name}")
            register(
                name, behavior, source, segments, source_entries,
                {
                    "provider_url": source_info["provider_url"],
                    "source_repository": source_info["repository"],
                    "source_ref": source_info["ref"],
                    "source_commit": (
                        None if source_info["repository"] == CONVERTER_REPO
                        else source_info["commit"]
                    ),
                    "source_path": source_info["path"],
                    "source_url": source_info["url"],
                    "source_generated_in_same_run": source_info["repository"] == CONVERTER_REPO,
                },
            )

        private_config = json.loads((ROOT / "config/sources.json").read_text(encoding="utf-8"))["privaterelay"]
        bett_private_url = (
            f"https://raw.githubusercontent.com/{BETT_REPO}/{args.bett_commit}/"
            f"{private_config['bett_path']}"
        )
        sukka_private_url = private_config["sukka_url"]
        bett_private_text = download_text(bett_private_url)
        sukka_private_text = download_text(sukka_private_url)
        private_source, private_merge = merge_privaterelay_sources(
            bett_private_text, sukka_private_text, private_config["excluded_domains"]
        )
        register(
            "privaterelay", "domain", private_source,
            parse_domain_list(private_source), source_rule_count(private_source),
            {
                "egern_only": True,
                **private_merge,
                "upstream_sources": [
                    {
                        "name": "bett-rules", "repository": BETT_REPO,
                        "ref": "meta", "commit": args.bett_commit,
                        "path": private_config["bett_path"], "url": bett_private_url,
                        "sha256": hashlib.sha256(bett_private_text.encode("utf-8")).hexdigest(),
                    },
                    {
                        "name": "Sukka", "url": sukka_private_url,
                        "sha256": hashlib.sha256(sukka_private_text.encode("utf-8")).hexdigest(),
                    },
                ],
            },
        )
        egern_only_records = [source_records.pop()]

        changed: list[str] = []
        for filename, rule_text in generated.items():
            if write_or_check(RULE_DIR / filename, rule_text, args.check):
                changed.append(f"dist/egern/{filename}")
        for stale in RULE_DIR.glob("*.yaml"):
            if stale.name not in generated:
                changed.append(f"dist/egern/{stale.name}")
                if not args.check:
                    stale.unlink()

        report_data = {
            "schema_version": 3,
            "mihomo_script": {"repository": MIHOMO_REPO, "commit": args.mihomo_commit},
            "bett_rules": {"repository": BETT_REPO, "branch": "meta", "commit": args.bett_commit},
            "apns_rules": {
                "repository": APNS_REPO,
                "branch": "main",
                "path": APNS_PATH,
                "commit": args.apns_commit,
            },
            "geolocation_cn": {
                "list_path": CONVERTER_GEOLOCATION_LIST_PATH,
                "report_path": CONVERTER_GEOLOCATION_REPORT_PATH,
                "report_sha256": hashlib.sha256(geo_report_text.encode("utf-8")).hexdigest(),
                "expected_entries": geo_expected_entries,
            },
            "native_rule_sets": source_records,
            "egern_only_rule_sets": egern_only_records,
        }
        report_text = json.dumps(report_data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if write_or_check(REPORT_PATH, report_text, args.check):
            changed.append("reports/egern-source.json")
        if args.check and changed:
            raise BuildError("Generated files are out of date: " + ", ".join(changed))
        print(f"Generated {len(generated)} one-file Egern-native rule sets.")
        return 0
    except (BuildError, ConversionError, OSError, ValueError, KeyError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"Build failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
