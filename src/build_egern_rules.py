#!/usr/bin/env python3
"""Publish Egern-native rule sets from the Mihomo provider model."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any

import yaml

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


def unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def slug(name: str) -> str:
    aliases = {
        "geolocation-!cn": "geolocation-non-cn",
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
    with urllib.request.urlopen(request, timeout=60) as response:
        if getattr(response, "status", 200) != 200:
            raise BuildError(f"HTTP error while fetching {url}")
        return response.read().decode("utf-8-sig")


def source_rule_count(text: str) -> int:
    return sum(
        1
        for raw in text.splitlines()
        if (line := raw.strip()) and not line.startswith(("#", ";", "//"))
    )


def output_rule_count(rule: dict[str, Any]) -> int:
    return sum(len(value) for value in rule.values() if isinstance(value, list))


def parse_domain_list(text: str) -> dict[str, Any]:
    fields: dict[str, list[str]] = {
        "domain_set": [],
        "domain_keyword_set": [],
        "domain_suffix_set": [],
        "domain_regex_set": [],
        "domain_wildcard_set": [],
    }
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        if line.startswith("+."):
            fields["domain_suffix_set"].append(line[2:])
        elif line.startswith("full:"):
            fields["domain_set"].append(line[5:])
        elif line.startswith("domain:"):
            fields["domain_suffix_set"].append(line[7:])
        elif line.startswith("keyword:"):
            fields["domain_keyword_set"].append(line[8:])
        elif line.startswith(("regexp:", "regex:")):
            fields["domain_regex_set"].append(line.split(":", 1)[1])
        elif "*" in line or "?" in line:
            fields["domain_wildcard_set"].append(line)
        else:
            fields["domain_set"].append(line)
    result = {key: value for key, value in fields.items() if value}
    if not result:
        raise BuildError("Domain source produced an empty rule set")
    return result


def parse_ip_list(text: str) -> dict[str, Any]:
    ipv4: list[str] = []
    ipv6: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError as exc:
            raise BuildError(f"Invalid IP network {line!r}") from exc
        target = ipv4 if network.version == 4 else ipv6
        target.append(line)
    result: dict[str, Any] = {"no_resolve": True}
    if ipv4:
        result["ip_cidr_set"] = ipv4
    if ipv6:
        result["ip_cidr6_set"] = ipv6
    if len(result) == 1:
        raise BuildError("IP source produced an empty rule set")
    return result


def parse_classical_rule_list(text: str) -> dict[str, Any]:
    fields: dict[str, list[str]] = {
        "domain_set": [],
        "domain_keyword_set": [],
        "domain_suffix_set": [],
        "ip_cidr_set": [],
        "ip_cidr6_set": [],
        "asn_set": [],
    }
    ip_rule_count = 0
    no_resolve_ip_rule_count = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        parts = [part.strip() for part in line.split(",")]
        kind = parts[0]
        if len(parts) < 2 or not parts[1]:
            raise BuildError(f"Invalid classical rule: {line!r}")
        value = parts[1]
        if kind == "DOMAIN":
            fields["domain_set"].append(value)
        elif kind == "DOMAIN-KEYWORD":
            fields["domain_keyword_set"].append(value)
        elif kind == "DOMAIN-SUFFIX":
            fields["domain_suffix_set"].append(value)
        elif kind in {"IP-CIDR", "IP-CIDR6"}:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise BuildError(f"Invalid classical IP network {value!r}") from exc
            expected_version = 4 if kind == "IP-CIDR" else 6
            if network.version != expected_version:
                raise BuildError(f"{kind} has the wrong address family: {value!r}")
            target = "ip_cidr_set" if network.version == 4 else "ip_cidr6_set"
            fields[target].append(value)
            ip_rule_count += 1
            no_resolve_ip_rule_count += int("no-resolve" in parts[2:])
        elif kind == "IP-ASN":
            if not re.fullmatch(r"(?:AS)?[1-9][0-9]*", value, re.I):
                raise BuildError(f"Invalid classical ASN {value!r}")
            fields["asn_set"].append(value)
            ip_rule_count += 1
            no_resolve_ip_rule_count += int("no-resolve" in parts[2:])
        else:
            raise BuildError(f"Unsupported classical rule: {line!r}")
    if ip_rule_count != no_resolve_ip_rule_count:
        raise BuildError("Every classical IP/ASN rule must use no-resolve")
    result: dict[str, Any] = {
        key: values for key, values in fields.items() if values
    }
    if ip_rule_count:
        result["no_resolve"] = True
    if not result or result == {"no_resolve": True}:
        raise BuildError("Classical source produced an empty rule set")
    return result


def parse_classical_yaml_provider(text: str) -> tuple[dict[str, Any], int]:
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
    return unique(result)


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
        generated: dict[str, dict[str, Any]] = {}
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

        apns_url = (
            f"https://raw.githubusercontent.com/{APNS_REPO}/{args.apns_commit}/{APNS_PATH}"
        )
        apns_source = download_text(apns_url)
        apns_rule = parse_classical_rule_list(apns_source)
        apns_source_entries = source_rule_count(apns_source)
        if output_rule_count(apns_rule) != apns_source_entries:
            raise BuildError("APNs conversion changed the rule count")
        generated[APNS_FILENAME] = apns_rule
        source_records.append({
            "provider": "apns",
            "behavior": "classical",
            "source_repository": APNS_REPO,
            "source_ref": "main",
            "source_commit": args.apns_commit,
            "source_path": APNS_PATH,
            "source_url": apns_url,
            "output": f"dist/egern/{APNS_FILENAME}",
            "source_entries": apns_source_entries,
            "entries": output_rule_count(apns_rule),
            "source_sha256": hashlib.sha256(apns_source.encode("utf-8")).hexdigest(),
        })

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
                rule = parse_domain_list(source)
                source_entries = source_rule_count(source)
            elif behavior == "ipcidr":
                rule = parse_ip_list(source)
                source_entries = source_rule_count(source)
            elif behavior == "classical":
                rule, source_entries = parse_classical_yaml_provider(source)
            else:
                raise BuildError(f"Unsupported provider behavior {behavior!r} for {name}")

            entries = output_rule_count(rule)
            if entries != source_entries:
                raise BuildError(
                    f"{name} conversion changed the rule count: {source_entries} -> {entries}"
                )
            source_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
            filename = slug(name) + ".yaml"
            record: dict[str, Any] = {
                "provider": name,
                "behavior": behavior,
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
                "output": f"dist/egern/{filename}",
                "source_entries": source_entries,
                "entries": entries,
                "source_sha256": source_sha256,
            }
            if name == "geolocation-cn":
                if (
                    source_info["repository"] != CONVERTER_REPO
                    or source_info["path"] != CONVERTER_GEOLOCATION_LIST_PATH
                    or entries != geo_expected_entries
                    or source_sha256 != geo_expected_sha256
                ):
                    raise BuildError("geolocation-cn disagrees with the converter report")
                record["expected_entries"] = geo_expected_entries
            generated[filename] = rule
            source_records.append(record)

        yaml_options = dict(allow_unicode=True, sort_keys=False, width=1000)
        changed: list[str] = []
        for record in source_records:
            filename = Path(record["output"]).name
            rule_text = yaml.safe_dump(generated[filename], **yaml_options)
            record["output_sha256"] = hashlib.sha256(rule_text.encode("utf-8")).hexdigest()
            if write_or_check(RULE_DIR / filename, rule_text, args.check):
                changed.append(record["output"])

        report_data = {
            "schema_version": 1,
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
        }
        report_text = json.dumps(report_data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if write_or_check(REPORT_PATH, report_text, args.check):
            changed.append("reports/egern-source.json")
        if args.check and changed:
            raise BuildError("Generated files are out of date: " + ", ".join(changed))
        print(f"Generated {len(generated)} Egern-native rule sets.")
        return 0
    except (BuildError, OSError, ValueError, KeyError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"Build failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
