#!/usr/bin/env python3
"""Validate V2Fly geolocation-cn text and its MRS compilation."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXPECTED_REGEX = ROOT / "config" / "v2fly" / "geolocation-cn-regex.txt"
DEFAULT_POSITIVE_HOSTS = (
    "qq.com",
    "taobao.com",
    "tmall.com",
    "jd.com",
    "bilibili.com",
    "weibo.com",
    "163.com",
    "xiaomi.com",
    "amap.com",
    "alipay.com",
)
DEFAULT_NEGATIVE_HOSTS = ("wetv.vip", "jd.hk")


class ValidationError(RuntimeError):
    """Raised when a generated provider loses or gains unsupported semantics."""


@dataclass(frozen=True)
class V2FlyEntry:
    rule_type: str
    value: str
    attrs: tuple[str, ...]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_v2fly_export(path: Path) -> list[V2FlyEntry]:
    entries: list[V2FlyEntry] = []
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValidationError(f"{path}:{line_number}: missing rule type")
        rule_type, remainder = line.split(":", 1)
        attrs: tuple[str, ...] = ()
        if ":@" in remainder:
            value, attr_text = remainder.rsplit(":", 1)
            attr_parts = attr_text.split(",")
            if not attr_parts or any(not part.startswith("@") for part in attr_parts):
                raise ValidationError(f"{path}:{line_number}: malformed attributes")
            attrs = tuple(part[1:] for part in attr_parts)
        else:
            value = remainder
        if rule_type not in {"domain", "full", "regexp", "keyword"} or not value:
            raise ValidationError(f"{path}:{line_number}: unsupported or empty rule")
        entries.append(V2FlyEntry(rule_type, value, attrs))
    if not entries:
        raise ValidationError(f"{path}: exported list is empty")
    return entries


def load_domain_rules(path: Path) -> list[str]:
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    rules = [line for line in lines if line and not line.startswith("#")]
    for rule in rules:
        domain = rule[2:] if rule.startswith("+.") else rule
        if not domain or any(character.isspace() for character in domain):
            raise ValidationError(f"{path}: malformed domain rule {rule!r}")
    return rules


def matches(host: str, rules: set[str]) -> bool:
    if host in rules:
        return True
    labels = host.split(".")
    return any("+." + ".".join(labels[index:]) in rules for index in range(len(labels)))


def validate(
    export_path: Path,
    domain_list_path: Path,
    mrs_path: Path,
    expected_regex_path: Path = DEFAULT_EXPECTED_REGEX,
    minimum_domain_rules: int = 7000,
    positive_hosts: Sequence[str] = DEFAULT_POSITIVE_HOSTS,
    negative_hosts: Sequence[str] = DEFAULT_NEGATIVE_HOSTS,
) -> dict[str, object]:
    entries = parse_v2fly_export(export_path)
    forbidden = [entry for entry in entries if {"ads", "!cn"} & set(entry.attrs)]
    if forbidden:
        raise ValidationError(
            f"Official export retained {len(forbidden)} @ads/@!cn entries"
        )

    by_type = {
        rule_type: [entry for entry in entries if entry.rule_type == rule_type]
        for rule_type in ("domain", "full", "regexp", "keyword")
    }
    if by_type["keyword"]:
        raise ValidationError(
            "V2Fly export gained keyword rules that a domain MRS cannot preserve"
        )

    expected_regex = {
        line.strip()
        for line in expected_regex_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }
    actual_regex = {f"regexp:{entry.value}" for entry in by_type["regexp"]}
    if actual_regex != expected_regex:
        missing = sorted(expected_regex - actual_regex)
        added = sorted(actual_regex - expected_regex)
        raise ValidationError(
            f"Reviewed regex set changed; missing={missing}, added={added}"
        )

    expected_domain_rules = [
        ("+." + entry.value if entry.rule_type == "domain" else entry.value)
        for entry in entries
        if entry.rule_type in {"domain", "full"}
    ]
    if len(expected_domain_rules) < minimum_domain_rules:
        raise ValidationError(
            f"Only {len(expected_domain_rules)} MRS-compatible rules remain; "
            f"expected at least {minimum_domain_rules}"
        )

    actual_domain_rules = load_domain_rules(domain_list_path)
    if actual_domain_rules != expected_domain_rules:
        mismatch = next(
            (
                index
                for index, (expected, actual) in enumerate(
                    zip(expected_domain_rules, actual_domain_rules), 1
                )
                if expected != actual
            ),
            min(len(expected_domain_rules), len(actual_domain_rules)) + 1,
        )
        raise ValidationError(
            "Canonical domain list does not preserve V2Fly domain/full order and count; "
            f"first mismatch at rule {mismatch}, expected count={len(expected_domain_rules)}, "
            f"actual count={len(actual_domain_rules)}"
        )

    rule_set = set(actual_domain_rules)
    failed_positive = [host for host in positive_hosts if not matches(host, rule_set)]
    failed_negative = [host for host in negative_hosts if matches(host, rule_set)]
    if failed_positive or failed_negative:
        raise ValidationError(
            f"Sentinel checks failed; missing={failed_positive}, unexpectedly matched={failed_negative}"
        )
    if not mrs_path.is_file() or mrs_path.stat().st_size < 1024:
        raise ValidationError(f"{mrs_path}: MRS output is missing or implausibly small")

    return {
        "source_entries": len(entries),
        "domain_entries": len(by_type["domain"]),
        "full_entries": len(by_type["full"]),
        "regex_entries_not_representable_in_domain_mrs": sorted(actual_regex),
        "keyword_entries": len(by_type["keyword"]),
        "mrs_compatible_entries": len(actual_domain_rules),
        "forbidden_attribute_entries": len(forbidden),
        "positive_sentinels": list(positive_hosts),
        "negative_sentinels": list(negative_hosts),
        "sha256": {
            "v2fly_export": sha256(export_path),
            "domain_list": sha256(domain_list_path),
            "domain_mrs": sha256(mrs_path),
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v2fly-export", type=Path, required=True)
    parser.add_argument("--domain-list", type=Path, required=True)
    parser.add_argument("--domain-mrs", type=Path, required=True)
    parser.add_argument("--expected-regex", type=Path, default=DEFAULT_EXPECTED_REGEX)
    parser.add_argument("--v2fly-commit", required=True)
    parser.add_argument("--mrs-converter-commit", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        report = validate(
            args.v2fly_export.resolve(),
            args.domain_list.resolve(),
            args.domain_mrs.resolve(),
            args.expected_regex.resolve(),
        )
        report["upstreams"] = {
            "v2fly/domain-list-community": args.v2fly_commit,
            "mrs_converter": {
                "name": "MetaCubeX/meta-rules-converter",
                "commit": args.mrs_converter_commit,
                "role": "MRS format generation only",
            },
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(
            "Validated geolocation-cn: "
            f"{report['source_entries']} V2Fly entries, "
            f"{report['mrs_compatible_entries']} MRS-compatible entries."
        )
        return 0
    except (OSError, ValidationError) as exc:
        print(f"geolocation-cn validation failed: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
