#!/usr/bin/env python3
"""Convert the providers referenced by one Mihomo script snapshot to native Egern YAML."""

import argparse
import ipaddress
import json
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULE_DIR = ROOT / "rules"


class BuildError(RuntimeError):
    pass


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
        elif line.startswith("."):
            field, value = "domain_wildcard_set", "*" + line
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


def referenced_providers(model):
    names = []
    for rule in model["rules"]:
        names.extend(re.findall(r"\bRULE-SET,([^,()]+)", rule))
    for matcher in model["dns"].get("nameserver-policy", {}):
        if not matcher.startswith("rule-set:"):
            raise BuildError(f"Unsupported DNS matcher: {matcher}")
        names.append(matcher.removeprefix("rule-set:"))
    return list(dict.fromkeys(names))


def slug(name):
    names = {"geolocation-!cn": "geolocation-non-cn", "mcdn屏蔽": "mcdn-block"}
    value = re.sub(r"[^A-Za-z0-9.-]+", "-", names.get(name, name.replace("_", "-"))).strip("-").lower()
    if not value:
        raise BuildError(f"Invalid provider filename: {name}")
    return value


def native(segments):
    result = {}
    for segment in segments:
        for field, values in segment.items():
            if isinstance(values, list):
                result.setdefault(field, []).extend(values)
            elif field == "no_resolve" and values is True:
                result[field] = True
            else:
                raise BuildError(f"Invalid native field: {field}")
    if not any(isinstance(values, list) and values for values in result.values()):
        raise BuildError("Empty native rule set")
    return result


class Sources:
    def __init__(self):
        self.downloads = {}
        self.decoded = {}

    def read(self, url):
        if url not in self.downloads:
            # Fetch the same Bett repository/ref directly: CDN package limits can
            # reject individual files. Keep the script URL in the source index.
            download_url = re.sub(
                r"^https://(?:fastly\.jsdelivr\.net|cdn\.jsdelivr\.net|cdn\.jsdmirror\.com)/gh/appshubcc/bett-rules@([^/]+)/",
                r"https://raw.githubusercontent.com/appshubcc/bett-rules/\1/",
                url,
            )
            request = urllib.request.Request(download_url, headers={"User-Agent": "egern-rules-builder/1"})
            print(f"Downloading rule source: {url} via {download_url}", flush=True)
            try:
                with urllib.request.urlopen(request, timeout=90) as response:
                    self.downloads[url] = response.read()
            except urllib.error.HTTPError as exc:
                detail = exc.read(512).decode("utf-8", errors="replace")
                raise BuildError(
                    f"Rule source download failed: {url} via {download_url}; HTTP {exc.code} "
                    f"{exc.reason}; response: {detail!r}"
                ) from exc
            if not self.downloads[url]:
                raise BuildError(f"Empty rule source: {url}")
        return self.downloads[url]

    def rules(self, provider):
        url = provider["url"]
        behavior = provider["behavior"]
        kind = provider.get("format", "yaml")
        key = (url, behavior, kind)
        if key in self.decoded:
            return self.decoded[key]
        data = self.read(url)
        if kind == "mrs":
            if behavior not in {"domain", "ipcidr"}:
                raise BuildError(f"Unsupported MRS behavior: {behavior}")
            with tempfile.TemporaryDirectory(prefix="egern-mrs-") as temporary:
                source = Path(temporary) / "source.mrs"
                output = Path(temporary) / "source.list"
                source.write_bytes(data)
                subprocess.run(["mihomo", "convert-ruleset", behavior, "mrs", str(source), str(output)], check=True)
                text = output.read_text(encoding="utf-8-sig")
        else:
            text = data.decode("utf-8-sig")
        if kind == "yaml":
            document = yaml.safe_load(text)
            if not isinstance(document, dict) or set(document) != {"payload"}:
                raise BuildError(f"Expected Mihomo payload: {url}")
            payload = document["payload"]
            if not isinstance(payload, list) or not payload or any(not isinstance(line, str) for line in payload):
                raise BuildError(f"Invalid Mihomo payload: {url}")
            text = "\n".join(payload)
        elif kind not in {"mrs", "text"}:
            raise BuildError(f"Unsupported provider format: {kind}")
        parser = {"domain": parse_domain_list, "ipcidr": parse_ip_list, "classical": parse_classical_rule_list}.get(behavior)
        if parser is None:
            raise BuildError(f"Unsupported provider behavior: {behavior}")
        result = native(parser(text))
        self.decoded[key] = result
        return result


def private_relay(sources, config):
    primary = parse_domain_list(sources.read(config["bett_url"]).decode("utf-8-sig"))
    extra = parse_domain_list(sources.read(config["sukka_url"]).decode("utf-8-sig"))
    result = native(primary)
    scopes = [(field, value) for field, values in result.items() if isinstance(values, list) for value in values]
    for segment in extra:
        for field, values in segment.items():
            if not isinstance(values, list):
                continue
            for value in values:
                if value in config["excluded_domains"]:
                    continue
                def covered(existing):
                    kind, domain = existing
                    if kind == "domain_suffix_set":
                        return value == domain or value.endswith("." + domain)
                    return kind == field and value == domain
                if any(covered(existing) for existing in scopes):
                    continue
                result.setdefault(field, []).append(value)
                scopes.append((field, value))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--mihomo-commit", required=True)
    args = parser.parse_args()
    model = json.loads(args.model.read_text(encoding="utf-8"))
    config = json.loads((ROOT / "config/sources.json").read_text(encoding="utf-8"))
    sources = Sources()
    output = {}
    index = {"mihomo_commit": args.mihomo_commit, "providers": {}}
    for name in referenced_providers(model):
        provider = model["providers"][name]
        filename = slug(name) + ".yaml"
        if filename in output:
            raise BuildError(f"Provider filename collision: {name}")
        output[filename] = sources.rules(provider)
        index["providers"][name] = {
            "file": filename, "url": provider["url"],
            "behavior": provider["behavior"], "format": provider.get("format", "yaml"),
        }
    output["apns.yaml"] = native(parse_classical_rule_list(sources.read(config["apns_url"]).decode("utf-8-sig")))
    output["privaterelay.yaml"] = private_relay(sources, config["privaterelay"])
    index["extra_files"] = ["apns.yaml", "privaterelay.yaml"]
    RULE_DIR.mkdir(exist_ok=True)
    # All sources are converted before any publication files are replaced.
    for filename, rule in output.items():
        (RULE_DIR / filename).write_text(yaml.safe_dump(rule, allow_unicode=True, sort_keys=False, width=1000), encoding="utf-8")
    for path in RULE_DIR.glob("*.yaml"):
        if path.name not in output:
            path.unlink()
    (RULE_DIR / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Published {len(output)} native rule files from {len(sources.downloads)} source downloads.")


if __name__ == "__main__":
    main()
