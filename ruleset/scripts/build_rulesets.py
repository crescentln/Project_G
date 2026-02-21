#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import pathlib
import re
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = ROOT_DIR / "config" / "sources.json"
DEFAULT_POLICY_PATH = ROOT_DIR / "config" / "policy_map.json"
DEFAULT_DIST_DIR = ROOT_DIR / "dist"
DEFAULT_CACHE_DIR = ROOT_DIR / ".cache"

USER_AGENT = "self-owned-ruleset-builder/1.0"

RULE_ORDER = {
    "DOMAIN": 0,
    "DOMAIN-SUFFIX": 1,
    "DOMAIN-KEYWORD": 2,
    "DOMAIN-WILDCARD": 3,
    "DOMAIN-REGEX": 4,
    "IP-CIDR": 5,
    "IP-CIDR6": 6,
}

ALLOWED_ACTIONS = {
    "DIRECT",
    "PROXY",
    "REJECT",
    "REJECT-DROP",
    "REJECT-NO-DROP",
    "UNSPECIFIED",
}

HOST_LINE_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+([^\s#;]+)")
FOOTNOTE_RE = re.compile(r"\s*\[[0-9]+\]\s*$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,62}$"
)


class BuildError(RuntimeError):
    pass


@dataclass
class SourceBuildResult:
    rules: set[str]
    used_cache: bool
    source_ref: str


def log(message: str) -> None:
    print(f"[ruleset] {message}")


def normalize_domain(value: str) -> str | None:
    value = value.strip().strip("\"'").lower()
    if not value:
        return None

    if value.startswith("||"):
        value = value[2:]
    if value.startswith("*."):
        value = value[2:]
    if value.startswith("+."):
        value = value[2:]
    value = value.lstrip(".")
    value = value.split("^", 1)[0]
    value = value.split("/", 1)[0]

    if value.startswith("[") and value.endswith("]"):
        return None

    # remove optional port from hostname
    if ":" in value and value.count(":") == 1:
        host, maybe_port = value.rsplit(":", 1)
        if maybe_port.isdigit():
            value = host

    value = value.strip(".")
    if not value:
        return None

    # Filter out IP literals accidentally parsed as hostnames.
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass

    if not DOMAIN_RE.fullmatch(value):
        return None
    return value


def rule_sort_key(rule: str) -> tuple[int, str]:
    if "," in rule:
        rule_type, payload = rule.split(",", 1)
    else:
        rule_type, payload = rule, ""
    return RULE_ORDER.get(rule_type, 99), payload


def format_ip_rule(network: ipaddress._BaseNetwork) -> str:
    if isinstance(network, ipaddress.IPv4Network):
        return f"IP-CIDR,{network.with_prefixlen},no-resolve"
    return f"IP-CIDR6,{network.with_prefixlen},no-resolve"


def parse_explicit_rule(line: str) -> str | None:
    line = line.strip()
    if not line:
        return None

    if line.startswith("DOMAIN,"):
        domain = normalize_domain(line.split(",", 1)[1])
        return f"DOMAIN,{domain}" if domain else None

    if line.startswith("DOMAIN-SUFFIX,"):
        domain = normalize_domain(line.split(",", 1)[1])
        return f"DOMAIN-SUFFIX,{domain}" if domain else None

    if line.startswith("DOMAIN-KEYWORD,"):
        value = line.split(",", 1)[1].strip()
        return f"DOMAIN-KEYWORD,{value}" if value else None

    if line.startswith("DOMAIN-WILDCARD,"):
        value = line.split(",", 1)[1].strip()
        return f"DOMAIN-WILDCARD,{value}" if value else None

    if line.startswith("DOMAIN-REGEX,"):
        value = line.split(",", 1)[1].strip()
        return f"DOMAIN-REGEX,{value}" if value else None

    if line.startswith("IP-CIDR,") or line.startswith("IP-CIDR6,"):
        rule_type, rest = line.split(",", 1)
        cidr = rest.split(",", 1)[0].strip()
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return None
        return format_ip_rule(network)

    return None


def parse_domain_or_ip_token(line: str) -> str | None:
    explicit = parse_explicit_rule(line)
    if explicit:
        return explicit

    if line.startswith("+.") or line.startswith("."):
        domain = normalize_domain(line[2:] if line.startswith("+.") else line[1:])
        return f"DOMAIN-SUFFIX,{domain}" if domain else None

    if line.startswith("||"):
        domain = normalize_domain(line)
        return f"DOMAIN-SUFFIX,{domain}" if domain else None

    host_match = HOST_LINE_RE.match(line)
    if host_match:
        domain = normalize_domain(host_match.group(1))
        return f"DOMAIN,{domain}" if domain else None

    try:
        network = ipaddress.ip_network(line, strict=False)
        return format_ip_rule(network)
    except ValueError:
        pass

    domain = normalize_domain(line)
    return f"DOMAIN-SUFFIX,{domain}" if domain else None


def strip_comment(line: str) -> str:
    line = line.strip()
    if not line:
        return ""
    if line.startswith(("#", ";")):
        return ""
    if " #" in line:
        line = line.split(" #", 1)[0]
    if "\t#" in line:
        line = line.split("\t#", 1)[0]
    if " ;" in line:
        line = line.split(" ;", 1)[0]
    if "\t;" in line:
        line = line.split("\t;", 1)[0]
    return line.strip()


def parse_local_domain_text(text: str) -> set[str]:
    rules: set[str] = set()
    for raw in text.splitlines():
        line = strip_comment(raw)
        if not line:
            continue
        parsed = parse_domain_or_ip_token(line)
        if parsed:
            rules.add(parsed)
    return rules


def parse_plain_cidr_text(text: str) -> set[str]:
    rules: set[str] = set()
    for raw in text.splitlines():
        line = strip_comment(raw)
        if not line:
            continue

        explicit = parse_explicit_rule(line)
        if explicit and explicit.startswith(("IP-CIDR,", "IP-CIDR6,")):
            rules.add(explicit)
            continue

        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        rules.add(format_ip_rule(network))
    return rules


def parse_adblock_text(text: str) -> set[str]:
    rules: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("!", "[", "#", ";")):
            continue
        if line.startswith("@@"):
            continue
        if "##" in line or "#@#" in line or "#?#" in line:
            continue

        line = line.split("$", 1)[0].strip()
        if not line:
            continue

        explicit = parse_explicit_rule(line)
        if explicit:
            rules.add(explicit)
            continue

        if line.startswith(("|http://", "|https://")):
            url = line.lstrip("|")
            try:
                hostname = urllib.parse.urlparse(url).hostname or ""
            except ValueError:
                hostname = ""
            domain = normalize_domain(hostname)
            if domain:
                rules.add(f"DOMAIN,{domain}")
            continue

        if line.startswith("||"):
            token = line[2:].split("^", 1)[0].split("/", 1)[0]
            domain = normalize_domain(token)
            if domain:
                rules.add(f"DOMAIN-SUFFIX,{domain}")
            continue

        host_match = HOST_LINE_RE.match(line)
        if host_match:
            domain = normalize_domain(host_match.group(1))
            if domain:
                rules.add(f"DOMAIN,{domain}")
            continue

        parsed = parse_domain_or_ip_token(line)
        if parsed:
            rules.add(parsed)
    return rules


def parse_telegram_cidr_text(text: str) -> set[str]:
    return parse_plain_cidr_text(text)


def parse_apnic_country_cidr(text: str, country: str) -> set[str]:
    rules: set[str] = set()
    cc = country.upper()

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 7:
            continue
        _, rec_cc, rec_type, start, value, _, status = parts[:7]
        if rec_cc.upper() != cc:
            continue
        if status not in {"allocated", "assigned"}:
            continue

        if rec_type == "ipv4":
            try:
                count = int(value)
                start_ip = ipaddress.IPv4Address(start)
                end_ip = ipaddress.IPv4Address(int(start_ip) + count - 1)
            except (ValueError, ipaddress.AddressValueError):
                continue
            for net in ipaddress.summarize_address_range(start_ip, end_ip):
                rules.add(format_ip_rule(net))
            continue

        if rec_type == "ipv6":
            try:
                prefix_len = int(value)
                net = ipaddress.IPv6Network(f"{start}/{prefix_len}", strict=False)
            except ValueError:
                continue
            rules.add(format_ip_rule(net))

    return rules


def parse_iana_special_csv(text: str) -> set[str]:
    rules: set[str] = set()
    reader = csv.DictReader(text.splitlines())
    if not reader.fieldnames:
        return rules

    address_key = next((f for f in reader.fieldnames if "Address Block" in f), None)
    reachable_key = next((f for f in reader.fieldnames if "Globally Reachable" in f), None)
    if not address_key:
        return rules

    for row in reader:
        if reachable_key:
            reach_value = (row.get(reachable_key) or "").strip()
            if "false" not in reach_value.lower():
                continue

        block_text = (row.get(address_key) or "").strip()
        if not block_text:
            continue

        block_candidates = [b.strip() for b in block_text.split(",") if b.strip()]
        for block in block_candidates:
            block = FOOTNOTE_RE.sub("", block).strip()
            if not block:
                continue
            try:
                network = ipaddress.ip_network(block, strict=False)
            except ValueError:
                continue
            rules.add(format_ip_rule(network))
    return rules


def parse_aws_ip_ranges(data: bytes, services: list[str]) -> set[str]:
    rules: set[str] = set()
    payload = json.loads(data.decode("utf-8"))
    service_set = {s.upper() for s in services}

    for item in payload.get("prefixes", []):
        service = str(item.get("service", "")).upper()
        if service_set and service not in service_set:
            continue
        prefix = item.get("ip_prefix")
        if not prefix:
            continue
        try:
            rules.add(format_ip_rule(ipaddress.ip_network(prefix, strict=False)))
        except ValueError:
            continue

    for item in payload.get("ipv6_prefixes", []):
        service = str(item.get("service", "")).upper()
        if service_set and service not in service_set:
            continue
        prefix = item.get("ipv6_prefix")
        if not prefix:
            continue
        try:
            rules.add(format_ip_rule(ipaddress.ip_network(prefix, strict=False)))
        except ValueError:
            continue

    return rules


def parse_gcp_ip_ranges(data: bytes) -> set[str]:
    rules: set[str] = set()
    payload = json.loads(data.decode("utf-8"))
    for item in payload.get("prefixes", []):
        for key in ("ipv4Prefix", "ipv6Prefix"):
            prefix = item.get(key)
            if not prefix:
                continue
            try:
                rules.add(format_ip_rule(ipaddress.ip_network(prefix, strict=False)))
            except ValueError:
                continue
    return rules


def fetch_bytes(url: str, cache_dir: pathlib.Path, offline: bool = False) -> tuple[bytes, bool]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
    cache_file = cache_dir / f"{digest}.bin"
    meta_file = cache_dir / f"{digest}.json"

    if offline:
        if not cache_file.exists():
            raise BuildError(f"offline mode: no cache for {url}")
        return cache_file.read_bytes(), True

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            data = response.read()
        if not data:
            raise BuildError(f"empty response from {url}")
        cache_file.write_bytes(data)
        meta_file.write_text(
            json.dumps({"url": url, "fetched_at_utc": dt.datetime.now(dt.UTC).isoformat()}),
            encoding="utf-8",
        )
        return data, False
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        if cache_file.exists():
            log(f"warning: fetch failed for {url}; using cache ({exc})")
            return cache_file.read_bytes(), True
        raise BuildError(f"fetch failed for {url}: {exc}") from exc


def decode_text(data: bytes) -> str:
    return data.decode("utf-8-sig", errors="ignore")


def load_source(
    source: dict[str, Any],
    root_dir: pathlib.Path,
    cache_dir: pathlib.Path,
    offline: bool,
) -> SourceBuildResult:
    source_type = str(source.get("type", "")).strip()
    if not source_type:
        raise BuildError("source missing 'type'")

    if source_type == "local_domain":
        path = root_dir / str(source["path"])
        if not path.exists():
            raise BuildError(f"local file not found: {path}")
        text = path.read_text(encoding="utf-8")
        return SourceBuildResult(parse_local_domain_text(text), False, str(path))

    url = str(source.get("url", "")).strip()
    if not url:
        raise BuildError(f"source type {source_type} requires 'url'")

    data, used_cache = fetch_bytes(url, cache_dir, offline=offline)
    text = decode_text(data)

    if source_type == "adblock":
        return SourceBuildResult(parse_adblock_text(text), used_cache, url)
    if source_type == "plain_cidr":
        return SourceBuildResult(parse_plain_cidr_text(text), used_cache, url)
    if source_type == "telegram_cidr":
        return SourceBuildResult(parse_telegram_cidr_text(text), used_cache, url)
    if source_type == "apnic_country_cidr":
        country = str(source.get("country", "")).strip()
        if not country:
            raise BuildError(f"source type {source_type} requires 'country'")
        return SourceBuildResult(parse_apnic_country_cidr(text, country), used_cache, url)
    if source_type == "iana_special_csv":
        return SourceBuildResult(parse_iana_special_csv(text), used_cache, url)
    if source_type == "aws_ip_ranges":
        services = [str(item) for item in source.get("services", [])]
        return SourceBuildResult(parse_aws_ip_ranges(data, services), used_cache, url)
    if source_type == "gcp_ip_ranges":
        return SourceBuildResult(parse_gcp_ip_ranges(data), used_cache, url)

    raise BuildError(f"unsupported source type: {source_type}")


def write_surge_rules(path: pathlib.Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(rules)
    if body:
        body += "\n"
    path.write_text(body, encoding="utf-8")


def write_openclash_rules(path: pathlib.Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rules:
        path.write_text("payload: []\n", encoding="utf-8")
        return

    lines = ["payload:"]
    for rule in rules:
        escaped = rule.replace("'", "''")
        lines.append(f"  - '{escaped}'")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def split_rules(rules: list[str]) -> tuple[list[str], list[str], list[str], list[str], list[str]]:
    non_ip_rules: list[str] = []
    ip_rules: list[str] = []
    domain_rules: list[str] = []
    ipcidr_payloads: list[str] = []
    surge_domainset_lines: list[str] = []

    for rule in rules:
        if rule.startswith(("IP-CIDR,", "IP-CIDR6,")):
            ip_rules.append(rule)
            parts = rule.split(",", 2)
            if len(parts) >= 2:
                ipcidr_payloads.append(parts[1])
            continue

        non_ip_rules.append(rule)

        if rule.startswith("DOMAIN,"):
            domain = rule.split(",", 1)[1]
            domain_rules.append(domain)
            surge_domainset_lines.append(domain)
            continue

        if rule.startswith("DOMAIN-SUFFIX,"):
            domain = rule.split(",", 1)[1]
            domain_rules.append(f"+.{domain}")
            surge_domainset_lines.append(f".{domain}")

    return non_ip_rules, ip_rules, domain_rules, ipcidr_payloads, surge_domainset_lines


def write_plain_lines(path: pathlib.Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(lines)
    if content:
        content += "\n"
    path.write_text(content, encoding="utf-8")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_policy_map(policy_path: pathlib.Path | None) -> dict[str, dict[str, Any]]:
    if policy_path is None:
        return {}
    if not policy_path.exists():
        return {}
    payload = read_json(policy_path)
    categories = payload.get("categories", {})
    if not isinstance(categories, dict):
        raise BuildError("policy map: 'categories' must be an object")
    out: dict[str, dict[str, Any]] = {}
    for key, value in categories.items():
        if not isinstance(value, dict):
            raise BuildError(f"policy map: category '{key}' must be an object")
        out[str(key)] = value
    return out


def render_policy_reference_markdown(categories: list[dict[str, Any]]) -> str:
    lines = [
        "# Ruleset Policy Reference",
        "",
        "This file defines the recommended action per category.",
        "",
        "| Category | Action | Priority | Rules | Note |",
        "|---|---:|---:|---:|---|",
    ]
    sorted_rows = sorted(
        categories,
        key=lambda c: (int(c.get("recommended_priority", 9999)), str(c.get("id", ""))),
    )
    for row in sorted_rows:
        category_id = str(row.get("id", ""))
        action = str(row.get("recommended_action", "UNSPECIFIED"))
        priority = int(row.get("recommended_priority", 9999))
        rules = int(row.get("rule_count", 0))
        note = str(row.get("recommended_note", "")).replace("|", "\\|")
        lines.append(f"| `{category_id}` | `{action}` | {priority} | {rules} | {note} |")
    lines.append("")
    lines.append("Action definitions:")
    lines.append("- `DIRECT`: bypass proxy.")
    lines.append("- `PROXY`: route via proxy policy group.")
    lines.append("- `REJECT`: deny with standard reject.")
    lines.append("- `REJECT-DROP`: silently drop packets.")
    lines.append("- `REJECT-NO-DROP`: explicit reject without drop.")
    lines.append("")
    return "\n".join(lines)


def build_category(
    category: dict[str, Any],
    root_dir: pathlib.Path,
    cache_dir: pathlib.Path,
    offline: bool,
) -> tuple[list[str], list[dict[str, Any]]]:
    category_id = str(category.get("id", "")).strip()
    if not category_id:
        raise BuildError("category missing 'id'")

    sources = category.get("sources", [])
    if not isinstance(sources, list) or not sources:
        raise BuildError(f"category {category_id} has no sources")

    rules: set[str] = set()
    source_meta: list[dict[str, Any]] = []

    for source in sources:
        result = load_source(source, root_dir, cache_dir, offline)
        rules.update(result.rules)
        source_meta.append(
            {
                "type": source["type"],
                "authority": source.get("authority", "unspecified"),
                "ref": result.source_ref,
                "used_cache": result.used_cache,
                "rule_count": len(result.rules),
            }
        )

    exclude_path = category.get("exclude_rules_path")
    if exclude_path:
        exclusion_file = root_dir / str(exclude_path)
        if exclusion_file.exists():
            exclude_rules = parse_local_domain_text(exclusion_file.read_text(encoding="utf-8"))
            before_count = len(rules)
            rules.difference_update(exclude_rules)
            removed = before_count - len(rules)
            if removed > 0:
                log(f"{category_id}: removed {removed} rules from exclusion file")

    sorted_rules = sorted(rules, key=rule_sort_key)
    return sorted_rules, source_meta


def build_all(
    config_path: pathlib.Path,
    policy_path: pathlib.Path | None,
    dist_dir: pathlib.Path,
    cache_dir: pathlib.Path,
    offline: bool,
    fail_on_conflicts: bool,
) -> int:
    config = read_json(config_path)
    policy_map = load_policy_map(policy_path)
    categories = config.get("categories", [])
    if not isinstance(categories, list) or not categories:
        raise BuildError("config has no categories")

    dist_dir.mkdir(parents=True, exist_ok=True)
    for stale in (dist_dir / "surge", dist_dir / "openclash", dist_dir / "compat"):
        if stale.exists():
            shutil.rmtree(stale)

    surge_dir = dist_dir / "surge"
    openclash_dir = dist_dir / "openclash"

    rules_by_category: dict[str, list[str]] = {}
    metadata_categories: list[dict[str, Any]] = []
    missing_policy: list[str] = []

    for category in categories:
        category_id = str(category.get("id", "")).strip()
        if not category_id:
            raise BuildError("category missing id")
        log(f"building category: {category_id}")

        rules, source_meta = build_category(category, ROOT_DIR, cache_dir, offline)
        rules_by_category[category_id] = rules

        policy_entry = policy_map.get(category_id, {})
        action = str(policy_entry.get("action", "UNSPECIFIED")).upper().strip()
        if action not in ALLOWED_ACTIONS:
            raise BuildError(f"policy map: invalid action '{action}' for category '{category_id}'")
        priority = int(policy_entry.get("priority", 9999))
        note = str(policy_entry.get("note", "")).strip()
        if action == "UNSPECIFIED":
            missing_policy.append(category_id)

        surge_file = surge_dir / f"{category_id}.list"
        openclash_file = openclash_dir / f"{category_id}.yaml"
        write_surge_rules(surge_file, rules)
        write_openclash_rules(openclash_file, rules)

        non_ip_rules, ip_rules, domainset_lines_oc, ipcidr_lines, domainset_lines_surge = split_rules(rules)

        write_surge_rules(dist_dir / "surge" / "non_ip" / f"{category_id}.list", non_ip_rules)
        write_surge_rules(dist_dir / "surge" / "ip" / f"{category_id}.list", ip_rules)
        write_plain_lines(dist_dir / "surge" / "domainset" / f"{category_id}.conf", domainset_lines_surge)

        write_openclash_rules(dist_dir / "openclash" / "non_ip" / f"{category_id}.yaml", non_ip_rules)
        write_openclash_rules(dist_dir / "openclash" / "ip" / f"{category_id}.yaml", ip_rules)
        write_plain_lines(dist_dir / "openclash" / "domainset" / f"{category_id}.txt", domainset_lines_oc)
        write_plain_lines(dist_dir / "openclash" / "ipcidr" / f"{category_id}.txt", ipcidr_lines)

        # Compatibility tree for direct replacement of common public ruleset layouts.
        write_surge_rules(dist_dir / "compat" / "Clash" / "non_ip" / f"{category_id}.txt", non_ip_rules)
        write_surge_rules(dist_dir / "compat" / "Clash" / "ip" / f"{category_id}.txt", ip_rules)
        write_plain_lines(dist_dir / "compat" / "Clash" / "domainset" / f"{category_id}.txt", domainset_lines_oc)
        write_surge_rules(dist_dir / "compat" / "List" / "non_ip" / f"{category_id}.conf", non_ip_rules)
        write_surge_rules(dist_dir / "compat" / "List" / "ip" / f"{category_id}.conf", ip_rules)
        write_plain_lines(dist_dir / "compat" / "List" / "domainset" / f"{category_id}.conf", domainset_lines_surge)

        metadata_categories.append(
            {
                "id": category_id,
                "description": category.get("description", ""),
                "rule_count": len(rules),
                "surge_path": str(surge_file.relative_to(dist_dir)),
                "openclash_path": str(openclash_file.relative_to(dist_dir)),
                "surge_non_ip_path": str((dist_dir / "surge" / "non_ip" / f"{category_id}.list").relative_to(dist_dir)),
                "surge_ip_path": str((dist_dir / "surge" / "ip" / f"{category_id}.list").relative_to(dist_dir)),
                "surge_domainset_path": str((dist_dir / "surge" / "domainset" / f"{category_id}.conf").relative_to(dist_dir)),
                "openclash_non_ip_path": str((dist_dir / "openclash" / "non_ip" / f"{category_id}.yaml").relative_to(dist_dir)),
                "openclash_ip_path": str((dist_dir / "openclash" / "ip" / f"{category_id}.yaml").relative_to(dist_dir)),
                "openclash_domainset_path": str((dist_dir / "openclash" / "domainset" / f"{category_id}.txt").relative_to(dist_dir)),
                "openclash_ipcidr_path": str((dist_dir / "openclash" / "ipcidr" / f"{category_id}.txt").relative_to(dist_dir)),
                "compat_clash_non_ip_path": str((dist_dir / "compat" / "Clash" / "non_ip" / f"{category_id}.txt").relative_to(dist_dir)),
                "compat_clash_ip_path": str((dist_dir / "compat" / "Clash" / "ip" / f"{category_id}.txt").relative_to(dist_dir)),
                "compat_clash_domainset_path": str((dist_dir / "compat" / "Clash" / "domainset" / f"{category_id}.txt").relative_to(dist_dir)),
                "compat_list_non_ip_path": str((dist_dir / "compat" / "List" / "non_ip" / f"{category_id}.conf").relative_to(dist_dir)),
                "compat_list_ip_path": str((dist_dir / "compat" / "List" / "ip" / f"{category_id}.conf").relative_to(dist_dir)),
                "compat_list_domainset_path": str((dist_dir / "compat" / "List" / "domainset" / f"{category_id}.conf").relative_to(dist_dir)),
                "recommended_action": action,
                "recommended_priority": priority,
                "recommended_note": note,
                "sources": source_meta,
            }
        )

        # Per-category sidecar metadata for auditing and ops.
        sidecar_dir = dist_dir / "meta"
        sidecar_dir.mkdir(parents=True, exist_ok=True)
        sidecar_path = sidecar_dir / f"{category_id}.json"
        sidecar_path.write_text(
            json.dumps(
                {
                    "id": category_id,
                    "description": category.get("description", ""),
                    "recommended_action": action,
                    "recommended_priority": priority,
                    "recommended_note": note,
                    "rule_count": len(rules),
                    "paths": {
                        "surge": str(surge_file.relative_to(dist_dir)),
                        "surge_non_ip": str((dist_dir / "surge" / "non_ip" / f"{category_id}.list").relative_to(dist_dir)),
                        "surge_ip": str((dist_dir / "surge" / "ip" / f"{category_id}.list").relative_to(dist_dir)),
                        "surge_domainset": str((dist_dir / "surge" / "domainset" / f"{category_id}.conf").relative_to(dist_dir)),
                        "openclash": str(openclash_file.relative_to(dist_dir)),
                        "openclash_non_ip": str((dist_dir / "openclash" / "non_ip" / f"{category_id}.yaml").relative_to(dist_dir)),
                        "openclash_ip": str((dist_dir / "openclash" / "ip" / f"{category_id}.yaml").relative_to(dist_dir)),
                        "openclash_domainset": str((dist_dir / "openclash" / "domainset" / f"{category_id}.txt").relative_to(dist_dir)),
                        "openclash_ipcidr": str((dist_dir / "openclash" / "ipcidr" / f"{category_id}.txt").relative_to(dist_dir)),
                        "compat_clash_non_ip": str((dist_dir / "compat" / "Clash" / "non_ip" / f"{category_id}.txt").relative_to(dist_dir)),
                        "compat_clash_ip": str((dist_dir / "compat" / "Clash" / "ip" / f"{category_id}.txt").relative_to(dist_dir)),
                        "compat_clash_domainset": str((dist_dir / "compat" / "Clash" / "domainset" / f"{category_id}.txt").relative_to(dist_dir)),
                        "compat_list_non_ip": str((dist_dir / "compat" / "List" / "non_ip" / f"{category_id}.conf").relative_to(dist_dir)),
                        "compat_list_ip": str((dist_dir / "compat" / "List" / "ip" / f"{category_id}.conf").relative_to(dist_dir)),
                        "compat_list_domainset": str((dist_dir / "compat" / "List" / "domainset" / f"{category_id}.conf").relative_to(dist_dir))
                    },
                    "sources": source_meta
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    rule_index: dict[str, list[str]] = defaultdict(list)
    for category_id, rules in rules_by_category.items():
        for rule in rules:
            rule_index[rule].append(category_id)

    ignored_conflict_sets = {
        frozenset({"domestic", "cncidr"})
    }
    reject_like = {"reject", "reject_extra", "reject_drop", "reject_no_drop"}

    conflicts = []
    for rule, category_ids in rule_index.items():
        category_set = set(category_ids)
        if len(category_set) <= 1:
            continue
        if frozenset(category_set) in ignored_conflict_sets:
            continue
        if len(category_set) == 2 and category_set & reject_like:
            continue
        conflicts.append({"rule": rule, "categories": sorted(category_set)})
    conflicts.sort(key=lambda item: (len(item["categories"]) * -1, item["rule"]))

    conflicts_file = dist_dir / "conflicts.json"
    conflicts_file.write_text(
        json.dumps(
            {
                "generated_at_utc": dt.datetime.now(dt.UTC).isoformat(),
                "conflict_count": len(conflicts),
                "conflicts": conflicts,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    manifest = {
        "generated_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "config_path": str(config_path),
        "policy_path": str(policy_path) if policy_path else None,
        "category_count": len(metadata_categories),
        "conflict_count": len(conflicts),
        "categories": metadata_categories,
    }
    manifest_file = dist_dir / "index.json"
    manifest_file.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    policy_reference_json = dist_dir / "policy_reference.json"
    policy_reference_json.write_text(
        json.dumps(
            {
                "generated_at_utc": dt.datetime.now(dt.UTC).isoformat(),
                "policy_path": str(policy_path) if policy_path else None,
                "categories": [
                    {
                        "id": c["id"],
                        "recommended_action": c["recommended_action"],
                        "recommended_priority": c["recommended_priority"],
                        "recommended_note": c["recommended_note"],
                        "rule_count": c["rule_count"],
                    }
                    for c in metadata_categories
                ],
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    policy_reference_md = dist_dir / "policy_reference.md"
    policy_reference_md.write_text(
        render_policy_reference_markdown(metadata_categories),
        encoding="utf-8",
    )

    log(f"build completed: {len(metadata_categories)} categories")
    log(f"conflicts detected: {len(conflicts)}")
    if missing_policy:
        log(f"warning: missing policy map for categories: {', '.join(sorted(missing_policy))}")

    if fail_on_conflicts and conflicts:
        return 2
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build self-owned rulesets for OpenClash and Surge from authoritative sources."
    )
    parser.add_argument(
        "--config",
        type=pathlib.Path,
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to source config JSON (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--policy",
        type=pathlib.Path,
        default=DEFAULT_POLICY_PATH,
        help=f"Path to policy map JSON (default: {DEFAULT_POLICY_PATH})",
    )
    parser.add_argument(
        "--dist-dir",
        type=pathlib.Path,
        default=DEFAULT_DIST_DIR,
        help=f"Output directory (default: {DEFAULT_DIST_DIR})",
    )
    parser.add_argument(
        "--cache-dir",
        type=pathlib.Path,
        default=DEFAULT_CACHE_DIR,
        help=f"Cache directory for downloaded sources (default: {DEFAULT_CACHE_DIR})",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Disable network fetches and build from local files plus cache only.",
    )
    parser.add_argument(
        "--fail-on-conflicts",
        action="store_true",
        help="Exit non-zero if duplicate rules appear across categories.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return build_all(
            config_path=args.config,
            policy_path=args.policy,
            dist_dir=args.dist_dir,
            cache_dir=args.cache_dir,
            offline=args.offline,
            fail_on_conflicts=args.fail_on_conflicts,
        )
    except BuildError as exc:
        log(f"error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
