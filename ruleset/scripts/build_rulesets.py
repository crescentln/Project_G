#!/usr/bin/env python3
from __future__ import annotations

import argparse
import bisect
import csv
import datetime as dt
import hashlib
import io
import ipaddress
import json
import os
import pathlib
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

try:
    from ruleset.scripts.public_suffix_policy import (
        PublicSuffixDatabase,
        PublicSuffixPolicyError,
        domain_topology_markers as psl_domain_topology_markers,
        load_public_suffix_database,
    )
except ModuleNotFoundError:
    from public_suffix_policy import (  # type: ignore[no-redef]
        PublicSuffixDatabase,
        PublicSuffixPolicyError,
        domain_topology_markers as psl_domain_topology_markers,
        load_public_suffix_database,
    )

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = ROOT_DIR / "config" / "sources.json"
DEFAULT_POLICY_PATH = ROOT_DIR / "config" / "policy_map.json"
DEFAULT_SOURCE_REGISTRY_PATH = ROOT_DIR / "config" / "source_registry.json"
DEFAULT_CATEGORY_CONTRACTS_PATH = ROOT_DIR / "config" / "category_contracts.json"
DEFAULT_PROTECTED_DOMAIN_ROOTS_PATH = (
    ROOT_DIR / "config" / "protected_domain_roots.json"
)
DEFAULT_DIST_DIR = ROOT_DIR / "dist"
DEFAULT_CACHE_DIR = ROOT_DIR / ".cache"

USER_AGENT = "self-owned-ruleset-builder/1.0"
FETCH_MEMO: dict[str, tuple[bytes, bool]] = {}
FETCH_EVENTS: dict[str, dict[str, Any]] = {}
FETCH_ATTEMPTS: list[dict[str, Any]] = []
FETCH_MODE_PRIORITY = {
    "network": 0,
    "mirror_network": 0,
    "not_modified": 0,
    "offline_cache": 1,
    "fallback_cache": 2,
}
SOURCE_REGISTRY: dict[str, Any] = {}
SOURCE_LOCK: dict[str, Any] = {}
SOURCE_PROVENANCE: list[dict[str, Any]] = []
SOURCE_RULE_SETS: dict[str, tuple[str, ...]] = {}
SOURCE_RULE_MERKLE_CACHE: dict[str, tuple[list[str], list[list[bytes]]]] = {}
V2FLY_ARCHIVE_MEMO: dict[str, tuple[dict[str, bytes], bool, dict[str, Any]]] = {}
V2FLY_PARSE_PROVENANCE: dict[str, dict[str, Any]] = {}
BUILD_GENERATED_AT = ""
PROTECTED_PUBLIC_SUFFIXES: set[str] = set()
PROTECTED_MULTI_TENANT_ROOTS: set[str] = set()
PUBLIC_SUFFIX_DATABASE: PublicSuffixDatabase | None = None

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
REJECT_ACTIONS = {"REJECT", "REJECT-DROP", "REJECT-NO-DROP"}

RULE_LEAF_DOMAIN = b"project-g-rule-v1\0"
RULE_NODE_DOMAIN = b"project-g-rule-node-v1\0"
EMPTY_RULE_SET_ROOT = hashlib.sha256(b"project-g-empty-rule-set-v1").hexdigest()

HOST_LINE_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+([^\s#;]+)")
FOOTNOTE_RE = re.compile(r"\s*\[[0-9]+\]\s*$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,62}$"
)
DUPLICATE_ARTIFACT_RE = re.compile(r"^.+ [0-9]+(?:\.[A-Za-z0-9_-]+)?$")


class BuildError(RuntimeError):
    pass


def rule_leaf_digest(rule: str) -> bytes:
    return hashlib.sha256(RULE_LEAF_DOMAIN + rule.encode("utf-8")).digest()


def build_rule_merkle_levels(rules: set[str] | tuple[str, ...]) -> tuple[list[str], list[list[bytes]]]:
    ordered = sorted(rules)
    if not ordered:
        return ordered, []
    levels = [[rule_leaf_digest(rule) for rule in ordered]]
    while len(levels[-1]) > 1:
        current = levels[-1]
        next_level: list[bytes] = []
        for index in range(0, len(current), 2):
            left = current[index]
            right = current[index + 1] if index + 1 < len(current) else left
            next_level.append(hashlib.sha256(RULE_NODE_DOMAIN + left + right).digest())
        levels.append(next_level)
    return ordered, levels


def rule_set_merkle_root(rules: set[str]) -> str:
    _ordered, levels = build_rule_merkle_levels(rules)
    return levels[-1][0].hex() if levels else EMPTY_RULE_SET_ROOT


def configured_source_digest(source: dict[str, Any]) -> str:
    payload = (
        json.dumps(
            source,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_protected_domain_roots(
    path: pathlib.Path, repository_root: pathlib.Path
) -> tuple[set[str], set[str], PublicSuffixDatabase]:
    payload = read_json(path)
    if payload.get("schema") != "project-g-protected-domain-roots-v1":
        raise BuildError("protected domain root schema is invalid")
    collections: list[set[str]] = []
    for field_name in ("public_suffixes", "multi_tenant_roots"):
        raw = payload.get(field_name)
        if not isinstance(raw, list) or any(
            not isinstance(item, str) for item in raw
        ):
            raise BuildError(f"protected domain roots {field_name} must be an array")
        normalized = [item.lower().strip(".") for item in raw]
        if (
            normalized != sorted(normalized)
            or len(normalized) != len(set(normalized))
            or any(not DOMAIN_RE.fullmatch(item) for item in normalized)
        ):
            raise BuildError(
                f"protected domain roots {field_name} must contain sorted unique domains"
            )
        collections.append(set(normalized))
    if collections[0] & collections[1]:
        raise BuildError("protected domain root classes must not overlap")
    try:
        database = load_public_suffix_database(
            payload.get("public_suffix_list"), repository_root
        )
    except PublicSuffixPolicyError as exc:
        raise BuildError(str(exc)) from exc
    return collections[0], collections[1], database


def register_source_rule_set(source_id: str, rules: set[str]) -> str:
    ordered, levels = build_rule_merkle_levels(rules)
    SOURCE_RULE_SETS[source_id] = tuple(ordered)
    return levels[-1][0].hex() if levels else EMPTY_RULE_SET_ROOT


def rule_membership_witness(source_id: str, rule: str) -> dict[str, Any]:
    rules = SOURCE_RULE_SETS.get(source_id)
    if rules is None:
        raise BuildError(
            f"rule attribution lacks accepted-source membership: {source_id}: {rule}"
        )
    cached = SOURCE_RULE_MERKLE_CACHE.get(source_id)
    if cached is None:
        cached = build_rule_merkle_levels(rules)
        SOURCE_RULE_MERKLE_CACHE[source_id] = cached
    ordered, levels = cached
    index = bisect.bisect_left(ordered, rule)
    if index >= len(ordered) or ordered[index] != rule:
        raise BuildError(
            f"rule attribution witness lookup failed: {source_id}: {rule}"
        )
    cursor = index
    proof: list[dict[str, str]] = []
    for level in levels[:-1]:
        if cursor % 2:
            sibling_index = cursor - 1
            side = "left"
        else:
            sibling_index = cursor + 1 if cursor + 1 < len(level) else cursor
            side = "right"
        proof.append({"side": side, "sha256": level[sibling_index].hex()})
        cursor //= 2
    return {
        "source_id": source_id,
        "leaf_index": index,
        "leaf_count": len(ordered),
        "proof": proof,
    }


@dataclass
class SourceBuildResult:
    rules: set[str]
    used_cache: bool
    source_ref: str
    provenance: dict[str, Any] = field(default_factory=dict)


def log(message: str) -> None:
    print(f"[ruleset] {message}")


def action_family(action: str) -> str:
    action = str(action).upper().strip()
    if action in REJECT_ACTIONS:
        return "REJECT"
    if action in {"DIRECT", "PROXY"}:
        return action
    return "UNSPECIFIED"


def record_fetch_event(url: str, mode: str, error: str = "", **metadata: Any) -> None:
    payload: dict[str, Any] = {"mode": mode, "error": error}
    payload.update(metadata)
    current = FETCH_EVENTS.get(url)
    if current is None:
        FETCH_EVENTS[url] = payload
        return

    current_prio = FETCH_MODE_PRIORITY.get(current.get("mode", "network"), 0)
    mode_prio = FETCH_MODE_PRIORITY.get(mode, 0)
    if mode_prio > current_prio:
        FETCH_EVENTS[url] = payload
        return

    if error and not current.get("error"):
        current["error"] = error
    for key, value in metadata.items():
        if value not in (None, ""):
            current[key] = value


def record_fetch_attempt(url: str, outcome: str, error: str = "", **metadata: Any) -> None:
    payload: dict[str, Any] = {
        "url": url,
        "outcome": outcome,
    }
    if error:
        payload["error"] = error
    payload.update({key: value for key, value in metadata.items() if value not in (None, "")})
    FETCH_ATTEMPTS.append(payload)


def build_fetch_report() -> dict[str, Any]:
    network_success_count = 0
    primary_success_count = 0
    mirror_success_count = 0
    offline_cache_count = 0
    fallback_cache_count = 0
    fallback_events: list[dict[str, Any]] = []

    for url in sorted(FETCH_EVENTS):
        item = FETCH_EVENTS[url]
        mode = item.get("mode", "network")
        if mode in {"network", "not_modified"}:
            network_success_count += 1
            primary_success_count += 1
        elif mode == "mirror_network":
            network_success_count += 1
            mirror_success_count += 1
        elif mode == "offline_cache":
            offline_cache_count += 1
        elif mode == "fallback_cache":
            fallback_cache_count += 1
            out = dict(item)
            out["url"] = url
            fallback_events.append(out)

    return {
        "generated_at_utc": BUILD_GENERATED_AT or dt.datetime.now(dt.timezone.utc).isoformat(),
        "url_count": len(FETCH_EVENTS),
        "network_success_count": network_success_count,
        "primary_success_count": primary_success_count,
        "mirror_success_count": mirror_success_count,
        "offline_cache_count": offline_cache_count,
        "fallback_cache_count": fallback_cache_count,
        "fallback_events": fallback_events,
        "attempts": FETCH_ATTEMPTS,
    }


def purge_duplicate_artifacts(base_dir: pathlib.Path) -> int:
    if not base_dir.exists():
        return 0

    removed = 0
    candidates = sorted(base_dir.rglob("*"), key=lambda p: len(p.parts), reverse=True)
    for path in candidates:
        if not DUPLICATE_ARTIFACT_RE.fullmatch(path.name):
            continue
        if path.is_dir():
            shutil.rmtree(path)
            removed += 1
            continue
        if path.is_file():
            path.unlink()
            removed += 1
    return removed


def purge_duplicate_sibling_artifacts(target_path: pathlib.Path) -> int:
    parent = target_path.parent
    if not parent.exists():
        return 0

    removed = 0
    prefix = f"{target_path.name} "
    for candidate in sorted(parent.iterdir(), key=lambda p: len(p.parts), reverse=True):
        if candidate.name == target_path.name:
            continue
        if not candidate.name.startswith(prefix):
            continue
        if not DUPLICATE_ARTIFACT_RE.fullmatch(candidate.name):
            continue
        if candidate.is_dir():
            shutil.rmtree(candidate)
            removed += 1
            continue
        if candidate.is_file():
            candidate.unlink()
            removed += 1
    return removed


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


def collapse_ip_networks(networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> set[str]:
    rules: set[str] = set()
    ipv4: list[ipaddress.IPv4Network] = []
    ipv6: list[ipaddress.IPv6Network] = []

    for network in networks:
        if isinstance(network, ipaddress.IPv4Network):
            ipv4.append(network)
        else:
            ipv6.append(network)

    for network in ipaddress.collapse_addresses(ipv4):
        rules.add(format_ip_rule(network))
    for network in ipaddress.collapse_addresses(ipv6):
        rules.add(format_ip_rule(network))
    return rules


def parse_cidr_csv_first_column(text: str) -> set[str]:
    rules: set[str] = set()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        token = line.split(",", 1)[0].strip()
        if not token:
            continue

        explicit = parse_explicit_rule(token)
        if explicit and explicit.startswith(("IP-CIDR,", "IP-CIDR6,")):
            rules.add(explicit)
            continue

        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if isinstance(network, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            networks.append(network)

    rules.update(collapse_ip_networks(networks))
    return rules


def parse_adblock_text(text: str) -> set[str]:
    """Convert only DNS-safe adblock rules into whole-domain rules.

    Browser filter syntax can scope a rule to a URL path, resource type,
    first/third-party context, or a particular embedding domain.  Those rules
    cannot be represented by DNS/domain rulesets without broadening their
    meaning, so they must be skipped instead of being promoted to a root-domain
    block.
    """
    rules: set[str] = set()
    exceptions: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("!", "[", "#", ";")):
            continue
        if line.startswith("@@"):
            exception = line[2:].strip()
            match = re.fullmatch(r"\|\|([A-Za-z0-9._-]+)\^", exception)
            if match:
                domain = normalize_domain(match.group(1))
                if domain:
                    exceptions.add(f"DOMAIN-SUFFIX,{domain}")
            continue
        if "##" in line or "#@#" in line or "#?#" in line:
            continue

        # Any browser/resource modifier changes the rule's scope.  Do not turn
        # it into an unconditional DNS block.
        if "$" in line:
            continue

        explicit = parse_explicit_rule(line)
        if explicit:
            rules.add(explicit)
            continue

        if line.startswith(("|http://", "|https://")):
            url = line[1:]
            if url.endswith("|"):
                url = url[:-1]
            try:
                parsed_url = urllib.parse.urlparse(url)
            except ValueError:
                parsed_url = None
            if parsed_url is None:
                continue
            # Do not upgrade path-specific URL filters into whole-domain DNS blocks.
            if parsed_url.path not in {"", "/"} or parsed_url.params or parsed_url.query or parsed_url.fragment:
                continue
            domain = normalize_domain(parsed_url.hostname or "")
            if domain:
                rules.add(f"DOMAIN,{domain}")
            continue

        if line.startswith("||"):
            match = re.fullmatch(r"\|\|([A-Za-z0-9._-]+)\^", line)
            if match is None:
                continue
            domain = normalize_domain(match.group(1))
            if domain:
                rules.add(f"DOMAIN-SUFFIX,{domain}")
            continue

        host_match = HOST_LINE_RE.match(line)
        if host_match:
            domain = normalize_domain(host_match.group(1))
            if domain:
                rules.add(f"DOMAIN,{domain}")
            continue

        # Plain DNS blocklists and phishing feeds are also accepted by this
        # source type.  Require an exact domain/IP token; normalize_domain()
        # deliberately strips paths and therefore is too permissive here.
        plain = line.rstrip(".").lower()
        domain = normalize_domain(plain)
        if domain and domain == plain:
            rules.add(f"DOMAIN-SUFFIX,{domain}")
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        rules.add(format_ip_rule(network))

    rules.difference_update(exceptions)
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


def parse_fastly_public_ip_list(data: bytes) -> set[str]:
    rules: set[str] = set()
    payload = json.loads(data.decode("utf-8"))

    for key in ("addresses", "ipv6_addresses"):
        entries = payload.get(key, [])
        if not isinstance(entries, list):
            continue
        for item in entries:
            prefix = str(item).strip()
            if not prefix:
                continue
            try:
                rules.add(format_ip_rule(ipaddress.ip_network(prefix, strict=False)))
            except ValueError:
                continue

    return rules


def parse_iana_tld_list_text(text: str, exclude_tlds: set[str]) -> set[str]:
    rules: set[str] = set()
    excluded = {item.lower() for item in exclude_tlds}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split("#", 1)[0].strip().lower()
        if not token:
            continue
        if token in excluded:
            continue
        # IANA list uses ASCII TLD labels (including punycode where needed).
        if not re.fullmatch(r"[a-z0-9-]{2,63}", token):
            continue
        rules.add(f"DOMAIN-SUFFIX,{token}")
    return rules


def parse_v2fly_attrs(payload: str) -> tuple[str, set[str]]:
    parts = payload.strip().split()
    if not parts:
        return "", set()
    value = parts[0].strip()
    attrs = {part.strip() for part in parts[1:] if part.strip().startswith("@")}
    return value, attrs


def split_v2fly_include_selectors(attrs: set[str]) -> tuple[set[str], set[str]]:
    """Return required and excluded rule attributes for an include line.

    v2fly defines ``include:list @attr @-other`` as selecting rules that have
    ``@attr`` and do not have ``@other``.
    """
    required: set[str] = set()
    excluded: set[str] = set()
    for attr in attrs:
        if attr.startswith("@-") and len(attr) > 2:
            excluded.add(f"@{attr[2:]}")
        elif attr.startswith("@") and len(attr) > 1:
            required.add(attr)
    return required, excluded


def parse_v2fly_dlc_text(
    text: str,
    *,
    include_attrs: set[str],
    exclude_attrs: set[str],
    required_attrs: set[str],
    include_handler: Any,
) -> set[str]:
    rules: set[str] = set()

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if not line:
            continue

        line_type = ""
        payload = line
        if ":" in line:
            prefix, rest = line.split(":", 1)
            prefix = prefix.strip().lower()
            if prefix in {"include", "full", "domain", "keyword", "regexp"}:
                line_type = prefix
                payload = rest.strip()

        if line_type == "include":
            include_name, include_selectors = parse_v2fly_attrs(payload)
            if include_name:
                required, excluded = split_v2fly_include_selectors(include_selectors)
                rules.update(include_handler(include_name, required, excluded))
            continue

        value, attrs = parse_v2fly_attrs(payload)
        if not value:
            continue

        if include_attrs and not (attrs & include_attrs):
            continue
        if required_attrs and not required_attrs.issubset(attrs):
            continue
        if exclude_attrs and (attrs & exclude_attrs):
            continue

        if line_type == "full":
            domain = normalize_domain(value)
            if domain:
                rules.add(f"DOMAIN,{domain}")
            continue

        if line_type == "domain":
            domain = normalize_domain(value)
            if domain:
                rules.add(f"DOMAIN-SUFFIX,{domain}")
            continue

        if line_type == "keyword":
            rules.add(f"DOMAIN-KEYWORD,{value}")
            continue

        if line_type == "regexp":
            rules.add(f"DOMAIN-REGEX,{value}")
            continue

        parsed = parse_domain_or_ip_token(value)
        if parsed:
            rules.add(parsed)

    return rules


def parse_v2fly_dlc_source(
    source_urls: list[str],
    cache_dir: pathlib.Path,
    offline: bool,
    include_attrs: set[str],
    exclude_attrs: set[str],
    exclude_includes: set[str],
    *,
    source_id: str = "",
    lock_entry: dict[str, Any] | None = None,
    controls: dict[str, Any] | None = None,
) -> tuple[set[str], bool, str]:
    if not source_urls:
        raise BuildError("v2fly_dlc source requires at least one URL")

    visited: set[tuple[str, frozenset[str], frozenset[str]]] = set()
    rules: set[str] = set()
    used_cache_only = True
    base_urls = [candidate.rsplit("/", 1)[0] for candidate in source_urls]
    root_name = source_urls[0].rsplit("/", 1)[-1]
    resolved_root_url = source_urls[0]
    include_graph: list[dict[str, Any]] = []
    file_records: dict[str, dict[str, Any]] = {}
    archive_files: dict[str, bytes] | None = None
    archive_meta: dict[str, Any] = {}
    archive_used_cache = False

    if lock_entry is not None:
        if controls is None:
            raise BuildError("v2fly source lock requires source controls")
        archive_files, archive_used_cache, archive_meta = load_v2fly_archive(
            lock_entry,
            cache_dir,
            offline,
            controls,
        )
        revision = str(lock_entry["resolved_revision"])
        resolved_root_url = (
            "https://github.com/v2fly/domain-list-community/blob/"
            f"{revision}/data/{root_name}"
        )

    def fetch_relative(name: str) -> tuple[bytes, bool, str]:
        if archive_files is not None:
            payload = archive_files.get(name)
            if payload is None:
                raise BuildError(
                    f"v2fly include '{name}' is missing from locked revision "
                    f"{lock_entry['resolved_revision'] if lock_entry else 'unknown'}"
                )
            return payload, archive_used_cache, (
                "https://github.com/v2fly/domain-list-community/blob/"
                f"{lock_entry['resolved_revision']}/data/{name}"
            )
        candidates = [f"{base}/{name}" for base in base_urls]
        source: dict[str, Any] = {"url": candidates[0], "fallback_urls": candidates[1:]}
        if controls is not None:
            source = apply_source_controls(source, controls)
        return fetch_source_bytes(source, cache_dir, offline)

    def walk(
        name: str,
        required_attrs: set[str] | None = None,
        inherited_exclude_attrs: set[str] | None = None,
        depth: int = 0,
    ) -> set[str]:
        nonlocal used_cache_only
        nonlocal resolved_root_url
        max_depth = int((controls or {}).get("max_include_depth", 64))
        max_files = int((controls or {}).get("max_files", 10000))
        if depth > max_depth:
            raise BuildError(
                f"v2fly include depth exceeded for {root_name}: {depth} > {max_depth}"
            )
        required_attrs = set(required_attrs or set())
        effective_exclude_attrs = set(exclude_attrs)
        effective_exclude_attrs.update(inherited_exclude_attrs or set())
        visit_key = (
            name,
            frozenset(required_attrs),
            frozenset(effective_exclude_attrs),
        )
        if visit_key in visited:
            return set()
        visited.add(visit_key)
        if len(visited) > max_files:
            raise BuildError(
                f"v2fly include file count exceeded for {root_name}: {len(visited)} > {max_files}"
            )

        if required_attrs & effective_exclude_attrs:
            return set()

        data, used_cache, chosen_url = fetch_relative(name)
        if name == root_name:
            resolved_root_url = chosen_url
        used_cache_only = used_cache_only and used_cache
        text = decode_text(data)
        file_records[name] = {
            "path": f"data/{name}",
            "content_sha256": hashlib.sha256(data).hexdigest(),
            "byte_count": len(data),
            "nonempty_line_count": sum(
                1
                for raw in text.splitlines()
                if raw.strip() and not raw.strip().startswith("#")
            ),
        }

        def include_handler(
            include_name: str,
            include_required: set[str],
            include_excluded: set[str],
        ) -> set[str]:
            if include_name in exclude_includes:
                include_graph.append(
                    {
                        "from": f"data/{name}",
                        "to": f"data/{include_name}",
                        "status": "excluded",
                    }
                )
                return set()
            include_graph.append(
                {
                    "from": f"data/{name}",
                    "to": f"data/{include_name}",
                    "status": "included",
                    "required_attrs": sorted(include_required),
                    "excluded_attrs": sorted(include_excluded),
                }
            )
            return walk(
                include_name,
                required_attrs=required_attrs | include_required,
                inherited_exclude_attrs=effective_exclude_attrs | include_excluded,
                depth=depth + 1,
            )

        parsed_rules = parse_v2fly_dlc_text(
            text,
            include_attrs=include_attrs,
            exclude_attrs=effective_exclude_attrs,
            required_attrs=required_attrs,
            include_handler=include_handler,
        )
        file_records[name]["rule_count_with_includes"] = len(parsed_rules)
        return parsed_rules

    rules.update(walk(root_name))
    if source_id:
        V2FLY_PARSE_PROVENANCE[source_id] = {
            **archive_meta,
            "root_path": f"data/{root_name}",
            "resolved_ref": resolved_root_url,
            "included_file_count": len(file_records),
            "include_graph": sorted(
                include_graph,
                key=lambda item: (
                    str(item.get("from", "")),
                    str(item.get("to", "")),
                    str(item.get("status", "")),
                ),
            ),
            "files": [file_records[key] for key in sorted(file_records)],
        }
    return rules, used_cache_only, resolved_root_url


def cache_paths(url: str, cache_dir: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
    return cache_dir / f"{digest}.bin", cache_dir / f"{digest}.json"


def parse_utc_timestamp(value: str) -> dt.datetime:
    normalized = value.strip().replace("Z", "+00:00")
    parsed = dt.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def validate_fetch_url(url: str, allowed_hosts: set[str] | None = None) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise BuildError(f"source URL must use https with a hostname: {url}")
    hostname = parsed.hostname.lower()
    if allowed_hosts and hostname not in allowed_hosts:
        raise BuildError(f"source host is not allowlisted: {hostname}")
    return hostname


def read_cache_metadata(meta_file: pathlib.Path) -> dict[str, Any]:
    try:
        payload = json.loads(meta_file.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BuildError(f"cache metadata missing: {meta_file}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BuildError(f"cache metadata invalid: {meta_file}: {exc}") from exc
    if not isinstance(payload, dict):
        raise BuildError(f"cache metadata must be an object: {meta_file}")
    return payload


def write_cache_metadata_atomic(
    meta_file: pathlib.Path,
    metadata: dict[str, Any],
) -> None:
    temp_path: pathlib.Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=meta_file.parent,
            prefix=f".{meta_file.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = pathlib.Path(handle.name)
            json.dump(metadata, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(meta_file)
    except OSError as exc:
        raise BuildError(f"cache metadata write failed: {meta_file}: {exc}") from exc
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def load_validated_cache(
    url: str,
    cache_dir: pathlib.Path,
    *,
    max_bytes: int,
    cache_ttl_hours: float,
    expected_sha256: str = "",
    mode: str,
    error: str = "",
) -> tuple[bytes, bool]:
    cache_file, meta_file = cache_paths(url, cache_dir)
    if not cache_file.exists():
        raise BuildError(f"no cache for {url}")

    metadata = read_cache_metadata(meta_file)
    if str(metadata.get("url", "")) != url:
        raise BuildError(f"cache URL mismatch for {url}")

    data = cache_file.read_bytes()
    if not data:
        raise BuildError(f"cached response is empty for {url}")
    if len(data) > max_bytes:
        raise BuildError(f"cached response exceeds max_bytes for {url}: {len(data)} > {max_bytes}")

    actual_sha256 = hashlib.sha256(data).hexdigest()
    recorded_sha256 = str(metadata.get("content_sha256", "")).strip().lower()
    if len(recorded_sha256) != 64 or recorded_sha256 != actual_sha256:
        raise BuildError(f"cache digest mismatch for {url}")
    if expected_sha256 and actual_sha256 != expected_sha256.lower():
        raise BuildError(f"cache does not match expected SHA-256 for {url}")

    try:
        fetched_at = parse_utc_timestamp(str(metadata["fetched_at_utc"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise BuildError(f"cache timestamp invalid for {url}") from exc
    try:
        validated_at = parse_utc_timestamp(
            str(metadata.get("validated_at_utc", metadata["fetched_at_utc"]))
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise BuildError(f"cache validation timestamp invalid for {url}") from exc
    age_seconds = max(
        0.0,
        (dt.datetime.now(dt.timezone.utc) - validated_at).total_seconds(),
    )
    if cache_ttl_hours >= 0 and age_seconds > cache_ttl_hours * 3600:
        raise BuildError(
            f"cache expired for {url}: age_hours={age_seconds / 3600:.2f} "
            f"ttl_hours={cache_ttl_hours:.2f}"
        )

    result = (data, True)
    record_fetch_event(
        url,
        mode,
        error=error,
        content_sha256=actual_sha256,
        byte_count=len(data),
        cache_age_seconds=round(age_seconds, 3),
        cache_age_basis="validated_at_utc",
        fetched_at_utc=fetched_at.isoformat(),
        validated_at_utc=validated_at.isoformat(),
        etag=str(metadata.get("etag", "")),
        last_modified=str(metadata.get("last_modified", "")),
        final_url=str(metadata.get("final_url", url)),
    )
    record_fetch_attempt(
        url,
        mode,
        error=error,
        content_sha256=actual_sha256,
        byte_count=len(data),
        cache_age_seconds=round(age_seconds, 3),
        cache_age_basis="validated_at_utc",
        validated_at_utc=validated_at.isoformat(),
    )
    FETCH_MEMO[url] = result
    return result


def fetch_bytes(
    url: str,
    cache_dir: pathlib.Path,
    offline: bool = False,
    *,
    allow_cache_fallback: bool = True,
    max_bytes: int = 64 * 1024 * 1024,
    cache_ttl_hours: float = 168.0,
    allowed_hosts: set[str] | None = None,
    expected_sha256: str = "",
) -> tuple[bytes, bool]:
    memo_hit = FETCH_MEMO.get(url)
    if memo_hit is not None:
        memo_data, _memo_cache = memo_hit
        if len(memo_data) > max_bytes:
            raise BuildError(f"memoized response exceeds max_bytes for {url}")
        if expected_sha256 and hashlib.sha256(memo_data).hexdigest() != expected_sha256.lower():
            raise BuildError(f"memoized response does not match expected SHA-256 for {url}")
        validate_fetch_url(url, allowed_hosts)
        return memo_hit

    validate_fetch_url(url, allowed_hosts)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file, meta_file = cache_paths(url, cache_dir)

    if offline:
        try:
            return load_validated_cache(
                url,
                cache_dir,
                max_bytes=max_bytes,
                cache_ttl_hours=cache_ttl_hours,
                expected_sha256=expected_sha256,
                mode="offline_cache",
            )
        except BuildError as exc:
            raise BuildError(f"offline mode: {exc}") from exc

    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if cache_file.exists() and meta_file.exists():
        try:
            cached_metadata = read_cache_metadata(meta_file)
        except BuildError:
            cached_metadata = {}
        etag = str(cached_metadata.get("etag", "")).strip()
        last_modified = str(cached_metadata.get("last_modified", "")).strip()
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified

    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            final_url = response.geturl()
            validate_fetch_url(final_url, allowed_hosts)
            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    declared_size = int(content_length)
                except ValueError:
                    declared_size = -1
                if declared_size > max_bytes:
                    raise BuildError(
                        f"response exceeds max_bytes for {url}: {declared_size} > {max_bytes}"
                    )
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise BuildError(
                    f"response exceeds max_bytes for {url}: {len(data)} > {max_bytes}"
                )
            etag = str(response.headers.get("ETag", "")).strip()
            last_modified = str(response.headers.get("Last-Modified", "")).strip()
        if not data:
            raise BuildError(f"empty response from {url}")
        content_sha256 = hashlib.sha256(data).hexdigest()
        if expected_sha256 and content_sha256 != expected_sha256.lower():
            raise BuildError(f"response does not match expected SHA-256 for {url}")
        cache_file.write_bytes(data)
        fetched_at_utc = dt.datetime.now(dt.timezone.utc).isoformat()
        metadata = {
            "url": url,
            "final_url": final_url,
            "fetched_at_utc": fetched_at_utc,
            "validated_at_utc": fetched_at_utc,
            "content_sha256": content_sha256,
            "byte_count": len(data),
            "etag": etag,
            "last_modified": last_modified,
        }
        write_cache_metadata_atomic(meta_file, metadata)
        result = (data, False)
        record_fetch_event(
            url,
            "network",
            content_sha256=content_sha256,
            byte_count=len(data),
            etag=etag,
            last_modified=last_modified,
            final_url=final_url,
        )
        record_fetch_attempt(
            url,
            "network_success",
            content_sha256=content_sha256,
            byte_count=len(data),
            final_url=final_url,
        )
        FETCH_MEMO[url] = result
        return result
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            try:
                cached_data, _used_cache = load_validated_cache(
                    url,
                    cache_dir,
                    max_bytes=max_bytes,
                    cache_ttl_hours=-1,
                    expected_sha256=expected_sha256,
                    mode="not_modified",
                )
                metadata = read_cache_metadata(meta_file)
                validated_at_utc = dt.datetime.now(dt.timezone.utc).isoformat()
                metadata["validated_at_utc"] = validated_at_utc
                response_headers = exc.headers or {}
                response_etag = str(response_headers.get("ETag", "")).strip()
                response_last_modified = str(
                    response_headers.get("Last-Modified", "")
                ).strip()
                if response_etag:
                    metadata["etag"] = response_etag
                if response_last_modified:
                    metadata["last_modified"] = response_last_modified
                write_cache_metadata_atomic(meta_file, metadata)
                FETCH_EVENTS[url].update(
                    {
                        "cache_age_seconds": 0,
                        "cache_age_basis": "validated_at_utc",
                        "validated_at_utc": validated_at_utc,
                        "etag": str(metadata.get("etag", "")),
                        "last_modified": str(metadata.get("last_modified", "")),
                    }
                )
                for attempt in reversed(FETCH_ATTEMPTS):
                    if (
                        attempt.get("url") == url
                        and attempt.get("outcome") == "not_modified"
                    ):
                        attempt.update(
                            {
                                "cache_age_seconds": 0,
                                "cache_age_basis": "validated_at_utc",
                                "validated_at_utc": validated_at_utc,
                            }
                        )
                        break
                result = (cached_data, False)
                FETCH_MEMO[url] = result
                return result
            except BuildError as cache_exc:
                raise BuildError(f"304 response without a valid cache for {url}: {cache_exc}") from exc
        failure: Exception = exc
    except (urllib.error.URLError, TimeoutError, OSError, BuildError) as exc:
        failure = exc

    record_fetch_attempt(url, "network_failure", error=str(failure))
    if allow_cache_fallback:
        try:
            log(f"warning: fetch failed for {url}; validating cache ({failure})")
            return load_validated_cache(
                url,
                cache_dir,
                max_bytes=max_bytes,
                cache_ttl_hours=cache_ttl_hours,
                expected_sha256=expected_sha256,
                mode="fallback_cache",
                error=str(failure),
            )
        except BuildError as cache_exc:
            raise BuildError(f"fetch failed for {url}: {failure}; cache rejected: {cache_exc}") from failure
    raise BuildError(f"fetch failed for {url}: {failure}") from failure


def collect_source_urls(source: dict[str, Any]) -> list[str]:
    urls: list[str] = []

    primary_url = str(source.get("url", "")).strip()
    if primary_url:
        urls.append(primary_url)

    raw_urls = source.get("urls")
    if raw_urls is not None:
        if not isinstance(raw_urls, list):
            raise BuildError("source field 'urls' must be an array")
        for item in raw_urls:
            candidate = str(item).strip()
            if candidate:
                urls.append(candidate)

    fallback_urls = source.get("fallback_urls")
    if fallback_urls is not None:
        if not isinstance(fallback_urls, list):
            raise BuildError("source field 'fallback_urls' must be an array")
        for item in fallback_urls:
            candidate = str(item).strip()
            if candidate:
                urls.append(candidate)

    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in urls:
        if candidate in seen:
            continue
        seen.add(candidate)
        deduped.append(candidate)
    return deduped


def make_source_id(category_id: str, source_index: int, source: dict[str, Any]) -> str:
    configured = str(source.get("source_id", "")).strip()
    if configured:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._:-]{2,127}", configured):
            raise BuildError(f"invalid source_id: {configured}")
        return configured

    identity = {
        "type": source.get("type"),
        "url": source.get("url"),
        "urls": source.get("urls"),
        "fallback_urls": source.get("fallback_urls"),
        "path": source.get("path"),
        "include_attrs": source.get("include_attrs"),
        "exclude_attrs": source.get("exclude_attrs"),
        "exclude_includes": source.get("exclude_includes"),
    }
    digest = hashlib.sha256(
        json.dumps(identity, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()[:12]
    return f"{category_id}:{source_index:02d}:{str(source.get('type', 'unknown'))}:{digest}"


def source_controls(source: dict[str, Any]) -> dict[str, Any]:
    authority = str(source.get("authority", "unspecified")).strip()
    profiles = SOURCE_REGISTRY.get("authority_profiles", {})
    if not isinstance(profiles, dict):
        raise BuildError("source registry: authority_profiles must be an object")
    raw_profile = profiles.get(authority)
    if not isinstance(raw_profile, dict):
        raise BuildError(f"source registry: unknown authority profile '{authority}'")

    controls = dict(raw_profile)
    source_type = str(source.get("type", "")).strip()

    for field_name in (
        "trust_tier",
        "license",
        "owner",
        "revision_strategy",
    ):
        if field_name in source and source[field_name] != raw_profile.get(field_name):
            raise BuildError(
                f"source authority '{authority}' cannot override {field_name}"
            )

    for field_name in (
        "max_bytes",
        "max_files",
        "max_include_depth",
        "max_uncompressed_bytes",
        "freshness_ttl_hours",
    ):
        if field_name not in source:
            continue
        try:
            profile_value = float(raw_profile[field_name])
            source_value = float(source[field_name])
        except (KeyError, TypeError, ValueError) as exc:
            raise BuildError(
                f"source authority '{authority}' has invalid {field_name}"
            ) from exc
        if source_value < 0 or source_value > profile_value:
            raise BuildError(
                f"source authority '{authority}' cannot relax {field_name}: "
                f"{source_value:g} > {profile_value:g}"
            )
        controls[field_name] = source[field_name]

    if "accepted_line_ratio" in source:
        try:
            profile_ratio = float(raw_profile["accepted_line_ratio"])
            source_ratio = float(source["accepted_line_ratio"])
        except (KeyError, TypeError, ValueError) as exc:
            raise BuildError(
                f"source authority '{authority}' has invalid accepted_line_ratio"
            ) from exc
        if not profile_ratio <= source_ratio <= 1:
            raise BuildError(
                f"source authority '{authority}' cannot relax accepted_line_ratio"
            )
        controls["accepted_line_ratio"] = source["accepted_line_ratio"]

    for field_name in (
        "critical",
        "no_cache_publish",
        "require_lock",
    ):
        if field_name not in source:
            continue
        profile_value = bool(raw_profile.get(field_name, False))
        source_value = bool(source[field_name])
        if profile_value and not source_value:
            raise BuildError(
                f"source authority '{authority}' cannot disable {field_name}"
            )
        controls[field_name] = source_value

    profile_parser = str(raw_profile.get("expected_parser", "")).strip()
    source_parser = str(source.get("expected_parser", profile_parser)).strip()
    if profile_parser not in {"", "*"} and source_parser != profile_parser:
        raise BuildError(
            f"source authority '{authority}' cannot override expected_parser"
        )
    if profile_parser == "*" and source_parser not in {"*", source_type}:
        raise BuildError(
            f"source authority '{authority}' can only narrow expected_parser "
            f"to '{source_type}'"
        )
    controls["expected_parser"] = source_parser

    profile_rule_types_raw = raw_profile.get("allowed_rule_types", [])
    if not isinstance(profile_rule_types_raw, list):
        raise BuildError(
            f"source registry: authority '{authority}' allowed_rule_types must be an array"
        )
    profile_rule_types = {
        str(item).strip().upper()
        for item in profile_rule_types_raw
        if str(item).strip()
    }
    source_rule_types_raw = source.get("allowed_rule_types")
    if source_rule_types_raw is not None:
        if not isinstance(source_rule_types_raw, list):
            raise BuildError("source field 'allowed_rule_types' must be an array")
        source_rule_types = {
            str(item).strip().upper()
            for item in source_rule_types_raw
            if str(item).strip()
        }
        unauthorized_types = source_rule_types - profile_rule_types
        if unauthorized_types:
            raise BuildError(
                f"source authority '{authority}' cannot expand allowed_rule_types: "
                + ", ".join(sorted(unauthorized_types))
            )
        controls["allowed_rule_types"] = sorted(source_rule_types)

    raw_hosts = raw_profile.get("allowed_hosts", [])
    if not isinstance(raw_hosts, list):
        raise BuildError(
            f"source registry: authority '{authority}' allowed_hosts must be an array"
        )
    profile_hosts = {
        str(item).strip().lower()
        for item in raw_hosts
        if str(item).strip()
    }
    source_hosts_raw = source.get("allowed_hosts")
    if source_hosts_raw is None:
        allowed_hosts = set(profile_hosts)
    else:
        if not isinstance(source_hosts_raw, list):
            raise BuildError("source field 'allowed_hosts' must be an array")
        source_hosts = {
            str(item).strip().lower()
            for item in source_hosts_raw
            if str(item).strip()
        }
        unauthorized_hosts = source_hosts - profile_hosts
        if unauthorized_hosts:
            raise BuildError(
                f"source authority '{authority}' cannot expand allowed_hosts: "
                + ", ".join(sorted(unauthorized_hosts))
            )
        allowed_hosts = source_hosts

    expected_parser = str(controls.get("expected_parser", source_type)).strip()
    if expected_parser not in {"", "*", source_type}:
        raise BuildError(
            f"source parser mismatch: configured={source_type} expected={expected_parser}"
        )

    required_text = {
        "trust_tier": str(controls.get("trust_tier", "")).strip(),
        "license": str(controls.get("license", "")).strip(),
        "owner": str(controls.get("owner", "")).strip(),
        "revision_strategy": str(controls.get("revision_strategy", "")).strip(),
    }
    for field_name, value in required_text.items():
        if not value:
            raise BuildError(f"source registry: authority '{authority}' missing {field_name}")

    max_bytes = int(controls.get("max_bytes", 0))
    max_files = int(controls.get("max_files", 0))
    max_include_depth = int(controls.get("max_include_depth", 0))
    max_uncompressed_bytes = int(controls.get("max_uncompressed_bytes", max_bytes * 4))
    freshness_ttl_hours = float(controls.get("freshness_ttl_hours", 0))
    accepted_line_ratio = float(controls.get("accepted_line_ratio", 0))
    if min(max_bytes, max_files, max_include_depth, max_uncompressed_bytes) <= 0:
        raise BuildError(f"source registry: invalid resource limit for authority '{authority}'")
    if freshness_ttl_hours < 0:
        raise BuildError(f"source registry: negative freshness_ttl_hours for '{authority}'")
    if not 0 <= accepted_line_ratio <= 1:
        raise BuildError(f"source registry: accepted_line_ratio must be between 0 and 1")

    controls.update(required_text)
    controls.update(
        {
            "allowed_hosts": sorted(allowed_hosts),
            "max_bytes": max_bytes,
            "max_files": max_files,
            "max_include_depth": max_include_depth,
            "max_uncompressed_bytes": max_uncompressed_bytes,
            "freshness_ttl_hours": freshness_ttl_hours,
            "accepted_line_ratio": accepted_line_ratio,
            "critical": bool(controls.get("critical", False)),
            "no_cache_publish": bool(controls.get("no_cache_publish", False)),
            "require_lock": bool(controls.get("require_lock", False)),
        }
    )
    return controls


def apply_source_controls(source: dict[str, Any], controls: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(source)
    enriched["_allowed_hosts"] = list(controls["allowed_hosts"])
    enriched["_max_bytes"] = int(controls["max_bytes"])
    enriched["_cache_ttl_hours"] = float(controls["freshness_ttl_hours"])
    return enriched


def v2fly_lock_entry() -> dict[str, Any] | None:
    repositories = SOURCE_LOCK.get("repositories", {})
    if not isinstance(repositories, dict):
        raise BuildError("source lock: repositories must be an object")
    raw = repositories.get("v2fly/domain-list-community")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise BuildError("source lock: v2fly entry must be an object")
    revision = str(raw.get("resolved_revision", "")).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise BuildError("source lock: v2fly resolved_revision must be a 40-character SHA")
    archive_urls = raw.get("archive_urls", [])
    if not isinstance(archive_urls, list) or not archive_urls:
        raise BuildError("source lock: v2fly archive_urls must be a non-empty array")
    return raw


def load_v2fly_archive(
    lock_entry: dict[str, Any],
    cache_dir: pathlib.Path,
    offline: bool,
    controls: dict[str, Any],
) -> tuple[dict[str, bytes], bool, dict[str, Any]]:
    revision = str(lock_entry["resolved_revision"]).strip().lower()
    memo_hit = V2FLY_ARCHIVE_MEMO.get(revision)
    if memo_hit is not None:
        return memo_hit

    archive_urls = [str(item).strip() for item in lock_entry.get("archive_urls", []) if str(item).strip()]
    archive_source = apply_source_controls(
        {
            "url": archive_urls[0],
            "fallback_urls": archive_urls[1:],
        },
        controls,
    )
    data, used_cache, chosen_url = fetch_source_bytes(archive_source, cache_dir, offline)
    archive_sha256 = hashlib.sha256(data).hexdigest()

    files: dict[str, bytes] = {}
    total_uncompressed = 0
    member_count = 0
    archive_root = ""
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive.getmembers():
                if member.issym() or member.islnk() or member.isdev():
                    raise BuildError(f"v2fly archive contains unsafe member: {member.name}")
                if not member.isfile():
                    continue
                member_count += 1
                if member_count > int(controls["max_files"]):
                    raise BuildError(
                        f"v2fly archive exceeds max_files={controls['max_files']}"
                    )
                total_uncompressed += int(member.size)
                if total_uncompressed > int(controls["max_uncompressed_bytes"]):
                    raise BuildError(
                        "v2fly archive exceeds max_uncompressed_bytes="
                        f"{controls['max_uncompressed_bytes']}"
                    )

                path = pathlib.PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts:
                    raise BuildError(f"v2fly archive contains unsafe path: {member.name}")
                if len(path.parts) != 3 or path.parts[1] != "data":
                    continue
                member_root, _data_dir, data_name = path.parts
                if archive_root and member_root != archive_root:
                    raise BuildError("v2fly archive contains multiple top-level roots")
                archive_root = member_root
                if data_name in files:
                    raise BuildError(
                        f"v2fly archive contains duplicate canonical data file: {data_name}"
                    )
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise BuildError(f"v2fly archive member cannot be read: {member.name}")
                payload = extracted.read(int(controls["max_bytes"]) + 1)
                if len(payload) > int(controls["max_bytes"]):
                    raise BuildError(f"v2fly data file exceeds max_bytes: {member.name}")
                files[data_name] = payload
    except (tarfile.TarError, OSError) as exc:
        raise BuildError(f"invalid v2fly archive: {exc}") from exc

    if not files:
        raise BuildError("v2fly archive contains no data files")
    metadata = {
        "repository": "v2fly/domain-list-community",
        "requested_ref": str(lock_entry.get("requested_ref", "master")),
        "resolved_revision": revision,
        "archive_url": chosen_url,
        "archive_sha256": archive_sha256,
        "archive_bytes": len(data),
        "archive_root": archive_root,
        "archive_file_count": len(files),
        "archive_member_count": member_count,
        "archive_uncompressed_bytes": total_uncompressed,
        "cache_mode": str(FETCH_EVENTS.get(chosen_url, {}).get("mode", "unknown")),
        "etag": str(FETCH_EVENTS.get(chosen_url, {}).get("etag", "")),
        "last_modified": str(
            FETCH_EVENTS.get(chosen_url, {}).get("last_modified", "")
        ),
        "cache_age_seconds": FETCH_EVENTS.get(chosen_url, {}).get(
            "cache_age_seconds"
        ),
    }
    result = (files, used_cache, metadata)
    V2FLY_ARCHIVE_MEMO[revision] = result
    return result


def fetch_source_bytes(source: dict[str, Any], cache_dir: pathlib.Path, offline: bool) -> tuple[bytes, bool, str]:
    candidates = collect_source_urls(source)
    if not candidates:
        raise BuildError("source requires at least one URL (url / urls / fallback_urls)")

    allowed_hosts_raw = source.get("_allowed_hosts", source.get("allowed_hosts", []))
    if allowed_hosts_raw is None:
        allowed_hosts_raw = []
    if not isinstance(allowed_hosts_raw, list):
        raise BuildError("source field 'allowed_hosts' must be an array")
    allowed_hosts = {str(item).strip().lower() for item in allowed_hosts_raw if str(item).strip()}
    if not allowed_hosts:
        allowed_hosts = {
            str(urllib.parse.urlparse(candidate).hostname or "").lower()
            for candidate in candidates
            if urllib.parse.urlparse(candidate).hostname
        }
    max_bytes = int(source.get("_max_bytes", source.get("max_bytes", 64 * 1024 * 1024)))
    if max_bytes <= 0:
        raise BuildError("source max_bytes must be > 0")
    cache_ttl_hours = float(
        source.get("_cache_ttl_hours", source.get("freshness_ttl_hours", 168.0))
    )
    expected_sha256 = str(source.get("expected_sha256", "")).strip().lower()
    if expected_sha256 and (
        len(expected_sha256) != 64
        or any(ch not in "0123456789abcdef" for ch in expected_sha256)
    ):
        raise BuildError("source expected_sha256 must be a lowercase SHA-256 digest")

    errors: list[str] = []
    if offline:
        for candidate in candidates:
            try:
                data, used_cache = fetch_bytes(
                    candidate,
                    cache_dir,
                    offline=True,
                    max_bytes=max_bytes,
                    cache_ttl_hours=cache_ttl_hours,
                    allowed_hosts=allowed_hosts,
                    expected_sha256=expected_sha256,
                )
                return data, used_cache, candidate
            except BuildError as exc:
                errors.append(f"{candidate}: {exc}")
        raise BuildError("all source caches failed; " + " | ".join(errors))

    for idx, candidate in enumerate(candidates):
        try:
            data, used_cache = fetch_bytes(
                candidate,
                cache_dir,
                offline=False,
                allow_cache_fallback=False,
                max_bytes=max_bytes,
                cache_ttl_hours=cache_ttl_hours,
                allowed_hosts=allowed_hosts,
                expected_sha256=expected_sha256,
            )
            if idx > 0:
                log(f"using fallback source URL: {candidate}")
                FETCH_EVENTS.setdefault(candidate, {"mode": "mirror_network", "error": ""})[
                    "mode"
                ] = "mirror_network"
            return data, used_cache, candidate
        except BuildError as exc:
            errors.append(f"{candidate}: {exc}")

    if bool(source.get("_no_cache_fallback", source.get("no_cache_fallback", False))):
        raise BuildError("all live source URLs failed and cache fallback is disabled; " + " | ".join(errors))

    cache_errors: list[str] = []
    for candidate in candidates:
        try:
            data, used_cache = load_validated_cache(
                candidate,
                cache_dir,
                max_bytes=max_bytes,
                cache_ttl_hours=cache_ttl_hours,
                expected_sha256=expected_sha256,
                mode="fallback_cache",
                error=" | ".join(errors),
            )
            log(f"warning: all live URLs failed; using validated cache for {candidate}")
            return data, used_cache, candidate
        except BuildError as exc:
            cache_errors.append(f"{candidate}: {exc}")

    raise BuildError(
        "all source URLs failed; "
        + " | ".join(errors)
        + "; all caches rejected; "
        + " | ".join(cache_errors)
    )


def decode_text(data: bytes) -> str:
    try:
        return data.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        raise BuildError(f"source is not valid UTF-8: {exc}") from exc


def rule_type_counts(rules: set[str]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for rule in rules:
        rule_type = rule.split(",", 1)[0].strip()
        counts[rule_type] += 1
    return {key: counts[key] for key in sorted(counts)}


def finalize_source_result(
    *,
    source: dict[str, Any],
    source_id: str,
    controls: dict[str, Any],
    rules: set[str],
    used_cache: bool,
    source_ref: str,
    data: bytes | None,
    text: str | None,
    extra_provenance: dict[str, Any] | None = None,
) -> SourceBuildResult:
    allowed_rule_types_raw = controls.get("allowed_rule_types", [])
    if allowed_rule_types_raw is None:
        allowed_rule_types_raw = []
    if not isinstance(allowed_rule_types_raw, list):
        raise BuildError("source registry: allowed_rule_types must be an array")
    allowed_rule_types = {
        str(item).strip().upper()
        for item in allowed_rule_types_raw
        if str(item).strip()
    }
    observed_rule_types = set(rule_type_counts(rules))
    forbidden_types = observed_rule_types - allowed_rule_types if allowed_rule_types else set()
    if forbidden_types:
        raise BuildError(
            f"source {source_id} emitted forbidden rule types: {', '.join(sorted(forbidden_types))}"
        )

    nonempty_lines = 0
    if text is not None:
        nonempty_lines = sum(
            1
            for raw in text.splitlines()
            if raw.strip() and not raw.strip().startswith(("#", ";", "!"))
        )
    accepted_ratio = min(1.0, len(rules) / nonempty_lines) if nonempty_lines else (1.0 if rules else 0.0)
    required_ratio = float(controls.get("accepted_line_ratio", 0))
    if nonempty_lines and accepted_ratio < required_ratio:
        raise BuildError(
            f"source {source_id} accepted-line ratio too low: "
            f"{accepted_ratio:.6f} < {required_ratio:.6f}"
        )

    fetch_metadata: dict[str, Any] = {}
    if source_ref in FETCH_EVENTS:
        fetch_metadata = dict(FETCH_EVENTS[source_ref])
    elif data is not None:
        for requested_url in collect_source_urls(source):
            event = FETCH_EVENTS.get(requested_url)
            if event and str(event.get("final_url", "")) == source_ref:
                fetch_metadata = dict(event)
                break

    content_sha256 = hashlib.sha256(data).hexdigest() if data is not None else ""
    byte_count = len(data) if data is not None else 0
    provenance: dict[str, Any] = {
        "source_id": source_id,
        "type": str(source.get("type", "")),
        "configured_source_sha256": configured_source_digest(source),
        "authority": str(source.get("authority", "unspecified")),
        "trust_tier": str(controls["trust_tier"]),
        "license": str(controls["license"]),
        "owner": str(controls["owner"]),
        "revision_strategy": str(controls["revision_strategy"]),
        "requested_refs": collect_source_urls(source)
        if str(source.get("type", "")) != "local_domain"
        else [str(source.get("path", ""))],
        "resolved_ref": source_ref,
        "content_sha256": content_sha256,
        "byte_count": byte_count,
        "used_cache": used_cache,
        "cache_mode": str(fetch_metadata.get("mode", "local" if data is not None else "aggregate")),
        "etag": str(fetch_metadata.get("etag", "")),
        "last_modified": str(fetch_metadata.get("last_modified", "")),
        "cache_age_seconds": fetch_metadata.get("cache_age_seconds"),
        "parser_stats": {
            "nonempty_line_count": nonempty_lines,
            "accepted_rule_count": len(rules),
            "accepted_line_ratio": round(accepted_ratio, 8),
            "rule_type_counts": rule_type_counts(rules),
        },
        "accepted_rules_merkle_root": register_source_rule_set(source_id, rules),
        "accepted_rules_merkle_leaf_count": len(rules),
        "limits": {
            "allowed_hosts": list(controls["allowed_hosts"]),
            "max_bytes": int(controls["max_bytes"]),
            "max_files": int(controls["max_files"]),
            "max_include_depth": int(controls["max_include_depth"]),
            "freshness_ttl_hours": float(controls["freshness_ttl_hours"]),
        },
        "critical": bool(controls["critical"]),
        "no_cache_publish": bool(controls["no_cache_publish"]),
    }
    if extra_provenance:
        provenance.update(extra_provenance)
        if not content_sha256 and extra_provenance.get("archive_sha256"):
            provenance["content_sha256"] = str(extra_provenance["archive_sha256"])
            provenance["byte_count"] = int(extra_provenance.get("archive_bytes", 0))
        included_lines = sum(
            int(item.get("nonempty_line_count", 0))
            for item in extra_provenance.get("files", [])
            if isinstance(item, dict)
        )
        if included_lines:
            provenance["parser_stats"]["nonempty_line_count"] = included_lines
            provenance["parser_stats"]["accepted_line_ratio"] = round(
                min(1.0, len(rules) / included_lines),
                8,
            )

    SOURCE_PROVENANCE.append(provenance)
    return SourceBuildResult(rules, used_cache, source_ref, provenance)


def load_source(
    source: dict[str, Any],
    root_dir: pathlib.Path,
    cache_dir: pathlib.Path,
    offline: bool,
    *,
    source_id: str,
) -> SourceBuildResult:
    source_type = str(source.get("type", "")).strip()
    if not source_type:
        raise BuildError("source missing 'type'")
    controls = source_controls(source)

    if source_type == "local_domain":
        source_path = pathlib.Path(str(source["path"]))
        path = root_dir / source_path
        if not path.exists():
            raise BuildError(f"local file not found: {path}")
        data = path.read_bytes()
        if len(data) > int(controls["max_bytes"]):
            raise BuildError(f"local source exceeds max_bytes: {path}")
        text = decode_text(data)
        rules = parse_local_domain_text(text)
        return finalize_source_result(
            source=source,
            source_id=source_id,
            controls=controls,
            rules=rules,
            used_cache=False,
            source_ref=source_path.as_posix(),
            data=data,
            text=text,
        )

    if source_type == "v2fly_dlc":
        lock_entry = v2fly_lock_entry()
        if lock_entry is None and bool(controls.get("require_lock", False)):
            raise BuildError(
                f"source {source_id} requires a resolved v2fly source lock"
            )
        include_attrs = {str(item).strip() for item in source.get("include_attrs", []) if str(item).strip()}
        exclude_attrs = {str(item).strip() for item in source.get("exclude_attrs", []) if str(item).strip()}
        exclude_includes = {
            str(item).strip() for item in source.get("exclude_includes", []) if str(item).strip()
        }
        rules, used_cache_only, resolved_source_ref = parse_v2fly_dlc_source(
            collect_source_urls(source),
            cache_dir=cache_dir,
            offline=offline,
            include_attrs=include_attrs,
            exclude_attrs=exclude_attrs,
            exclude_includes=exclude_includes,
            source_id=source_id,
            lock_entry=lock_entry,
            controls=controls,
        )
        return finalize_source_result(
            source=source,
            source_id=source_id,
            controls=controls,
            rules=rules,
            used_cache=used_cache_only,
            source_ref=resolved_source_ref,
            data=None,
            text=None,
            extra_provenance=V2FLY_PARSE_PROVENANCE.get(source_id, {}),
        )

    controlled_source = apply_source_controls(source, controls)
    data, used_cache, source_ref = fetch_source_bytes(controlled_source, cache_dir, offline)
    text = decode_text(data)

    if source_type == "adblock":
        rules = parse_adblock_text(text)
    elif source_type == "plain_cidr":
        rules = parse_plain_cidr_text(text)
    elif source_type == "csv_cidr_first_column":
        rules = parse_cidr_csv_first_column(text)
    elif source_type == "telegram_cidr":
        rules = parse_telegram_cidr_text(text)
    elif source_type == "apnic_country_cidr":
        country = str(source.get("country", "")).strip()
        if not country:
            raise BuildError(f"source type {source_type} requires 'country'")
        rules = parse_apnic_country_cidr(text, country)
    elif source_type == "iana_special_csv":
        rules = parse_iana_special_csv(text)
    elif source_type == "aws_ip_ranges":
        services = [str(item) for item in source.get("services", [])]
        rules = parse_aws_ip_ranges(data, services)
    elif source_type == "gcp_ip_ranges":
        rules = parse_gcp_ip_ranges(data)
    elif source_type == "fastly_public_ip_list":
        rules = parse_fastly_public_ip_list(data)
    elif source_type == "iana_tld_list":
        exclude_tlds = {str(item).strip().lower() for item in source.get("exclude_tlds", []) if str(item).strip()}
        rules = parse_iana_tld_list_text(text, exclude_tlds)
    else:
        raise BuildError(f"unsupported source type: {source_type}")

    return finalize_source_result(
        source=source,
        source_id=source_id,
        controls=controls,
        rules=rules,
        used_cache=used_cache,
        source_ref=source_ref,
        data=data,
        text=text,
    )


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


def filter_surge_compatible_rules(rules: list[str]) -> list[str]:
    # Surge external rulesets currently reject DOMAIN-REGEX lines. Keep the
    # canonical rules for OpenClash, but strip regex lines from Surge/List outputs.
    return [rule for rule in rules if not rule.startswith("DOMAIN-REGEX,")]


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


def split_stash_rules(rules: list[str]) -> tuple[list[str], list[str], list[str]]:
    classical_rules: list[str] = []
    ipcidr_payloads: list[str] = []
    domain_lines: list[str] = []

    for rule in rules:
        if rule.startswith(("IP-CIDR,", "IP-CIDR6,")):
            parts = rule.split(",", 2)
            if len(parts) >= 2:
                ipcidr_payloads.append(parts[1])
            continue

        if rule.startswith("DOMAIN,"):
            domain_lines.append(rule.split(",", 1)[1])
            continue

        if rule.startswith("DOMAIN-SUFFIX,"):
            domain_lines.append(f"+.{rule.split(',', 1)[1]}")
            continue

        classical_rules.append(rule)

    return classical_rules, ipcidr_payloads, domain_lines


def write_plain_lines(path: pathlib.Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(lines)
    if content:
        content += "\n"
    path.write_text(content, encoding="utf-8")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def format_repo_path(path: pathlib.Path | None) -> str | None:
    if path is None:
        return None
    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)


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


def load_ignored_conflict_sets(
    config: dict[str, Any],
    policy_map: dict[str, dict[str, Any]],
) -> dict[frozenset[str], dict[str, str]]:
    ignored: dict[frozenset[str], dict[str, str]] = {}
    raw = config.get("ignore_conflicts", [])
    if raw is None:
        return ignored
    if not isinstance(raw, list):
        raise BuildError("config: 'ignore_conflicts' must be a list of override objects")

    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            raise BuildError(
                f"config: ignore_conflicts[{idx}] must be an override object "
                "with categories, reason, owner, and expires_at"
            )
        categories_raw = item.get("categories", [])
        if not isinstance(categories_raw, list):
            raise BuildError(f"config: ignore_conflicts[{idx}].categories must be an array")
        categories = {str(x).strip() for x in categories_raw if str(x).strip()}
        if len(categories) < 2:
            continue
        for field_name in ("reason", "owner", "expires_at"):
            if not str(item.get(field_name, "")).strip():
                raise BuildError(
                    f"config: ignore_conflicts[{idx}] missing '{field_name}'"
                )
        try:
            expires_at = dt.date.fromisoformat(str(item["expires_at"]))
        except ValueError as exc:
            raise BuildError(
                f"config: ignore_conflicts[{idx}].expires_at must be YYYY-MM-DD"
            ) from exc
        if expires_at < dt.datetime.now(dt.timezone.utc).date():
            raise BuildError(
                f"config: ignore_conflicts[{idx}] expired on {expires_at.isoformat()}"
            )
        action_families = {
            action_family(policy_map.get(category_id, {}).get("action", "UNSPECIFIED"))
            for category_id in categories
        }
        if len(action_families) > 1:
            raise BuildError(
                "config: cross-action conflicts require rule-scoped overrides: "
                + ", ".join(sorted(categories))
            )
        ignored[frozenset(categories)] = {
            "scope": "category",
            "reason": str(item["reason"]).strip(),
            "owner": str(item["owner"]).strip(),
            "expires_at": str(item["expires_at"]).strip(),
        }
    return ignored


def load_ignored_rule_conflicts(
    config: dict[str, Any],
) -> dict[str, dict[frozenset[str], dict[str, str]]]:
    raw = config.get("ignore_conflicts_by_rule", [])
    if raw is None:
        return {}
    if not isinstance(raw, list):
        raise BuildError("config: 'ignore_conflicts_by_rule' must be a list")

    ignored: dict[str, dict[frozenset[str], dict[str, str]]] = defaultdict(dict)
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            raise BuildError(f"config: ignore_conflicts_by_rule[{idx}] must be an object")

        rule = str(item.get("rule", "")).strip()
        if not rule:
            raise BuildError(f"config: ignore_conflicts_by_rule[{idx}] missing 'rule'")
        for field_name in ("reason", "owner", "expires_at"):
            if not str(item.get(field_name, "")).strip():
                raise BuildError(
                    f"config: ignore_conflicts_by_rule[{idx}] missing '{field_name}'"
                )
        try:
            expires_at = dt.date.fromisoformat(str(item["expires_at"]))
        except ValueError as exc:
            raise BuildError(
                f"config: ignore_conflicts_by_rule[{idx}].expires_at must be YYYY-MM-DD"
            ) from exc
        if expires_at < dt.datetime.now(dt.timezone.utc).date():
            raise BuildError(
                f"config: ignore_conflicts_by_rule[{idx}] expired on {expires_at.isoformat()}"
            )

        categories_raw = item.get("categories", [])
        if not isinstance(categories_raw, list):
            raise BuildError(f"config: ignore_conflicts_by_rule[{idx}].categories must be an array")
        categories = {str(x).strip() for x in categories_raw if str(x).strip()}
        if len(categories) < 2:
            continue

        ignored[rule][frozenset(categories)] = {
            "scope": "rule",
            "reason": str(item["reason"]).strip(),
            "owner": str(item["owner"]).strip(),
            "expires_at": str(item["expires_at"]).strip(),
        }
        covering_rule = str(item.get("covering_rule", "")).strip()
        if covering_rule:
            ignored[rule][frozenset(categories)]["covering_rule"] = covering_rule
    return ignored


def canonical_conflict_categories(
    category_ids: set[str],
    category_actions: dict[str, str],
) -> set[str]:
    """Remove aggregate/overlay noise while retaining concrete conflicts."""
    category_set = set(category_ids)
    overlay_categories = {"gfw", "global", "tld_proxy"}

    # direct is an aggregate convenience set.  Prefer concrete DIRECT
    # categories when they are present, but retain direct when it is the only
    # DIRECT side of a real conflict (for example direct vs tiktok).
    if "direct" in category_set:
        has_explicit_direct = any(
            category_id != "direct"
            and category_actions.get(category_id, "UNSPECIFIED") == "DIRECT"
            for category_id in category_set
        )
        if has_explicit_direct:
            category_set.discard("direct")

    concrete = category_set - overlay_categories
    if len(concrete) >= 2:
        category_set = concrete
    elif category_set & overlay_categories:
        # One concrete category plus a broad proxy overlay is intentional and
        # does not provide enough information for an actionable conflict.
        return concrete

    return category_set


def classify_action_conflict(actions: dict[str, str]) -> tuple[str, str]:
    families = {action_family(action) for action in actions.values()}
    if len(families) <= 1:
        return "same_action_overlap", "low"
    if "DIRECT" in families and "REJECT" in families:
        return "direct_reject_conflict", "high"
    if "DIRECT" in families and "PROXY" in families:
        return "direct_proxy_conflict", "high"
    if "PROXY" in families and "REJECT" in families:
        return "proxy_reject_conflict", "medium"
    return "cross_action_conflict", "medium"


def build_conflict_record(
    *,
    rule: str,
    category_set: set[str],
    category_actions: dict[str, str],
    category_priorities: dict[str, int],
    conflict_type: str | None = None,
    severity: str | None = None,
    gated: bool = True,
    covering_rule: str | None = None,
) -> dict[str, Any]:
    actions = {category_id: category_actions.get(category_id, "UNSPECIFIED") for category_id in category_set}
    default_type, default_severity = classify_action_conflict(actions)
    record: dict[str, Any] = {
        "rule": rule,
        "categories": sorted(category_set),
        "actions": [
            {
                "category": category_id,
                "action": actions[category_id],
                "action_family": action_family(actions[category_id]),
                "priority": category_priorities.get(category_id, 9999),
            }
            for category_id in sorted(category_set)
        ],
        "type": conflict_type or default_type,
        "severity": severity or default_severity,
        "gated": gated,
    }
    if covering_rule is not None:
        record["covering_rule"] = covering_rule
    return record


def detect_rule_conflicts(
    rules_by_category: dict[str, list[str]],
    category_actions: dict[str, str],
    category_priorities: dict[str, int],
    ignored_conflict_sets: (
        set[frozenset[str]] | dict[frozenset[str], dict[str, str]]
    ),
    ignored_rule_conflicts: (
        dict[str, set[frozenset[str]]]
        | dict[str, dict[frozenset[str], dict[str, str]]]
    ),
) -> list[dict[str, Any]]:
    rule_index: dict[str, set[str]] = defaultdict(set)
    for category_id, rules in rules_by_category.items():
        for rule in rules:
            rule_index[rule].add(category_id)

    conflicts: list[dict[str, Any]] = []

    def waiver_for(
        rule: str,
        category_set: set[str],
        other_rule: str | None = None,
    ) -> dict[str, str] | None:
        frozen_set = frozenset(category_set)
        if frozen_set in ignored_conflict_sets:
            if isinstance(ignored_conflict_sets, dict):
                return dict(ignored_conflict_sets[frozen_set])
            return {"scope": "category"}
        rule_waivers = ignored_rule_conflicts.get(rule, {})
        if frozen_set in rule_waivers:
            if isinstance(rule_waivers, dict):
                waiver = dict(rule_waivers[frozen_set])
            else:
                waiver = {"scope": "rule"}
            configured_covering = str(waiver.get("covering_rule", "")).strip()
            if other_rule is None and not configured_covering:
                return waiver
            if other_rule is not None and configured_covering == other_rule:
                return waiver
        return None

    def apply_waiver(
        record: dict[str, Any],
        waiver: dict[str, str] | None,
    ) -> dict[str, Any]:
        if waiver is None:
            record["waived"] = False
            return record
        record["waived"] = True
        record["original_gated"] = bool(record.get("gated", True))
        record["gated"] = False
        record["waiver"] = waiver
        return record

    # Exact duplicates remain useful even when they are same-action; unlike
    # the old implementation, reject and overlay presence does not erase a
    # concrete conflict between the remaining categories.
    for rule, category_ids in rule_index.items():
        category_set = canonical_conflict_categories(category_ids, category_actions)
        if len(category_set) <= 1:
            continue
        waiver = waiver_for(rule, category_set)
        conflict_type, _severity = classify_action_conflict(
            {category_id: category_actions.get(category_id, "UNSPECIFIED") for category_id in category_set}
        )
        earliest_priority = min(category_priorities.get(category_id, 9999) for category_id in category_set)
        earliest_families = {
            action_family(category_actions.get(category_id, "UNSPECIFIED"))
            for category_id in category_set
            if category_priorities.get(category_id, 9999) == earliest_priority
        }
        gated = conflict_type != "same_action_overlap" and earliest_families != {"REJECT"}
        conflicts.append(
            apply_waiver(
                build_conflict_record(
                rule=rule,
                category_set=category_set,
                category_actions=category_actions,
                category_priorities=category_priorities,
                conflict_type=(
                    f"expected_reject_override_{conflict_type}"
                    if conflict_type != "same_action_overlap" and not gated
                    else conflict_type
                ),
                severity="low" if conflict_type != "same_action_overlap" and not gated else None,
                gated=gated,
                ),
                waiver,
            )
        )

    # DOMAIN-SUFFIX parents also overlap more-specific DOMAIN/SUFFIX rules.
    # Report all cross-action overlaps, but gate only when the earlier rule is
    # the broader parent.  A more-specific early rule overriding a later broad
    # category is a normal exception pattern and remains informational.
    suffix_index: dict[str, set[str]] = defaultdict(set)
    domain_entries: list[tuple[str, str, set[str]]] = []
    for rule, category_ids in rule_index.items():
        if rule.startswith("DOMAIN-SUFFIX,"):
            domain = rule.split(",", 1)[1]
            suffix_index[domain].update(category_ids)
            domain_entries.append((rule, domain, category_ids))
        elif rule.startswith("DOMAIN,"):
            domain_entries.append((rule, rule.split(",", 1)[1], category_ids))

    seen_hierarchy: set[tuple[str, str, frozenset[str]]] = set()
    for child_rule, child_domain, child_categories in domain_entries:
        labels = child_domain.split(".")
        for index in range(1, len(labels)):
            parent_domain = ".".join(labels[index:])
            parent_categories = suffix_index.get(parent_domain)
            if not parent_categories:
                continue
            parent_rule = f"DOMAIN-SUFFIX,{parent_domain}"
            if parent_rule == child_rule:
                continue

            for parent_category in parent_categories:
                for child_category in child_categories:
                    if parent_category == child_category:
                        continue
                    category_set = canonical_conflict_categories(
                        {parent_category, child_category}, category_actions
                    )
                    if len(category_set) <= 1:
                        continue
                    waiver = waiver_for(child_rule, category_set, parent_rule)
                    actions = {
                        category_id: category_actions.get(category_id, "UNSPECIFIED")
                        for category_id in category_set
                    }
                    base_type, base_severity = classify_action_conflict(actions)
                    if base_type == "same_action_overlap":
                        continue

                    key = (parent_rule, child_rule, frozenset(category_set))
                    if key in seen_hierarchy:
                        continue
                    seen_hierarchy.add(key)

                    parent_order = (
                        category_priorities.get(parent_category, 9999),
                        parent_category,
                    )
                    child_order = (
                        category_priorities.get(child_category, 9999),
                        child_category,
                    )
                    parent_shadows_child = parent_order < child_order
                    parent_family = action_family(
                        category_actions.get(parent_category, "UNSPECIFIED")
                    )
                    expected_reject_override = parent_shadows_child and parent_family == "REJECT"
                    if expected_reject_override:
                        conflict_type = f"expected_reject_override_{base_type}"
                        severity = "low"
                    elif parent_shadows_child:
                        conflict_type = f"parent_{base_type}"
                        severity = base_severity
                    else:
                        conflict_type = f"specific_override_{base_type}"
                        severity = "low"

                    conflicts.append(
                        apply_waiver(
                            build_conflict_record(
                            rule=child_rule,
                            covering_rule=parent_rule,
                            category_set=category_set,
                            category_actions=category_actions,
                            category_priorities=category_priorities,
                            conflict_type=conflict_type,
                            severity=severity,
                            gated=parent_shadows_child and not expected_reject_override,
                            ),
                            waiver,
                        )
                    )

    # CIDR parents can shadow more-specific ranges in the same way as domain
    # suffix parents. Use a prefix index so the check stays bounded for large
    # country-IP datasets.
    cidr_index: dict[tuple[int, int, int], tuple[str, set[str]]] = {}
    cidr_entries: list[
        tuple[
            str,
            ipaddress.IPv4Network | ipaddress.IPv6Network,
            set[str],
        ]
    ] = []
    present_prefixes: dict[int, set[int]] = defaultdict(set)
    for rule, category_ids in rule_index.items():
        if not rule.startswith(("IP-CIDR,", "IP-CIDR6,")):
            continue
        parts = rule.split(",", 2)
        if len(parts) < 2:
            continue
        try:
            network = ipaddress.ip_network(parts[1], strict=False)
        except ValueError:
            continue
        key = (network.version, network.prefixlen, int(network.network_address))
        cidr_index[key] = (rule, category_ids)
        cidr_entries.append((rule, network, category_ids))
        present_prefixes[network.version].add(network.prefixlen)

    seen_cidr_hierarchy: set[tuple[str, str, frozenset[str]]] = set()
    for child_rule, child_network, child_categories in cidr_entries:
        for prefixlen in sorted(
            value
            for value in present_prefixes[child_network.version]
            if value < child_network.prefixlen
        ):
            parent_network = ipaddress.ip_network(
                (child_network.network_address, prefixlen),
                strict=False,
            )
            parent_hit = cidr_index.get(
                (
                    parent_network.version,
                    parent_network.prefixlen,
                    int(parent_network.network_address),
                )
            )
            if parent_hit is None:
                continue
            parent_rule, parent_categories = parent_hit
            for parent_category in parent_categories:
                for child_category in child_categories:
                    if parent_category == child_category:
                        continue
                    category_set = canonical_conflict_categories(
                        {parent_category, child_category},
                        category_actions,
                    )
                    if len(category_set) <= 1:
                        continue
                    waiver = waiver_for(child_rule, category_set, parent_rule)
                    actions = {
                        category_id: category_actions.get(category_id, "UNSPECIFIED")
                        for category_id in category_set
                    }
                    base_type, base_severity = classify_action_conflict(actions)
                    if base_type == "same_action_overlap":
                        continue
                    key = (parent_rule, child_rule, frozenset(category_set))
                    if key in seen_cidr_hierarchy:
                        continue
                    seen_cidr_hierarchy.add(key)

                    parent_order = (
                        category_priorities.get(parent_category, 9999),
                        parent_category,
                    )
                    child_order = (
                        category_priorities.get(child_category, 9999),
                        child_category,
                    )
                    parent_shadows_child = parent_order < child_order
                    parent_family = action_family(
                        category_actions.get(parent_category, "UNSPECIFIED")
                    )
                    expected_reject_override = (
                        parent_shadows_child and parent_family == "REJECT"
                    )
                    if expected_reject_override:
                        conflict_type = f"expected_reject_override_cidr_{base_type}"
                        severity = "low"
                    elif parent_shadows_child:
                        conflict_type = f"parent_cidr_{base_type}"
                        severity = base_severity
                    else:
                        conflict_type = f"specific_override_cidr_{base_type}"
                        severity = "low"
                    conflicts.append(
                        apply_waiver(
                            build_conflict_record(
                            rule=child_rule,
                            covering_rule=parent_rule,
                            category_set=category_set,
                            category_actions=category_actions,
                            category_priorities=category_priorities,
                            conflict_type=conflict_type,
                            severity=severity,
                            gated=parent_shadows_child and not expected_reject_override,
                            ),
                            waiver,
                        )
                    )

    severity_weight = {"high": 0, "medium": 1, "low": 2}
    conflicts.sort(
        key=lambda item: (
            not bool(item.get("gated", True)),
            severity_weight.get(str(item.get("severity", "low")), 3),
            len(item["categories"]) * -1,
            str(item.get("covering_rule", "")),
            item["rule"],
        )
    )
    return conflicts


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


def render_rule_catalog_markdown(categories: list[dict[str, Any]]) -> str:
    lines = [
        "# Ruleset Catalog",
        "",
        "Use with base URL:",
        "`https://raw.githubusercontent.com/<owner>/<repo>/main/ruleset/dist`",
        "",
        "| Category | Action | Priority | Rules | OpenClash (YAML) | Surge | Compat (txt/conf) | Note |",
        "|---|---|---:|---:|---|---|---|---|",
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

        openclash_paths = "<br>".join(
            [
                f"`openclash/{category_id}.yaml`",
                f"`openclash/non_ip/{category_id}.yaml`",
                f"`openclash/ip/{category_id}.yaml`",
            ]
        )
        surge_paths = "<br>".join(
            [
                f"`surge/{category_id}.list`",
                f"`surge/non_ip/{category_id}.list`",
                f"`surge/ip/{category_id}.list`",
                f"`surge/domainset/{category_id}.conf`",
            ]
        )
        compat_paths = "<br>".join(
            [
                f"`compat/Clash/non_ip/{category_id}.txt`",
                f"`compat/Clash/ip/{category_id}.txt`",
                f"`compat/Clash/domainset/{category_id}.txt`",
                f"`compat/List/non_ip/{category_id}.conf`",
                f"`compat/List/ip/{category_id}.conf`",
                f"`compat/List/domainset/{category_id}.conf`",
            ]
        )
        lines.append(
            f"| `{category_id}` | `{action}` | {priority} | {rules} | {openclash_paths} | {surge_paths} | {compat_paths} | {note} |"
        )

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
) -> tuple[list[str], list[dict[str, Any]], dict[str, set[str]]]:
    category_id = str(category.get("id", "")).strip()
    if not category_id:
        raise BuildError("category missing 'id'")

    sources = category.get("sources", [])
    if not isinstance(sources, list) or not sources:
        raise BuildError(f"category {category_id} has no sources")

    rules: set[str] = set()
    source_meta: list[dict[str, Any]] = []
    attribution: dict[str, set[str]] = defaultdict(set)

    for source_index, source in enumerate(sources):
        if not isinstance(source, dict):
            raise BuildError(f"category {category_id}: sources[{source_index}] must be an object")
        source_id = make_source_id(category_id, source_index, source)
        result = load_source(
            source,
            root_dir,
            cache_dir,
            offline,
            source_id=source_id,
        )
        rules.update(result.rules)
        for rule in result.rules:
            attribution[rule].add(source_id)
        source_meta.append(
            {
                "source_id": source_id,
                "type": source["type"],
                "authority": source.get("authority", "unspecified"),
                "trust_tier": result.provenance.get("trust_tier", "unknown"),
                "ref": result.source_ref,
                "resolved_revision": result.provenance.get("resolved_revision"),
                "content_sha256": result.provenance.get("content_sha256", ""),
                "used_cache": result.used_cache,
                "rule_count": len(result.rules),
            }
        )

    exclude_path = category.get("exclude_rules_path")
    if exclude_path:
        exclusion_file = root_dir / str(exclude_path)
        if not exclusion_file.is_file():
            raise BuildError(f"{category_id}: declared exclusion file missing: {exclusion_file}")
        exclude_rules = parse_local_domain_text(exclusion_file.read_text(encoding="utf-8"))
        before_count = len(rules)
        rules.difference_update(exclude_rules)
        removed = before_count - len(rules)
        if removed > 0:
            log(f"{category_id}: removed {removed} rules from exclusion file")

    allow_path = category.get("allow_rules_path")
    if allow_path:
        allow_file = root_dir / str(allow_path)
        if not allow_file.is_file():
            raise BuildError(f"{category_id}: declared allowlist file missing: {allow_file}")
        allow_rules = parse_local_domain_text(allow_file.read_text(encoding="utf-8"))
        before_count = len(rules)
        rules.difference_update(allow_rules)
        removed = before_count - len(rules)
        if removed > 0:
            log(f"{category_id}: removed {removed} rules from allowlist file")

    sorted_rules = sorted(rules, key=rule_sort_key)
    filtered_attribution = {
        rule: set(attribution.get(rule, set()))
        for rule in sorted_rules
    }
    return sorted_rules, source_meta, filtered_attribution


def build_aggregate_category(
    category: dict[str, Any],
    root_dir: pathlib.Path,
    cache_dir: pathlib.Path,
    offline: bool,
    rules_by_category: dict[str, list[str]],
    attribution_by_category: dict[str, dict[str, set[str]]],
) -> tuple[list[str], list[dict[str, Any]], dict[str, set[str]]]:
    category_id = str(category.get("id", "")).strip()
    raw_components = category.get("aggregate_of", [])
    if not isinstance(raw_components, list) or not raw_components:
        raise BuildError(f"aggregate category {category_id} requires aggregate_of")
    components = [str(item).strip() for item in raw_components if str(item).strip()]
    if len(components) != len(set(components)):
        raise BuildError(f"aggregate category {category_id} has duplicate components")
    missing = [item for item in components if item not in rules_by_category]
    if missing:
        raise BuildError(
            f"aggregate category {category_id} references categories not built earlier: "
            + ", ".join(missing)
        )
    if category.get("sources"):
        raise BuildError(
            f"aggregate category {category_id} must not duplicate component sources"
        )

    rules: set[str] = set()
    attribution: dict[str, set[str]] = defaultdict(set)
    for component in components:
        rules.update(rules_by_category[component])
        for rule, source_ids in attribution_by_category[component].items():
            attribution[rule].update(source_ids)

    source_meta: list[dict[str, Any]] = [
        {
            "source_id": f"{category_id}:aggregate:{component}",
            "type": "aggregate",
            "authority": "owner-controlled",
            "trust_tier": "derived",
            "ref": component,
            "resolved_revision": None,
            "content_sha256": "",
            "used_cache": False,
            "rule_count": len(rules_by_category[component]),
        }
        for component in components
    ]

    overlay_path = category.get("manual_overlay_path")
    if overlay_path:
        overlay_source = {
            "type": "local_domain",
            "path": str(overlay_path),
            "authority": "owner-controlled",
        }
        overlay_id = f"{category_id}:manual-overlay"
        overlay_result = load_source(
            overlay_source,
            root_dir,
            cache_dir,
            offline,
            source_id=overlay_id,
        )
        rules.update(overlay_result.rules)
        for rule in overlay_result.rules:
            attribution[rule].add(overlay_id)
        source_meta.append(
            {
                "source_id": overlay_id,
                "type": "local_domain",
                "authority": "owner-controlled",
                "trust_tier": overlay_result.provenance.get("trust_tier", "owner"),
                "ref": overlay_result.source_ref,
                "resolved_revision": None,
                "content_sha256": overlay_result.provenance.get("content_sha256", ""),
                "used_cache": False,
                "rule_count": len(overlay_result.rules),
            }
        )

    for field_name, label in (
        ("exclude_rules_path", "exclusion"),
        ("allow_rules_path", "allowlist"),
    ):
        raw_path = category.get(field_name)
        if not raw_path:
            continue
        path = root_dir / str(raw_path)
        if not path.is_file():
            raise BuildError(f"{category_id}: declared {label} file missing: {path}")
        removed_rules = parse_local_domain_text(path.read_text(encoding="utf-8"))
        before_count = len(rules)
        rules.difference_update(removed_rules)
        removed = before_count - len(rules)
        if removed:
            log(f"{category_id}: removed {removed} rules from {label} file")

    sorted_rules = sorted(rules, key=rule_sort_key)
    filtered_attribution = {
        rule: set(attribution.get(rule, set()))
        for rule in sorted_rules
    }
    SOURCE_PROVENANCE.append(
        {
            "source_id": f"{category_id}:aggregate",
            "type": "aggregate",
            "configured_source_sha256": configured_source_digest(
                {
                    "type": "aggregate",
                    "category": category_id,
                    "aggregate_of": components,
                }
            ),
            "authority": "owner-controlled",
            "trust_tier": "derived",
            "license": "inherits-components",
            "owner": "crescentln",
            "revision_strategy": "derived-from-locked-components",
            "requested_refs": components,
            "resolved_ref": category_id,
            "content_sha256": hashlib.sha256(
                "\n".join(sorted_rules).encode("utf-8")
            ).hexdigest(),
            "byte_count": sum(len(rule.encode("utf-8")) + 1 for rule in sorted_rules),
            "used_cache": any(bool(item.get("used_cache")) for item in source_meta),
            "cache_mode": "aggregate",
            "parser_stats": {
                "accepted_rule_count": len(sorted_rules),
                "rule_type_counts": rule_type_counts(set(sorted_rules)),
            },
            "accepted_rules_merkle_root": register_source_rule_set(
                f"{category_id}:aggregate", set(sorted_rules)
            ),
            "accepted_rules_merkle_leaf_count": len(sorted_rules),
            "components": components,
            "critical": True,
            "no_cache_publish": True,
        }
    )
    return sorted_rules, source_meta, filtered_attribution


def resolve_category_contract(
    category_id: str,
    action: str,
    category: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    defaults = config.get("defaults", {})
    action_profiles = config.get("action_profiles", {})
    category_overrides = config.get("categories", {})
    if not isinstance(defaults, dict):
        raise BuildError("category contracts: defaults must be an object")
    if not isinstance(action_profiles, dict):
        raise BuildError("category contracts: action_profiles must be an object")
    if not isinstance(category_overrides, dict):
        raise BuildError("category contracts: categories must be an object")

    contract = dict(defaults)
    action_profile = action_profiles.get(action_family(action), {})
    if not isinstance(action_profile, dict):
        raise BuildError(
            f"category contracts: action profile '{action_family(action)}' must be an object"
        )
    contract.update(action_profile)
    override = category_overrides.get(category_id, {})
    if not isinstance(override, dict):
        raise BuildError(f"category contracts: category '{category_id}' must be an object")
    contract.update(override)
    if category.get("aggregate_of"):
        aggregate_of = [str(item).strip() for item in category["aggregate_of"] if str(item).strip()]
        configured_aggregate = contract.get("aggregate_of")
        if configured_aggregate is not None and list(configured_aggregate) != aggregate_of:
            raise BuildError(
                f"category contract aggregate_of mismatch for '{category_id}'"
            )
        contract["aggregate_of"] = aggregate_of
    contract["category"] = category_id
    contract["action"] = action
    return contract


def validate_category_contract(
    category_id: str,
    rules: list[str],
    action: str,
    priority: int,
    contract: dict[str, Any],
    policy_map: dict[str, dict[str, Any]],
    source_meta: list[dict[str, Any]],
) -> None:
    required_budgets = (
        "max_add",
        "max_remove",
        "max_pct",
        "max_new_apex",
        "max_new_regex",
        "max_new_cidr",
        "max_informational_overlap_delta",
    )
    for field_name in required_budgets:
        try:
            value = float(contract[field_name])
        except (KeyError, TypeError, ValueError) as exc:
            raise BuildError(
                f"category contract '{category_id}' requires numeric {field_name}"
            ) from exc
        if value < 0:
            raise BuildError(
                f"category contract '{category_id}' has negative {field_name}"
            )

    allowed_rule_types_raw = contract.get("allowed_rule_types", [])
    allowed_source_tiers_raw = contract.get("allowed_source_tiers", [])
    if not isinstance(allowed_rule_types_raw, list) or not allowed_rule_types_raw:
        raise BuildError(
            f"category contract '{category_id}' requires allowed_rule_types"
        )
    if not isinstance(allowed_source_tiers_raw, list) or not allowed_source_tiers_raw:
        raise BuildError(
            f"category contract '{category_id}' requires allowed_source_tiers"
        )
    allowed_rule_types = {
        str(item).strip().upper()
        for item in allowed_rule_types_raw
        if str(item).strip()
    }
    observed_rule_types = set(rule_type_counts(set(rules)))
    forbidden_rule_types = observed_rule_types - allowed_rule_types
    if forbidden_rule_types:
        raise BuildError(
            f"category '{category_id}' violates allowed_rule_types: "
            + ", ".join(sorted(forbidden_rule_types))
        )
    allowed_source_tiers = {
        str(item).strip()
        for item in allowed_source_tiers_raw
        if str(item).strip()
    }
    observed_source_tiers = {
        str(item.get("trust_tier", "")).strip()
        for item in source_meta
        if str(item.get("trust_tier", "")).strip()
    }
    forbidden_source_tiers = observed_source_tiers - allowed_source_tiers
    if forbidden_source_tiers:
        raise BuildError(
            f"category '{category_id}' violates allowed_source_tiers: "
            + ", ".join(sorted(forbidden_source_tiers))
        )

    required_action = contract.get("required_action")
    if required_action is not None:
        normalized_required_action = str(required_action).upper().strip()
        if normalized_required_action not in ALLOWED_ACTIONS - {"UNSPECIFIED"}:
            raise BuildError(
                f"category contract '{category_id}' has invalid required_action"
            )
        if action != normalized_required_action:
            raise BuildError(
                f"category '{category_id}' requires action "
                f"'{normalized_required_action}', got '{action}'"
            )

    aggregate_of = contract.get("aggregate_of")
    if aggregate_of is not None:
        if not isinstance(aggregate_of, list) or not aggregate_of:
            raise BuildError(
                f"category contract '{category_id}' aggregate_of must be a non-empty array"
            )
        for raw_component in aggregate_of:
            component = str(raw_component).strip()
            component_policy = policy_map.get(component)
            if not isinstance(component_policy, dict):
                raise BuildError(
                    f"aggregate category '{category_id}' references unknown component "
                    f"'{component}'"
                )
            component_action = str(
                component_policy.get("action", "UNSPECIFIED")
            ).upper().strip()
            if component_action != action:
                raise BuildError(
                    f"aggregate category '{category_id}' action '{action}' does not "
                    f"match component '{component}' action '{component_action}'"
                )

    promotion_policy = str(contract.get("auto_promotion_policy", "")).strip()
    if promotion_policy not in {"low-risk", "review", "manual"}:
        raise BuildError(
            f"category contract '{category_id}' has invalid auto_promotion_policy"
        )
    per_client_support = contract.get("per_client_support")
    if not isinstance(per_client_support, dict):
        raise BuildError(
            f"category contract '{category_id}' requires per_client_support"
        )
    for client in ("openclash", "surge", "stash"):
        if client not in per_client_support:
            raise BuildError(
                f"category contract '{category_id}' missing per_client_support.{client}"
            )
        client_contract = per_client_support[client]
        if not isinstance(client_contract, dict):
            raise BuildError(
                f"category contract '{category_id}' per_client_support.{client} "
                "must be an object"
            )
        supported_raw = client_contract.get("supported_rule_types", [])
        unsupported_raw = client_contract.get("unsupported_rule_types", [])
        if not isinstance(supported_raw, list) or not isinstance(
            unsupported_raw,
            list,
        ):
            raise BuildError(
                f"category contract '{category_id}' per_client_support.{client} "
                "rule-type fields must be arrays"
            )
        supported = {str(item).strip() for item in supported_raw if str(item).strip()}
        unsupported = {
            str(item).strip() for item in unsupported_raw if str(item).strip()
        }
        if not supported or supported & unsupported:
            raise BuildError(
                f"category contract '{category_id}' per_client_support.{client} "
                "has invalid supported/unsupported rule types"
            )
        for field_name in ("max_loss_count", "max_loss_pct"):
            try:
                value = float(client_contract[field_name])
            except (KeyError, TypeError, ValueError) as exc:
                raise BuildError(
                    f"category contract '{category_id}' "
                    f"per_client_support.{client}.{field_name} must be numeric"
                ) from exc
            if value < 0:
                raise BuildError(
                    f"category contract '{category_id}' "
                    f"per_client_support.{client}.{field_name} cannot be negative"
                )

    for relation_field, relation in (
        ("must_precede", "before"),
        ("must_follow", "after"),
    ):
        raw_targets = contract.get(relation_field, [])
        if raw_targets is None:
            raw_targets = []
        if not isinstance(raw_targets, list):
            raise BuildError(
                f"category contract '{category_id}' field {relation_field} must be an array"
            )
        for raw_target in raw_targets:
            target = str(raw_target).strip()
            if target not in policy_map:
                raise BuildError(
                    f"category contract '{category_id}' references unknown {relation} target '{target}'"
                )
            target_priority = int(policy_map[target].get("priority", 9999))
            if relation == "before" and priority >= target_priority:
                raise BuildError(
                    f"category '{category_id}' must precede '{target}'"
                )
            if relation == "after" and priority <= target_priority:
                raise BuildError(
                    f"category '{category_id}' must follow '{target}'"
                )

    if action_family(action) == "UNSPECIFIED":
        raise BuildError(f"category '{category_id}' must have an explicit action")


def read_openclash_rule_file(path: pathlib.Path) -> set[str]:
    if not path.is_file():
        return set()
    rules: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line == "payload:" or line == "payload: []" or line.startswith("#"):
            continue
        if not line.startswith("- "):
            continue
        value = line[2:].strip()
        if value.startswith("'") and value.endswith("'") and len(value) >= 2:
            value = value[1:-1].replace("''", "'")
        rules.add(value)
    return rules


def rules_semantically_overlap(left: str, right: str) -> bool:
    if left == right:
        return True
    left_type, _, left_value = left.partition(",")
    right_type, _, right_value = right.partition(",")
    left_value = left_value.split(",", 1)[0].strip()
    right_value = right_value.split(",", 1)[0].strip()
    domain_types = {"DOMAIN", "DOMAIN-SUFFIX"}
    if left_type in domain_types and right_type in domain_types:
        if left_type == "DOMAIN" and right_type == "DOMAIN":
            return False
        if left_type == "DOMAIN-SUFFIX" and right_type == "DOMAIN-SUFFIX":
            return (
                left_value.endswith(f".{right_value}")
                or right_value.endswith(f".{left_value}")
            )
        domain = left_value if left_type == "DOMAIN" else right_value
        suffix = left_value if left_type == "DOMAIN-SUFFIX" else right_value
        return domain == suffix or domain.endswith(f".{suffix}")
    if left_type.startswith("IP-CIDR") and right_type.startswith("IP-CIDR"):
        try:
            left_network = ipaddress.ip_network(left_value, strict=False)
            right_network = ipaddress.ip_network(right_value, strict=False)
        except ValueError:
            return False
        return (
            left_network.version == right_network.version
            and left_network.overlaps(right_network)
        )
    return False


def validate_disjoint_category_contracts(
    rules_by_category: dict[str, list[str]],
    resolved_contracts: dict[str, dict[str, Any]],
) -> None:
    for category_id, contract in resolved_contracts.items():
        raw_targets = contract.get("must_be_disjoint_from", [])
        if not isinstance(raw_targets, list):
            raise BuildError(
                f"category contract '{category_id}' must_be_disjoint_from "
                "must be an array"
            )
        for raw_target in raw_targets:
            target = str(raw_target).strip()
            if target not in rules_by_category:
                raise BuildError(
                    f"category contract '{category_id}' has unknown disjoint "
                    f"target '{target}'"
                )
            for left in rules_by_category.get(category_id, []):
                for right in rules_by_category[target]:
                    if rules_semantically_overlap(left, right):
                        raise BuildError(
                            f"category '{category_id}' must be disjoint from "
                            f"'{target}', but {left} overlaps {right}"
                        )


def domain_topology_risk_markers(value: str) -> set[str]:
    return psl_domain_topology_markers(
        value,
        PUBLIC_SUFFIX_DATABASE,
        PROTECTED_PUBLIC_SUFFIXES,
        PROTECTED_MULTI_TENANT_ROOTS,
    )


def rule_risk_markers(rule: str, action: str, *, added: bool) -> list[str]:
    markers: list[str] = []
    rule_type, _, value = rule.partition(",")
    rule_type = rule_type.upper()
    value = value.split(",", 1)[0].strip()
    family = action_family(action)
    if added and family in {"DIRECT", "REJECT"}:
        markers.append(f"{family.lower()}-addition")
    if rule_type in {"DOMAIN-REGEX", "DOMAIN-WILDCARD", "DOMAIN-KEYWORD"}:
        markers.append(f"new-{rule_type.lower()}")
    if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
        markers.extend(domain_topology_risk_markers(value))
    if rule_type in {"IP-CIDR", "IP-CIDR6"}:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            markers.append("invalid-cidr")
        else:
            if (network.version == 4 and network.prefixlen <= 16) or (
                network.version == 6 and network.prefixlen <= 48
            ):
                markers.append("new-wide-cidr")
    return sorted(set(markers))


def semantic_rules_digest(
    rules_by_category: dict[str, list[str]],
    category_actions: dict[str, str],
    category_priorities: dict[str, int],
) -> str:
    digest = hashlib.sha256()
    for category_id in sorted(rules_by_category):
        digest.update(
            (
                f"[{category_id}] action={category_actions.get(category_id, 'UNSPECIFIED')} "
                f"priority={category_priorities.get(category_id, 9999)}\n"
            ).encode("utf-8")
        )
        for rule in rules_by_category[category_id]:
            digest.update(rule.encode("utf-8"))
            digest.update(b"\n")
    return digest.hexdigest()


def count_budget_dimensions(rules: list[str]) -> dict[str, int]:
    return {
        "new_apex": sum(
            1
            for rule in rules
            if rule.startswith(("DOMAIN,", "DOMAIN-SUFFIX,"))
            and "new-apex"
            in domain_topology_risk_markers(rule.split(",", 1)[1])
        ),
        "new_regex": sum(
            1
            for rule in rules
            if rule.startswith(("DOMAIN-REGEX,", "DOMAIN-WILDCARD,", "DOMAIN-KEYWORD,"))
        ),
        "new_cidr": sum(
            1
            for rule in rules
            if rule.startswith(("IP-CIDR,", "IP-CIDR6,"))
        ),
    }


def build_allow_shadow_report(
    config: dict[str, Any],
    rules_by_category: dict[str, list[str]],
) -> dict[str, Any]:
    categories: list[dict[str, Any]] = []
    total_shadows = 0
    for category in config.get("categories", []):
        if not isinstance(category, dict):
            continue
        category_id = str(category.get("id", "")).strip()
        allow_rel = category.get("allow_rules_path")
        if not category_id or not allow_rel:
            continue
        allow_path = ROOT_DIR / str(allow_rel)
        if not allow_path.is_file():
            raise BuildError(f"{category_id}: declared allowlist file missing: {allow_path}")
        allow_rules = parse_local_domain_text(allow_path.read_text(encoding="utf-8"))
        allowed_suffixes = {
            rule.split(",", 1)[1]
            for rule in allow_rules
            if rule.startswith("DOMAIN-SUFFIX,")
        }
        allowed_networks: list[
            ipaddress.IPv4Network | ipaddress.IPv6Network
        ] = []
        for allow_rule in allow_rules:
            if not allow_rule.startswith(("IP-CIDR,", "IP-CIDR6,")):
                continue
            try:
                allowed_networks.append(
                    ipaddress.ip_network(
                        allow_rule.split(",", 2)[1],
                        strict=False,
                    )
                )
            except ValueError:
                continue
        shadows: list[dict[str, str]] = []
        for rule in rules_by_category.get(category_id, []):
            if rule.startswith(("DOMAIN,", "DOMAIN-SUFFIX,")):
                domain = rule.split(",", 1)[1]
                for allowed in sorted(allowed_suffixes):
                    if domain != allowed and domain.endswith(f".{allowed}"):
                        shadows.append(
                            {
                                "allow_root": f"DOMAIN-SUFFIX,{allowed}",
                                "remaining_rule": rule,
                                "relationship": "domain-descendant",
                            }
                        )
                        break
                continue
            if not rule.startswith(("IP-CIDR,", "IP-CIDR6,")):
                continue
            try:
                remaining_network = ipaddress.ip_network(
                    rule.split(",", 2)[1],
                    strict=False,
                )
            except ValueError:
                continue
            for allowed_network in allowed_networks:
                if (
                    remaining_network.version == allowed_network.version
                    and remaining_network != allowed_network
                    and remaining_network.subnet_of(allowed_network)
                ):
                    shadows.append(
                        {
                            "allow_root": format_ip_rule(allowed_network),
                            "remaining_rule": rule,
                            "relationship": "cidr-subnet",
                        }
                    )
                    break
        total_shadows += len(shadows)
        categories.append(
            {
                "category": category_id,
                "allow_rules_path": str(allow_rel),
                "exact_allow_rule_count": len(allow_rules),
                "semantic_shadow_count": len(shadows),
                "semantic_shadows": shadows,
            }
        )
    return {
        "generated_at_utc": BUILD_GENERATED_AT,
        "semantics": (
            "Exact-set allow removal is preserved. More-specific descendants are "
            "reported for evidence-based review and are not recursively allowed."
        ),
        "semantic_shadow_count": total_shadows,
        "categories": categories,
    }


def write_intelligence_outputs(
    *,
    dist_dir: pathlib.Path,
    baseline_dist_dir: pathlib.Path | None,
    config: dict[str, Any],
    rules_by_category: dict[str, list[str]],
    attribution_by_category: dict[str, dict[str, set[str]]],
    category_actions: dict[str, str],
    category_priorities: dict[str, int],
    resolved_contracts: dict[str, dict[str, Any]],
    metadata_categories: list[dict[str, Any]],
    fetch_report: dict[str, Any],
    conflicts_payload: dict[str, Any],
) -> None:
    source_lock_payload = SOURCE_LOCK or {
        "version": 1,
        "generated_at_utc": BUILD_GENERATED_AT,
        "repositories": {},
        "status": "unlocked",
    }
    (dist_dir / "sources.lock.json").write_text(
        json.dumps(source_lock_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    source_lock_digest = hashlib.sha256(
        json.dumps(
            {
                "version": source_lock_payload.get("version", 1),
                "repositories": source_lock_payload.get("repositories", {}),
            },
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()

    provenance_payload = {
        "generated_at_utc": BUILD_GENERATED_AT,
        "source_count": len(SOURCE_PROVENANCE),
        "source_lock_sha256": source_lock_digest,
        "sources": sorted(
            SOURCE_PROVENANCE,
            key=lambda item: str(item.get("source_id", "")),
        ),
    }
    (dist_dir / "source_provenance.json").write_text(
        json.dumps(provenance_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    cache_blocked_sources = sorted(
        str(item.get("source_id", ""))
        for item in SOURCE_PROVENANCE
        if item.get("used_cache") and item.get("no_cache_publish")
    )
    health_status = "healthy"
    if fetch_report.get("fallback_cache_count", 0) or cache_blocked_sources:
        health_status = "degraded"
    source_health = {
        "generated_at_utc": BUILD_GENERATED_AT,
        "status": health_status,
        "source_count": len(SOURCE_PROVENANCE),
        "network_success_count": int(fetch_report.get("network_success_count", 0)),
        "primary_success_count": int(fetch_report.get("primary_success_count", 0)),
        "mirror_success_count": int(fetch_report.get("mirror_success_count", 0)),
        "fallback_cache_count": int(fetch_report.get("fallback_cache_count", 0)),
        "cache_blocked_source_ids": cache_blocked_sources,
        "source_lock_sha256": source_lock_digest,
        "resolved_repositories": source_lock_payload.get("repositories", {}),
        "freshness_slo": {
            "discovery_max_age_hours": 26,
            "published_snapshot_max_age_hours": 192,
        },
    }
    (dist_dir / "source_health.json").write_text(
        json.dumps(source_health, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    client_rows: list[dict[str, Any]] = []
    for item in metadata_categories:
        client_rows.append(
            {
                "category": item["id"],
                "openclash": {
                    "effective_rule_count": item["openclash_rule_count"],
                    "lost_rule_count": 0,
                    "lost_rule_types": {},
                },
                "surge": {
                    "effective_rule_count": item["surge_rule_count"],
                    "lost_rule_count": item["surge_lost_rule_count"],
                    "lost_rule_types": item["surge_lost_rule_types"],
                },
                "stash": {
                    "effective_rule_count": item["stash_rule_count"],
                    "lost_rule_count": 0,
                    "lost_rule_types": {},
                },
                "contract": resolved_contracts[item["id"]].get("per_client_support", {}),
            }
        )
    client_parity = {
        "generated_at_utc": BUILD_GENERATED_AT,
        "category_count": len(client_rows),
        "clients": {
            "openclash_effective_rules": sum(
                int(row["openclash"]["effective_rule_count"]) for row in client_rows
            ),
            "surge_effective_rules": sum(
                int(row["surge"]["effective_rule_count"]) for row in client_rows
            ),
            "surge_lost_rules": sum(
                int(row["surge"]["lost_rule_count"]) for row in client_rows
            ),
            "stash_effective_rules": sum(
                int(row["stash"]["effective_rule_count"]) for row in client_rows
            ),
        },
        "categories": client_rows,
    }
    (dist_dir / "client_parity.json").write_text(
        json.dumps(client_parity, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (dist_dir / "category_contracts_resolved.json").write_text(
        json.dumps(
            {
                "generated_at_utc": BUILD_GENERATED_AT,
                "category_count": len(resolved_contracts),
                "categories": resolved_contracts,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (dist_dir / "allow_shadow.json").write_text(
        json.dumps(
            build_allow_shadow_report(config, rules_by_category),
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    baseline_available = bool(
        baseline_dist_dir is not None and baseline_dist_dir.is_dir()
    )
    baseline_actions: dict[str, str] = {}
    baseline_priorities: dict[str, int] = {}
    baseline_conflicts: dict[str, Any] = {}
    baseline_lock: dict[str, Any] = {}
    if baseline_available and baseline_dist_dir is not None:
        baseline_index_path = baseline_dist_dir / "index.json"
        if baseline_index_path.is_file():
            baseline_index = read_json(baseline_index_path)
            for row in baseline_index.get("categories", []):
                if not isinstance(row, dict):
                    continue
                cid = str(row.get("id", "")).strip()
                if not cid:
                    continue
                baseline_actions[cid] = str(
                    row.get("recommended_action", "UNSPECIFIED")
                )
                baseline_priorities[cid] = int(
                    row.get("recommended_priority", 9999)
                )
        baseline_conflicts_path = baseline_dist_dir / "conflicts.json"
        if baseline_conflicts_path.is_file():
            baseline_conflicts = read_json(baseline_conflicts_path)
        baseline_lock_path = baseline_dist_dir / "sources.lock.json"
        if baseline_lock_path.is_file():
            baseline_lock = read_json(baseline_lock_path)

    delta_categories: list[dict[str, Any]] = []
    risk_markers: set[str] = set()
    budget_exceeded: list[str] = []
    changed_category_ids: list[str] = []
    if baseline_available and baseline_dist_dir is not None:
        baseline_category_ids = set(baseline_actions)
        current_category_ids = set(rules_by_category)
        baseline_rule_sets = {
            category_id: read_openclash_rule_file(
                baseline_dist_dir / "openclash" / f"{category_id}.yaml"
            )
            for category_id in baseline_category_ids
        }
        current_rule_sets = {
            category_id: set(rules) for category_id, rules in rules_by_category.items()
        }

        def effective_action_for_rule(
            rule: str,
            category_rules: dict[str, set[str]],
            actions: dict[str, str],
            priorities: dict[str, int],
        ) -> str:
            matches = [
                category_id
                for category_id, category_rules_set in category_rules.items()
                if rule in category_rules_set
            ]
            if not matches:
                return "ABSENT"
            category_id = min(
                matches,
                key=lambda item: (priorities.get(item, 9999), item),
            )
            return actions.get(category_id, "UNSPECIFIED")

        for category_id in sorted(current_category_ids | baseline_category_ids):
            category_added = (
                category_id in current_category_ids
                and category_id not in baseline_category_ids
            )
            category_removed = (
                category_id in baseline_category_ids
                and category_id not in current_category_ids
            )
            before_rules = baseline_rule_sets.get(category_id, set())
            after_rules = current_rule_sets.get(category_id, set())
            added_rules = sorted(after_rules - before_rules, key=rule_sort_key)
            removed_rules = sorted(before_rules - after_rules, key=rule_sort_key)
            old_action = baseline_actions.get(category_id, "ABSENT")
            new_action = category_actions.get(category_id, "REMOVED")
            old_priority = baseline_priorities.get(category_id)
            new_priority = category_priorities.get(category_id)
            action_changed = (
                category_id in baseline_category_ids
                and category_id in current_category_ids
                and old_action != new_action
            )
            priority_changed = (
                category_id in baseline_category_ids
                and category_id in current_category_ids
                and old_priority != new_priority
            )
            if not (
                added_rules
                or removed_rules
                or category_added
                or category_removed
                or action_changed
                or priority_changed
            ):
                continue
            changed_category_ids.append(category_id)
            action_for_risk = (
                category_actions[category_id]
                if category_id in current_category_ids
                else baseline_actions.get(category_id, "UNSPECIFIED")
            )
            contract = resolved_contracts.get(category_id)
            dimensions = count_budget_dimensions(added_rules)
            before_count = len(before_rules)
            delta_pct = (
                (
                    (len(added_rules) + len(removed_rules))
                    * 100.0
                    / before_count
                )
                if before_count
                else (100.0 if after_rules else 0.0)
            )
            budget_values = {
                "max_add": len(added_rules),
                "max_remove": len(removed_rules),
                "max_pct": delta_pct,
                "max_new_apex": dimensions["new_apex"],
                "max_new_regex": dimensions["new_regex"],
                "max_new_cidr": dimensions["new_cidr"],
            }
            category_budget_exceeded: list[str] = []
            if contract is None:
                message = f"{category_id}:category_removed observed=1 allowed=0"
                category_budget_exceeded.append(message)
                budget_exceeded.append(message)
            else:
                for budget_name, observed in budget_values.items():
                    allowed = float(contract[budget_name])
                    if observed > allowed:
                        message = (
                            f"{category_id}:{budget_name} observed={observed:.6g} "
                            f"allowed={allowed:.6g}"
                        )
                        category_budget_exceeded.append(message)
                        budget_exceeded.append(message)

            added_payload: list[dict[str, Any]] = []
            for rule in added_rules:
                markers = rule_risk_markers(rule, action_for_risk, added=True)
                risk_markers.update(markers)
                source_ids = sorted(
                    attribution_by_category.get(category_id, {}).get(rule, set())
                )
                tiers = sorted(
                    {
                        str(item.get("trust_tier", "unknown"))
                        for item in SOURCE_PROVENANCE
                        if str(item.get("source_id", "")) in source_ids
                    }
                )
                if tiers and set(tiers) == {"community"}:
                    markers = sorted(set(markers) | {"single-community-tier"})
                    risk_markers.add("single-community-tier")
                added_payload.append(
                    {
                        "rule": rule,
                        "sources": source_ids,
                        "source_tiers": tiers,
                        "source_membership": [
                            rule_membership_witness(source_id, rule)
                            for source_id in source_ids
                        ],
                        "first_seen_utc": BUILD_GENERATED_AT,
                        "old_effective_action": effective_action_for_rule(
                            rule,
                            baseline_rule_sets,
                            baseline_actions,
                            baseline_priorities,
                        ),
                        "new_effective_action": effective_action_for_rule(
                            rule,
                            current_rule_sets,
                            category_actions,
                            category_priorities,
                        ),
                        "risk": markers,
                    }
                )
            removed_payload = [
                {
                    "rule": rule,
                    "sources": ["previous_snapshot"],
                    "last_seen_utc": BUILD_GENERATED_AT,
                    "old_effective_action": effective_action_for_rule(
                        rule,
                        baseline_rule_sets,
                        baseline_actions,
                        baseline_priorities,
                    ),
                    "new_effective_action": effective_action_for_rule(
                        rule,
                        current_rule_sets,
                        category_actions,
                        category_priorities,
                    ),
                    "risk": rule_risk_markers(
                        rule,
                        action_for_risk,
                        added=False,
                    ),
                }
                for rule in removed_rules
            ]
            if category_added:
                risk_markers.add("category-added")
            if category_removed:
                risk_markers.add("category-removed")
            if action_changed:
                risk_markers.add("effective-action-change")
            if priority_changed:
                risk_markers.add("priority-change")
            if contract is not None and str(
                contract.get("auto_promotion_policy")
            ) != "low-risk":
                risk_markers.add(
                    f"category-policy-{contract.get('auto_promotion_policy', 'review')}"
                )
            delta_categories.append(
                {
                    "category": category_id,
                    "action": new_action,
                    "previous_action": old_action,
                    "action_changed": action_changed,
                    "previous_priority": old_priority,
                    "priority": new_priority,
                    "priority_changed": priority_changed,
                    "category_added": category_added,
                    "category_removed": category_removed,
                    "before_count": before_count,
                    "after_count": len(after_rules),
                    "added_count": len(added_rules),
                    "removed_count": len(removed_rules),
                    "delta_pct": round(delta_pct, 6),
                    "budget_observed": budget_values,
                    "budget_exceeded": category_budget_exceeded,
                    "added": added_payload,
                    "removed": removed_payload,
                }
            )

    def informational_conflicts_by_category(
        payload: dict[str, Any],
    ) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        raw_conflicts = payload.get("conflicts", [])
        if not isinstance(raw_conflicts, list):
            return {}
        for item in raw_conflicts:
            if (
                not isinstance(item, dict)
                or bool(item.get("gated", True))
                or bool(item.get("waived", False))
                or str(item.get("type", "")) == "same_action_overlap"
            ):
                continue
            for raw_category in item.get("categories", []):
                category = str(raw_category).strip()
                if category:
                    counts[category] += 1
        return dict(counts)

    current_info_by_category = informational_conflicts_by_category(
        conflicts_payload
    )
    baseline_info_by_category = informational_conflicts_by_category(
        baseline_conflicts
    )
    info_delta_by_category = {
        category_id: current_info_by_category.get(category_id, 0)
        - baseline_info_by_category.get(category_id, 0)
        for category_id in sorted(
            set(current_info_by_category) | set(baseline_info_by_category)
        )
    }

    conflict_delta = {
        "cross_action": int(conflicts_payload.get("cross_action_conflict_count", 0))
        - int(baseline_conflicts.get("cross_action_conflict_count", 0)),
        "informational_cross_action": int(
            conflicts_payload.get("informational_cross_action_conflict_count", 0)
        )
        - int(
            baseline_conflicts.get(
                "informational_cross_action_conflict_count",
                0,
            )
        ),
        "high_severity": int(conflicts_payload.get("high_severity_conflict_count", 0))
        - int(baseline_conflicts.get("high_severity_conflict_count", 0)),
        "informational_by_category": info_delta_by_category,
    }
    for category_id in changed_category_ids:
        category_contract = resolved_contracts.get(category_id)
        if category_contract is None:
            continue
        allowed_info_delta = int(
            category_contract["max_informational_overlap_delta"]
        )
        observed_info_delta = info_delta_by_category.get(category_id, 0)
        if observed_info_delta > allowed_info_delta:
            message = (
                f"{category_id}:max_informational_overlap_delta "
                f"observed={observed_info_delta} "
                f"allowed={allowed_info_delta}"
            )
            if message not in budget_exceeded:
                budget_exceeded.append(message)

    source_lock_changed = bool(
        baseline_lock
        and baseline_lock.get("repositories", {})
        != source_lock_payload.get("repositories", {})
    )
    if not baseline_lock and SOURCE_LOCK:
        source_lock_changed = True
    changed = bool(delta_categories)
    auto_eligible = (
        baseline_available
        and changed
        and not risk_markers
        and not budget_exceeded
        and int(fetch_report.get("fallback_cache_count", 0)) == 0
        and not cache_blocked_sources
        and all(
            str(resolved_contracts.get(cid, {}).get("auto_promotion_policy"))
            == "low-risk"
            for cid in changed_category_ids
        )
    )
    semantic_digest = semantic_rules_digest(
        rules_by_category,
        category_actions,
        category_priorities,
    )
    rule_delta_payload = {
        "generated_at_utc": BUILD_GENERATED_AT,
        "baseline_available": baseline_available,
        "changed": changed,
        "changed_category_count": len(delta_categories),
        "changed_categories": changed_category_ids,
        "risk_markers": sorted(risk_markers),
        "budget_exceeded": sorted(budget_exceeded),
        "conflict_delta": conflict_delta,
        "source_lock_changed": source_lock_changed,
        "categories": delta_categories,
    }
    (dist_dir / "rule_delta.json").write_text(
        json.dumps(rule_delta_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    candidate_manifest = {
        "generated_at_utc": BUILD_GENERATED_AT,
        "baseline_available": baseline_available,
        "changed": changed,
        "semantic_digest": semantic_digest,
        "source_lock_sha256": source_lock_digest,
        "source_lock_changed": source_lock_changed,
        "risk_level": (
            "high"
            if risk_markers or budget_exceeded or cache_blocked_sources
            else ("low" if changed else "none")
        ),
        "auto_promotion_eligible": auto_eligible,
        "requires_review": changed and not auto_eligible,
        "changed_categories": changed_category_ids,
        "risk_markers": sorted(risk_markers),
        "budget_exceeded": sorted(budget_exceeded),
        "fallback_cache_count": int(fetch_report.get("fallback_cache_count", 0)),
        "cache_blocked_source_ids": cache_blocked_sources,
        "conflict_delta": conflict_delta,
    }
    (dist_dir / "candidate_manifest.json").write_text(
        json.dumps(candidate_manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def build_all(
    config_path: pathlib.Path,
    policy_path: pathlib.Path | None,
    source_registry_path: pathlib.Path,
    category_contracts_path: pathlib.Path,
    source_lock_path: pathlib.Path | None,
    baseline_dist_dir: pathlib.Path | None,
    dist_dir: pathlib.Path,
    cache_dir: pathlib.Path,
    offline: bool,
    fail_on_conflicts: bool,
    fail_on_cross_action_conflicts: bool,
) -> int:
    global BUILD_GENERATED_AT
    global PROTECTED_MULTI_TENANT_ROOTS
    global PROTECTED_PUBLIC_SUFFIXES
    global PUBLIC_SUFFIX_DATABASE
    global SOURCE_LOCK
    global SOURCE_REGISTRY

    BUILD_GENERATED_AT = dt.datetime.now(dt.timezone.utc).isoformat()
    FETCH_MEMO.clear()
    FETCH_EVENTS.clear()
    FETCH_ATTEMPTS.clear()
    SOURCE_PROVENANCE.clear()
    SOURCE_RULE_SETS.clear()
    SOURCE_RULE_MERKLE_CACHE.clear()
    V2FLY_ARCHIVE_MEMO.clear()
    V2FLY_PARSE_PROVENANCE.clear()
    SOURCE_REGISTRY = read_json(source_registry_path)
    (
        PROTECTED_PUBLIC_SUFFIXES,
        PROTECTED_MULTI_TENANT_ROOTS,
        PUBLIC_SUFFIX_DATABASE,
    ) = load_protected_domain_roots(
        DEFAULT_PROTECTED_DOMAIN_ROOTS_PATH, ROOT_DIR.parent
    )
    if source_lock_path is None:
        SOURCE_LOCK = {}
    else:
        if not source_lock_path.is_file():
            raise BuildError(f"source lock not found: {source_lock_path}")
        SOURCE_LOCK = read_json(source_lock_path)
    config = read_json(config_path)
    policy_map = load_policy_map(policy_path)
    category_contracts_config = read_json(category_contracts_path)
    ignored_conflict_sets = load_ignored_conflict_sets(config, policy_map)
    ignored_rule_conflicts = load_ignored_rule_conflicts(config)
    categories = config.get("categories", [])
    if not isinstance(categories, list) or not categories:
        raise BuildError("config has no categories")
    category_ids = {
        str(item.get("id", "")).strip()
        for item in categories
        if isinstance(item, dict) and str(item.get("id", "")).strip()
    }
    contract_overrides = category_contracts_config.get("categories", {})
    if not isinstance(contract_overrides, dict):
        raise BuildError("category contracts: categories must be an object")
    unknown_contracts = set(contract_overrides) - category_ids
    if unknown_contracts:
        raise BuildError(
            "category contracts contain unknown categories: "
            + ", ".join(sorted(unknown_contracts))
        )

    dist_dir.mkdir(parents=True, exist_ok=True)
    removed_duplicates = purge_duplicate_artifacts(dist_dir)
    if removed_duplicates > 0:
        log(f"removed {removed_duplicates} duplicate artifacts from dist directory")
    for stale in (dist_dir / "surge", dist_dir / "openclash", dist_dir / "compat", dist_dir / "meta", dist_dir / "stash"):
        if stale.exists():
            shutil.rmtree(stale)
    for stale_file in (
        dist_dir / "index.json",
        dist_dir / "conflicts.json",
        dist_dir / "fetch_report.json",
        dist_dir / "source_provenance.json",
        dist_dir / "source_health.json",
        dist_dir / "sources.lock.json",
        dist_dir / "rule_delta.json",
        dist_dir / "candidate_manifest.json",
        dist_dir / "client_parity.json",
        dist_dir / "allow_shadow.json",
        dist_dir / "category_contracts_resolved.json",
        dist_dir / "policy_reference.json",
        dist_dir / "policy_reference.md",
        dist_dir / "rule_catalog.md",
    ):
        if stale_file.exists():
            stale_file.unlink()

    surge_dir = dist_dir / "surge"
    openclash_dir = dist_dir / "openclash"

    rules_by_category: dict[str, list[str]] = {}
    attribution_by_category: dict[str, dict[str, set[str]]] = {}
    category_actions: dict[str, str] = {}
    category_priorities: dict[str, int] = {}
    resolved_contracts: dict[str, dict[str, Any]] = {}
    metadata_categories: list[dict[str, Any]] = []
    missing_policy: list[str] = []

    for category in categories:
        category_id = str(category.get("id", "")).strip()
        if not category_id:
            raise BuildError("category missing id")
        log(f"building category: {category_id}")

        if category.get("aggregate_of"):
            rules, source_meta, attribution = build_aggregate_category(
                category,
                ROOT_DIR,
                cache_dir,
                offline,
                rules_by_category,
                attribution_by_category,
            )
        else:
            rules, source_meta, attribution = build_category(
                category,
                ROOT_DIR,
                cache_dir,
                offline,
            )
        rules_by_category[category_id] = rules
        attribution_by_category[category_id] = attribution

        policy_entry = policy_map.get(category_id, {})
        action = str(policy_entry.get("action", "UNSPECIFIED")).upper().strip()
        if action not in ALLOWED_ACTIONS:
            raise BuildError(f"policy map: invalid action '{action}' for category '{category_id}'")
        category_actions[category_id] = action
        priority = int(policy_entry.get("priority", 9999))
        category_priorities[category_id] = priority
        note = str(policy_entry.get("note", "")).strip()
        contract = resolve_category_contract(
            category_id,
            action,
            category,
            category_contracts_config,
        )
        resolved_contracts[category_id] = contract
        validate_category_contract(
            category_id,
            rules,
            action,
            priority,
            contract,
            policy_map,
            source_meta,
        )
        if action == "UNSPECIFIED":
            missing_policy.append(category_id)

        surge_file = surge_dir / f"{category_id}.list"
        openclash_file = openclash_dir / f"{category_id}.yaml"
        stash_file = dist_dir / "stash" / f"{category_id}.list"
        surge_rules = filter_surge_compatible_rules(rules)
        surge_lost_rules = sorted(set(rules) - set(surge_rules), key=rule_sort_key)
        surge_lost_rule_types = rule_type_counts(set(surge_lost_rules))
        write_surge_rules(surge_file, surge_rules)
        write_openclash_rules(openclash_file, rules)
        write_surge_rules(stash_file, rules)

        surge_non_ip_rules, surge_ip_rules, _, _, domainset_lines_surge = split_rules(surge_rules)
        non_ip_rules, ip_rules, domainset_lines_oc, ipcidr_lines, _ = split_rules(rules)
        stash_classical_rules, stash_ipcidr_lines, stash_domain_lines = split_stash_rules(rules)

        write_surge_rules(dist_dir / "surge" / "non_ip" / f"{category_id}.list", surge_non_ip_rules)
        write_surge_rules(dist_dir / "surge" / "ip" / f"{category_id}.list", surge_ip_rules)
        write_plain_lines(dist_dir / "surge" / "domainset" / f"{category_id}.conf", domainset_lines_surge)

        write_openclash_rules(dist_dir / "openclash" / "non_ip" / f"{category_id}.yaml", non_ip_rules)
        write_openclash_rules(dist_dir / "openclash" / "ip" / f"{category_id}.yaml", ip_rules)
        write_plain_lines(dist_dir / "openclash" / "domainset" / f"{category_id}.txt", domainset_lines_oc)
        write_plain_lines(dist_dir / "openclash" / "ipcidr" / f"{category_id}.txt", ipcidr_lines)

        # Compatibility tree for direct replacement of common public ruleset layouts.
        write_surge_rules(dist_dir / "compat" / "Clash" / "non_ip" / f"{category_id}.txt", non_ip_rules)
        write_surge_rules(dist_dir / "compat" / "Clash" / "ip" / f"{category_id}.txt", ip_rules)
        write_plain_lines(dist_dir / "compat" / "Clash" / "domainset" / f"{category_id}.txt", domainset_lines_oc)
        write_surge_rules(dist_dir / "compat" / "List" / "non_ip" / f"{category_id}.conf", surge_non_ip_rules)
        write_surge_rules(dist_dir / "compat" / "List" / "ip" / f"{category_id}.conf", surge_ip_rules)
        write_plain_lines(dist_dir / "compat" / "List" / "domainset" / f"{category_id}.conf", domainset_lines_surge)

        write_surge_rules(dist_dir / "stash" / "classical" / f"{category_id}.list", stash_classical_rules)
        write_plain_lines(dist_dir / "stash" / "domainset" / f"{category_id}.txt", stash_domain_lines)
        write_plain_lines(dist_dir / "stash" / "ipcidr" / f"{category_id}.txt", stash_ipcidr_lines)

        metadata_categories.append(
            {
                "id": category_id,
                "description": category.get("description", ""),
                "rule_count": len(rules),
                "openclash_rule_count": len(rules),
                "surge_rule_count": len(surge_rules),
                "surge_lost_rule_count": len(surge_lost_rules),
                "surge_lost_rule_types": surge_lost_rule_types,
                "stash_rule_count": len(rules),
                "stash_classical_rule_count": len(stash_classical_rules),
                "stash_domain_rule_count": len(stash_domain_lines),
                "stash_ipcidr_rule_count": len(stash_ipcidr_lines),
                "surge_path": str(surge_file.relative_to(dist_dir)),
                "openclash_path": str(openclash_file.relative_to(dist_dir)),
                "stash_path": str(stash_file.relative_to(dist_dir)),
                "surge_non_ip_path": str((dist_dir / "surge" / "non_ip" / f"{category_id}.list").relative_to(dist_dir)),
                "surge_ip_path": str((dist_dir / "surge" / "ip" / f"{category_id}.list").relative_to(dist_dir)),
                "surge_domainset_path": str((dist_dir / "surge" / "domainset" / f"{category_id}.conf").relative_to(dist_dir)),
                "openclash_non_ip_path": str((dist_dir / "openclash" / "non_ip" / f"{category_id}.yaml").relative_to(dist_dir)),
                "openclash_ip_path": str((dist_dir / "openclash" / "ip" / f"{category_id}.yaml").relative_to(dist_dir)),
                "openclash_domainset_path": str((dist_dir / "openclash" / "domainset" / f"{category_id}.txt").relative_to(dist_dir)),
                "openclash_ipcidr_path": str((dist_dir / "openclash" / "ipcidr" / f"{category_id}.txt").relative_to(dist_dir)),
                "stash_classical_path": str((dist_dir / "stash" / "classical" / f"{category_id}.list").relative_to(dist_dir)),
                "stash_domainset_path": str((dist_dir / "stash" / "domainset" / f"{category_id}.txt").relative_to(dist_dir)),
                "stash_ipcidr_path": str((dist_dir / "stash" / "ipcidr" / f"{category_id}.txt").relative_to(dist_dir)),
                "compat_clash_non_ip_path": str((dist_dir / "compat" / "Clash" / "non_ip" / f"{category_id}.txt").relative_to(dist_dir)),
                "compat_clash_ip_path": str((dist_dir / "compat" / "Clash" / "ip" / f"{category_id}.txt").relative_to(dist_dir)),
                "compat_clash_domainset_path": str((dist_dir / "compat" / "Clash" / "domainset" / f"{category_id}.txt").relative_to(dist_dir)),
                "compat_list_non_ip_path": str((dist_dir / "compat" / "List" / "non_ip" / f"{category_id}.conf").relative_to(dist_dir)),
                "compat_list_ip_path": str((dist_dir / "compat" / "List" / "ip" / f"{category_id}.conf").relative_to(dist_dir)),
                "compat_list_domainset_path": str((dist_dir / "compat" / "List" / "domainset" / f"{category_id}.conf").relative_to(dist_dir)),
                "recommended_action": action,
                "recommended_priority": priority,
                "recommended_note": note,
                "contract": contract,
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
                    "openclash_rule_count": len(rules),
                    "surge_rule_count": len(surge_rules),
                    "surge_lost_rule_count": len(surge_lost_rules),
                    "surge_lost_rule_types": surge_lost_rule_types,
                    "stash_rule_count": len(rules),
                    "stash_classical_rule_count": len(stash_classical_rules),
                    "stash_domain_rule_count": len(stash_domain_lines),
                    "stash_ipcidr_rule_count": len(stash_ipcidr_lines),
                    "paths": {
                        "stash": str(stash_file.relative_to(dist_dir)),
                        "stash_classical": str((dist_dir / "stash" / "classical" / f"{category_id}.list").relative_to(dist_dir)),
                        "stash_domainset": str((dist_dir / "stash" / "domainset" / f"{category_id}.txt").relative_to(dist_dir)),
                        "stash_ipcidr": str((dist_dir / "stash" / "ipcidr" / f"{category_id}.txt").relative_to(dist_dir)),
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
                    "contract": contract,
                    "sources": source_meta
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    validate_disjoint_category_contracts(
        rules_by_category,
        resolved_contracts,
    )

    conflicts = detect_rule_conflicts(
        rules_by_category=rules_by_category,
        category_actions=category_actions,
        category_priorities=category_priorities,
        ignored_conflict_sets=ignored_conflict_sets,
        ignored_rule_conflicts=ignored_rule_conflicts,
    )
    cross_action_conflict_count = sum(
        1
        for item in conflicts
        if item.get("gated", True) and item["type"] != "same_action_overlap"
    )
    informational_cross_action_conflict_count = sum(
        1
        for item in conflicts
        if (
            not item.get("gated", True)
            and not item.get("waived", False)
            and item["type"] != "same_action_overlap"
        )
    )
    waived_conflict_count = sum(
        1 for item in conflicts if bool(item.get("waived", False))
    )
    high_severity_conflict_count = sum(
        1 for item in conflicts if item.get("gated", True) and item["severity"] == "high"
    )
    medium_severity_conflict_count = sum(
        1 for item in conflicts if item.get("gated", True) and item["severity"] == "medium"
    )
    low_severity_conflict_count = sum(1 for item in conflicts if item["severity"] == "low")

    conflicts_payload = {
        "generated_at_utc": BUILD_GENERATED_AT,
        "conflict_count": len(conflicts),
        "cross_action_conflict_count": cross_action_conflict_count,
        "informational_cross_action_conflict_count": informational_cross_action_conflict_count,
        "waived_conflict_count": waived_conflict_count,
        "high_severity_conflict_count": high_severity_conflict_count,
        "medium_severity_conflict_count": medium_severity_conflict_count,
        "low_severity_conflict_count": low_severity_conflict_count,
        "conflicts": conflicts,
    }
    conflicts_file = dist_dir / "conflicts.json"
    conflicts_file.write_text(
        json.dumps(
            conflicts_payload,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    fetch_report_file = dist_dir / "fetch_report.json"
    fetch_report = build_fetch_report()
    fetch_report_file.write_text(
        json.dumps(fetch_report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    write_intelligence_outputs(
        dist_dir=dist_dir,
        baseline_dist_dir=baseline_dist_dir,
        config=config,
        rules_by_category=rules_by_category,
        attribution_by_category=attribution_by_category,
        category_actions=category_actions,
        category_priorities=category_priorities,
        resolved_contracts=resolved_contracts,
        metadata_categories=metadata_categories,
        fetch_report=fetch_report,
        conflicts_payload=conflicts_payload,
    )

    manifest = {
        "generated_at_utc": BUILD_GENERATED_AT,
        "config_path": format_repo_path(config_path),
        "policy_path": format_repo_path(policy_path),
        "category_count": len(metadata_categories),
        "conflict_count": len(conflicts),
        "cross_action_conflict_count": cross_action_conflict_count,
        "informational_cross_action_conflict_count": informational_cross_action_conflict_count,
        "high_severity_conflict_count": high_severity_conflict_count,
        "fetch_report_path": str(fetch_report_file.relative_to(dist_dir)),
        "source_provenance_path": "source_provenance.json",
        "source_health_path": "source_health.json",
        "source_lock_path": "sources.lock.json",
        "rule_delta_path": "rule_delta.json",
        "candidate_manifest_path": "candidate_manifest.json",
        "client_parity_path": "client_parity.json",
        "allow_shadow_path": "allow_shadow.json",
        "category_contracts_path": "category_contracts_resolved.json",
        "recommended_templates": {
            "openclash": "recommended_openclash.yaml",
            "surge": "recommended_surge.conf",
            "stash_classical": "recommended_stash.yaml",
            "stash_native": "recommended_stash_native.yaml",
        },
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
                "generated_at_utc": BUILD_GENERATED_AT,
                "policy_path": format_repo_path(policy_path),
                "categories": [
                    {
                        "id": c["id"],
                        "recommended_action": c["recommended_action"],
                        "recommended_priority": c["recommended_priority"],
                        "recommended_note": c["recommended_note"],
                        "rule_count": c["rule_count"],
                        "openclash_rule_count": c["openclash_rule_count"],
                        "surge_rule_count": c["surge_rule_count"],
                        "surge_lost_rule_count": c["surge_lost_rule_count"],
                        "surge_lost_rule_types": c["surge_lost_rule_types"],
                        "stash_rule_count": c["stash_rule_count"],
                        "contract": c["contract"],
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


    log(f"build completed: {len(metadata_categories)} categories")
    log(
        "conflicts detected: "
        f"total={len(conflicts)} cross_action={cross_action_conflict_count} high={high_severity_conflict_count}"
    )
    log(
        "fetch summary: "
        f"network={fetch_report['network_success_count']} "
        f"offline_cache={fetch_report['offline_cache_count']} "
        f"fallback_cache={fetch_report['fallback_cache_count']}"
    )
    if missing_policy:
        log(f"warning: missing policy map for categories: {', '.join(sorted(missing_policy))}")

    if fail_on_conflicts and conflicts:
        return 2
    if fail_on_cross_action_conflicts and cross_action_conflict_count > 0:
        return 3
    return 0


def build_all_staged(
    config_path: pathlib.Path,
    policy_path: pathlib.Path | None,
    source_registry_path: pathlib.Path,
    category_contracts_path: pathlib.Path,
    source_lock_path: pathlib.Path | None,
    baseline_dist_dir: pathlib.Path | None,
    dist_dir: pathlib.Path,
    cache_dir: pathlib.Path,
    offline: bool,
    fail_on_conflicts: bool,
    fail_on_cross_action_conflicts: bool,
) -> int:
    """
    Build into a fresh staging directory and atomically replace dist_dir.

    This avoids sync-conflict duplicate artifacts (e.g. '* 2.list') in
    cloud-synced folders by preventing in-place multi-file rewrites.
    """
    dist_dir = validate_dist_target(dist_dir)
    dist_parent = dist_dir.parent
    dist_parent.mkdir(parents=True, exist_ok=True)
    staging_dir = pathlib.Path(
        tempfile.mkdtemp(prefix=f".{dist_dir.name}.staging.", dir=str(dist_parent))
    )
    try:
        code = build_all(
            config_path=config_path,
            policy_path=policy_path,
            source_registry_path=source_registry_path,
            category_contracts_path=category_contracts_path,
            source_lock_path=source_lock_path,
            baseline_dist_dir=baseline_dist_dir,
            dist_dir=staging_dir,
            cache_dir=cache_dir,
            offline=offline,
            fail_on_conflicts=fail_on_conflicts,
            fail_on_cross_action_conflicts=fail_on_cross_action_conflicts,
        )

        # A final duplicate sweep in staging prevents sync-generated conflict copies.
        removed_duplicates = purge_duplicate_artifacts(staging_dir)
        if removed_duplicates > 0:
            log(f"staging cleanup removed {removed_duplicates} duplicate artifacts")

        if dist_dir.exists():
            shutil.rmtree(dist_dir)
        staging_dir.replace(dist_dir)
        if not dist_dir.exists():
            renamed_candidates = sorted(
                path for path in dist_parent.glob(f"{dist_dir.name} *") if path.is_dir()
            )
            if len(renamed_candidates) == 1:
                log(
                    f"warning: dist directory was renamed to {renamed_candidates[0].name}; restoring expected path"
                )
                renamed_candidates[0].replace(dist_dir)
        removed_sibling_duplicates = purge_duplicate_sibling_artifacts(dist_dir)
        if removed_sibling_duplicates > 0:
            log(f"removed {removed_sibling_duplicates} duplicate sibling artifacts for {dist_dir.name}")
        return code
    finally:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)


def validate_dist_target(dist_dir: pathlib.Path) -> pathlib.Path:
    """Constrain recursive replacement to the canonical or OS temp tree."""
    if dist_dir.exists() and dist_dir.is_symlink():
        raise BuildError(f"refusing symlink dist target: {dist_dir}")

    resolved = dist_dir.expanduser().resolve(strict=False)
    canonical = DEFAULT_DIST_DIR.resolve(strict=False)
    temp_root = pathlib.Path(tempfile.gettempdir()).resolve(strict=False)
    if resolved == canonical:
        return resolved
    try:
        resolved.relative_to(temp_root)
    except ValueError as exc:
        raise BuildError(
            "custom --dist-dir must be inside the operating-system temporary directory"
        ) from exc
    if resolved == temp_root:
        raise BuildError("refusing to replace the temporary-directory root")
    if resolved.exists():
        if not resolved.is_dir():
            raise BuildError(f"custom dist target is not a directory: {resolved}")
        entries = list(resolved.iterdir())
        generated_markers = {"index.json", "policy_reference.json"}
        if entries and not generated_markers.issubset({entry.name for entry in entries}):
            raise BuildError(
                "refusing to replace a non-empty temporary directory without ruleset markers"
            )
    return resolved


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
        "--source-registry",
        type=pathlib.Path,
        default=DEFAULT_SOURCE_REGISTRY_PATH,
        help=f"Source security registry JSON (default: {DEFAULT_SOURCE_REGISTRY_PATH})",
    )
    parser.add_argument(
        "--category-contracts",
        type=pathlib.Path,
        default=DEFAULT_CATEGORY_CONTRACTS_PATH,
        help=f"Category semantic contracts JSON (default: {DEFAULT_CATEGORY_CONTRACTS_PATH})",
    )
    parser.add_argument(
        "--source-lock",
        type=pathlib.Path,
        default=None,
        help="Resolved immutable source lock JSON. Required by locked sources.",
    )
    parser.add_argument(
        "--baseline-dist",
        type=pathlib.Path,
        default=None,
        help="Previous dist directory used to generate semantic candidate deltas.",
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
    parser.add_argument(
        "--fail-on-cross-action-conflicts",
        action="store_true",
        help="Exit non-zero only when a rule overlaps across different action families.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return build_all_staged(
            config_path=args.config,
            policy_path=args.policy,
            source_registry_path=args.source_registry,
            category_contracts_path=args.category_contracts,
            source_lock_path=args.source_lock,
            baseline_dist_dir=args.baseline_dist,
            dist_dir=args.dist_dir,
            cache_dir=args.cache_dir,
            offline=args.offline,
            fail_on_conflicts=args.fail_on_conflicts,
            fail_on_cross_action_conflicts=args.fail_on_cross_action_conflicts,
        )
    except BuildError as exc:
        log(f"error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
