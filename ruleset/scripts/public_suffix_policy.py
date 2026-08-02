#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import pathlib
import re
from dataclasses import dataclass
from typing import Any, Iterable


GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PSL_BEGIN_ICANN = "// ===BEGIN ICANN DOMAINS==="
PSL_END_ICANN = "// ===END ICANN DOMAINS==="
PSL_BEGIN_PRIVATE = "// ===BEGIN PRIVATE DOMAINS==="
PSL_END_PRIVATE = "// ===END PRIVATE DOMAINS==="


class PublicSuffixPolicyError(RuntimeError):
    pass


def normalize_domain(value: str) -> str:
    raw = value.lower().strip().strip(".")
    if not raw or ".." in raw:
        raise PublicSuffixPolicyError(f"invalid domain: {value!r}")
    try:
        normalized = ".".join(
            label.encode("idna").decode("ascii") for label in raw.split(".")
        )
    except UnicodeError as exc:
        raise PublicSuffixPolicyError(f"invalid IDNA domain: {value!r}") from exc
    if len(normalized) > 253 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or re.fullmatch(r"[a-z0-9-]+", label) is None
        for label in normalized.split(".")
    ):
        raise PublicSuffixPolicyError(f"invalid domain: {value!r}")
    return normalized


@dataclass(frozen=True)
class PublicSuffixMatch:
    public_suffix: str
    registrable_domain: str | None
    section: str
    rule: str
    is_exception: bool


@dataclass(frozen=True)
class PublicSuffixDatabase:
    exact_rules: dict[str, str]
    wildcard_rules: dict[str, str]
    exception_rules: dict[str, str]
    sha256: str
    source_commit: str

    @property
    def rule_count(self) -> int:
        return (
            len(self.exact_rules)
            + len(self.wildcard_rules)
            + len(self.exception_rules)
        )

    @property
    def icann_rule_count(self) -> int:
        return sum(
            section == "icann"
            for rules in (
                self.exact_rules,
                self.wildcard_rules,
                self.exception_rules,
            )
            for section in rules.values()
        )

    @property
    def private_rule_count(self) -> int:
        return sum(
            section == "private"
            for rules in (
                self.exact_rules,
                self.wildcard_rules,
                self.exception_rules,
            )
            for section in rules.values()
        )

    def match(self, value: str) -> PublicSuffixMatch:
        normalized = normalize_domain(value)
        labels = normalized.split(".")

        for index in range(len(labels)):
            candidate = ".".join(labels[index:])
            section = self.exception_rules.get(candidate)
            if section is None:
                continue
            suffix_labels = candidate.split(".")[1:]
            public_suffix = ".".join(suffix_labels)
            registrable_count = len(suffix_labels) + 1
            return PublicSuffixMatch(
                public_suffix=public_suffix,
                registrable_domain=".".join(labels[-registrable_count:]),
                section=section,
                rule=f"!{candidate}",
                is_exception=True,
            )

        best_length = 1
        best_section = "default"
        best_rule = "*"
        best_priority = 0
        for index in range(len(labels)):
            candidate = ".".join(labels[index:])
            exact_section = self.exact_rules.get(candidate)
            candidate_length = len(labels) - index
            if exact_section is not None and (
                candidate_length > best_length
                or (candidate_length == best_length and best_priority < 2)
            ):
                best_length = candidate_length
                best_section = exact_section
                best_rule = candidate
                best_priority = 2
            wildcard_section = self.wildcard_rules.get(candidate)
            wildcard_length = candidate_length + 1
            if (
                wildcard_section is not None
                and index > 0
                and (
                    wildcard_length > best_length
                    or (wildcard_length == best_length and best_priority < 1)
                )
            ):
                best_length = wildcard_length
                best_section = wildcard_section
                best_rule = f"*.{candidate}"
                best_priority = 1

        public_suffix = ".".join(labels[-best_length:])
        registrable_domain = (
            ".".join(labels[-(best_length + 1) :])
            if len(labels) > best_length
            else None
        )
        return PublicSuffixMatch(
            public_suffix=public_suffix,
            registrable_domain=registrable_domain,
            section=best_section,
            rule=best_rule,
            is_exception=False,
        )


def _parse_psl_lines(
    lines: Iterable[str], *, sha256: str, source_commit: str
) -> PublicSuffixDatabase:
    exact: dict[str, str] = {}
    wildcard: dict[str, str] = {}
    exceptions: dict[str, str] = {}
    section: str | None = None
    observed_markers: set[str] = set()

    for raw in lines:
        line = raw.strip()
        if line in {
            PSL_BEGIN_ICANN,
            PSL_END_ICANN,
            PSL_BEGIN_PRIVATE,
            PSL_END_PRIVATE,
        }:
            if line in observed_markers:
                raise PublicSuffixPolicyError(f"duplicate PSL section marker: {line}")
            observed_markers.add(line)
            if line == PSL_BEGIN_ICANN:
                if section is not None:
                    raise PublicSuffixPolicyError("nested PSL ICANN section")
                section = "icann"
            elif line == PSL_BEGIN_PRIVATE:
                if section is not None:
                    raise PublicSuffixPolicyError("nested PSL PRIVATE section")
                section = "private"
            else:
                expected = "icann" if line == PSL_END_ICANN else "private"
                if section != expected:
                    raise PublicSuffixPolicyError(f"unbalanced PSL section: {line}")
                section = None
            continue
        if not line or line.startswith("//"):
            continue
        if section is None:
            raise PublicSuffixPolicyError("PSL rule appears outside a named section")

        target = exact
        raw_domain = line
        if line.startswith("!"):
            target = exceptions
            raw_domain = line[1:]
        elif line.startswith("*."):
            target = wildcard
            raw_domain = line[2:]
        domain = normalize_domain(raw_domain)
        if domain in target:
            raise PublicSuffixPolicyError(f"duplicate PSL rule: {line}")
        target[domain] = section

    required_markers = {
        PSL_BEGIN_ICANN,
        PSL_END_ICANN,
        PSL_BEGIN_PRIVATE,
        PSL_END_PRIVATE,
    }
    if observed_markers != required_markers or section is not None:
        raise PublicSuffixPolicyError("PSL section markers are incomplete")
    database = PublicSuffixDatabase(
        exact_rules=exact,
        wildcard_rules=wildcard,
        exception_rules=exceptions,
        sha256=sha256,
        source_commit=source_commit,
    )
    if database.icann_rule_count < 5_000 or database.private_rule_count < 2_000:
        raise PublicSuffixPolicyError("PSL snapshot is unexpectedly incomplete")
    return database


def load_public_suffix_database(
    metadata: dict[str, Any], repository_root: pathlib.Path
) -> PublicSuffixDatabase:
    if not isinstance(metadata, dict):
        raise PublicSuffixPolicyError("public_suffix_list metadata must be an object")
    if metadata.get("source_repository") != "publicsuffix/list":
        raise PublicSuffixPolicyError("public_suffix_list source repository is invalid")
    source_commit = str(metadata.get("source_commit", ""))
    expected_sha256 = str(metadata.get("sha256", ""))
    relative_path = str(metadata.get("path", ""))
    expected_url = (
        "https://raw.githubusercontent.com/publicsuffix/list/"
        f"{source_commit}/public_suffix_list.dat"
    )
    if not GIT_SHA_RE.fullmatch(source_commit):
        raise PublicSuffixPolicyError("public_suffix_list source commit is invalid")
    if not SHA256_RE.fullmatch(expected_sha256):
        raise PublicSuffixPolicyError("public_suffix_list SHA-256 is invalid")
    if metadata.get("source_url") != expected_url:
        raise PublicSuffixPolicyError("public_suffix_list source URL is not commit-pinned")
    if relative_path != "ruleset/config/public_suffix_list.dat":
        raise PublicSuffixPolicyError("public_suffix_list path is invalid")

    root = repository_root.resolve()
    path = (root / relative_path).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise PublicSuffixPolicyError("public_suffix_list path escapes repository") from exc
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PublicSuffixPolicyError(f"cannot read public_suffix_list: {exc}") from exc
    observed_sha256 = hashlib.sha256(data).hexdigest()
    if observed_sha256 != expected_sha256:
        raise PublicSuffixPolicyError(
            "public_suffix_list SHA-256 mismatch: "
            f"expected={expected_sha256} observed={observed_sha256}"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PublicSuffixPolicyError("public_suffix_list is not UTF-8") from exc
    return _parse_psl_lines(
        text.splitlines(), sha256=observed_sha256, source_commit=source_commit
    )


def domain_topology_markers(
    value: str,
    database: PublicSuffixDatabase | None,
    public_suffixes: set[str],
    multi_tenant_roots: set[str],
) -> set[str]:
    normalized = normalize_domain(value)
    labels = normalized.split(".")
    markers: set[str] = set()
    if len(labels) == 1:
        markers.add("new-tld")
    elif len(labels) == 2:
        markers.add("new-apex")

    if database is not None:
        match = database.match(normalized)
        if match.section == "private":
            markers.add("protected-domain-root")
        elif normalized == match.public_suffix and match.section == "icann":
            markers.add("protected-domain-root")
        elif match.registrable_domain == normalized:
            markers.add("new-apex")

    if any(
        normalized.endswith(f".{suffix}")
        and len(labels) == len(suffix.split(".")) + 1
        for suffix in public_suffixes
    ):
        markers.add("new-apex")
    if normalized in public_suffixes or any(
        normalized == root or normalized.endswith(f".{root}")
        for root in multi_tenant_roots
    ):
        markers.add("protected-domain-root")
    return markers
