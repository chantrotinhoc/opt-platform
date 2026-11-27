"""Reversible redaction applied before any cloud LLM call.

Replaces IPv4 addresses, emails, credential-like values and internal hostnames
with stable placeholders, then restores them in the model's answer.
"""
from __future__ import annotations

import ipaddress
import re
import secrets
from dataclasses import dataclass, field

_SECRET = re.compile(
    r"(?i)\b((?:password|passwd|pwd|token|secret|api[_-]?key)\s*[=:]\s*)"
    r"(?:\"((?:[^\"\\]|\\.)*)\"|'((?:[^'\\]|\\.)*)'|([^\s'\",;]+))")

_IPV6_CANDIDATE = re.compile(r"(?<![\w:])[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*(?![\w:])")

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("IP", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("HOST", re.compile(r"\b[\w-]+(?:\.[\w-]+)*\.(?:local|lan|internal|corp|intra)\b", re.I)),
]


@dataclass
class Redactor:
    _forward: dict[str, str] = field(default_factory=dict)
    _reverse: dict[str, str] = field(default_factory=dict)
    _counters: dict[str, int] = field(default_factory=dict)
    # A per-instance nonce makes placeholders impossible to confuse with text
    # that already looks like a placeholder (e.g. a literal "IP_1").
    _nonce: str = field(default_factory=lambda: secrets.token_hex(3))

    def _token(self, kind: str, value: str) -> str:
        if value in self._forward:
            return self._forward[value]
        n = self._counters.get(kind, 0) + 1
        self._counters[kind] = n
        token = f"<{kind}_{n}_{self._nonce}>"
        self._forward[value] = token
        self._reverse[token] = value
        return token

    def _token_re(self) -> re.Pattern[str]:
        return re.compile(rf"<[A-Z]+_\d+_{self._nonce}>")

    def redact(self, text: str) -> str:
        # Input that already contains one of our own placeholders (e.g. pasted
        # from an earlier answer) is itself redacted as a literal, so restore()
        # gives it back unchanged instead of expanding it.
        text = self._token_re().sub(lambda m: self._token("LIT", m.group(0)), text)

        def secret(m: re.Match[str]) -> str:
            if m.group(2) is not None:
                return f'{m.group(1)}"{self._token("SECRET", m.group(2))}"'
            if m.group(3) is not None:
                return f"{m.group(1)}'{self._token('SECRET', m.group(3))}'"
            return m.group(1) + self._token("SECRET", m.group(4))

        text = _SECRET.sub(secret, text)
        def ipv6(m: re.Match[str]) -> str:
            try:
                ipaddress.IPv6Address(m.group(0))
            except ValueError:
                return m.group(0)
            return self._token("IP", m.group(0))

        text = _IPV6_CANDIDATE.sub(ipv6, text)
        for kind, pattern in _PATTERNS:
            text = pattern.sub(lambda m, k=kind: self._token(k, m.group(0)), text)
        return text

    def restore(self, text: str) -> str:
        # One pass, so a restored value is never expanded a second time.
        return self._token_re().sub(lambda m: self._reverse.get(m.group(0), m.group(0)), text)
