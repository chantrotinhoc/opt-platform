"""Reversible redaction applied before any cloud LLM call.

Replaces IPv4 addresses, emails, credential-like values and internal hostnames
with stable placeholders, then restores them in the model's answer.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_SECRET = re.compile(r"(?i)\b((?:password|passwd|pwd|token|secret|api[_-]?key)[=:]\s?)([^\s'\",;]+)")

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

    def _token(self, kind: str, value: str) -> str:
        if value in self._forward:
            return self._forward[value]
        n = self._counters.get(kind, 0) + 1
        self._counters[kind] = n
        token = f"{kind}_{n}"
        self._forward[value] = token
        self._reverse[token] = value
        return token

    def redact(self, text: str) -> str:
        text = _SECRET.sub(lambda m: m.group(1) + self._token("SECRET", m.group(2)), text)
        for kind, pattern in _PATTERNS:
            text = pattern.sub(lambda m, k=kind: self._token(k, m.group(0)), text)
        return text

    def restore(self, text: str) -> str:
        for token in sorted(self._reverse, key=len, reverse=True):
            text = text.replace(token, self._reverse[token])
        return text
