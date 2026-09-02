"""
Kural semasi: SourcePattern / SanitizerPattern / SinkPattern / Rule

Bu modul, taint motorunun "kural mantigini" traversal kodundan ayirir.
Traversal (ast.NodeVisitor) sadece bir node'u RuleEngine'e sorar;
"bu node'un guvenlik acisindan ne ifade ettigine" RuleEngine karar verir.
Boylece taint_engine.py icinde asla "if function_name == 'execute'" gibi
kurala ozgu kod bulunmaz -- yeni bir kategori eklemek rules/ altina yeni
bir Rule tanimlamak demektir, bu dosyaya ya da traversal'a dokunmadan.

MVP eslestirme stratejisi: qualified-name tabanli (regex degil).
Bilinen sinir: tam type inference yapmiyoruz -- "cursor.execute" ile
farkli bir sinifin ayni isimli metodu ayirt edilemeyebilir. module alani
ileride bu ayrimi guclendirmek icin ayrilmis durumda.
"""

from __future__ import annotations
import ast
from dataclasses import dataclass
from typing import Literal

from .call_arguments import ArgumentSelectorLike

MatchRole = Literal["source", "sanitizer", "sink"]


@dataclass(frozen=True)
class CallTarget:
    qualified_name: str
    module: str | None = None


@dataclass(frozen=True)
class SourcePattern:
    id: str
    kind: str
    targets: tuple[CallTarget, ...]


@dataclass(frozen=True)
class SanitizerPattern:
    id: str
    sanitizes_for: tuple[str, ...]
    targets: tuple[CallTarget, ...]
    input_selectors: tuple[ArgumentSelectorLike, ...] = (0,)
    """Hangi parametrenin sanitize edildigi -- parametre basina bir giris.
    Varsayilan ilk pozisyonel arguman (onceki davranis). parameter(0, "s")
    ile html.escape(x) ve html.escape(s=x) ayni tanimla cozulur."""


@dataclass(frozen=True)
class SinkPattern:
    id: str
    targets: tuple[CallTarget, ...]
    dangerous_arguments: tuple[ArgumentSelectorLike, ...]
    requires_sanitization_for: tuple[str, ...] = ()
    """Bu sink'in kabul ettigi sanitizer kategorileri. Bos ise: herhangi bir
    tainted deger (sanitize durumuna bakilmaksizin) alarm uretir. Bilincli
    olarak rule.sanitizers'in birlesiminden degil, sink'in kendi tanimindan
    geliyor -- bir rule'da birden fazla, farkli baglamlar icin sanitizer
    oldugunda hepsinin zorunlu kilinmasini onlemek icin (bkz. design-decisions.md)."""


@dataclass(frozen=True)
class Rule:
    id: str
    cwe: str
    severity: str
    sources: tuple[SourcePattern, ...]
    sanitizers: tuple[SanitizerPattern, ...]
    sinks: tuple[SinkPattern, ...]


@dataclass(frozen=True)
class RuleMatch:
    """classify()'in tek bir eslesme icin dondurdugu zengin sonuc."""
    rule: Rule
    role: MatchRole
    pattern: SourcePattern | SanitizerPattern | SinkPattern


def resolve_qualified_name(node: ast.AST) -> str | None:
    """Attribute/Name/Call/Subscript zincirini 'a.b.c' string'ine cevirir."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = resolve_qualified_name(node.value)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Call):
        return resolve_qualified_name(node.func)
    if isinstance(node, ast.Subscript):
        return resolve_qualified_name(node.value)
    return None


def matches_target(qualified_name: str, target: CallTarget) -> bool:
    return (
        qualified_name == target.qualified_name
        or qualified_name.endswith(f".{target.qualified_name}")
    )


class RuleEngine:
    """Traversal'in tek sordugu soru: 'bu node ne anlama geliyor?'"""

    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def classify(self, node: ast.AST) -> list[RuleMatch]:
        qname = resolve_qualified_name(node)
        if not qname:
            return []

        matches: list[RuleMatch] = []
        for rule in self.rules:
            for src in rule.sources:
                if any(matches_target(qname, t) for t in src.targets):
                    matches.append(RuleMatch(rule, "source", src))
            for san in rule.sanitizers:
                if any(matches_target(qname, t) for t in san.targets):
                    matches.append(RuleMatch(rule, "sanitizer", san))
            for sink in rule.sinks:
                if any(matches_target(qname, t) for t in sink.targets):
                    matches.append(RuleMatch(rule, "sink", sink))
        return matches
