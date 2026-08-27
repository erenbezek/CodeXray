"""
Taint motoru: TaintState + TaintAnalyzer

Traversal sozlesmesi:
  Expression  -> analyze_expression(node) -> TaintState
  Statement   -> visit_Assign / visit_Expr -> env guncellenir / Finding uretilir

Traversal hicbir yerde kurala ozgu bilgi tasimaz (orn. "sql" veya
"execute" gibi string'ler burada gecmez) -- butun karar RuleEngine'e
soruluyor. Yeni bir kategori eklemek (XSS, Path Manipulation, ...)
rules/ altina yeni bir Rule tanimlamak demektir, bu dosyaya dokunmadan.

MVP kapsami: intra-procedural. Tuple unpacking (a, b = ...) ve
fonksiyonlar arasi taint propagation (v0.2) bilincli olarak desteklenmiyor.
"""

from __future__ import annotations
import ast
from dataclasses import dataclass, replace

from .rule_model import RuleEngine, RuleMatch, resolve_qualified_name


@dataclass(frozen=True)
class TaintState:
    """Immutable -- b = a sonrasinda b'yi degistirmek a'yi etkilemesin diye."""
    tainted: bool
    source: str | None = None
    kind: str | None = None
    path: tuple[str, ...] = ()
    sanitized_for: tuple[str, ...] = ()


CLEAN = TaintState(tainted=False)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    cwe: str
    severity: str
    message: str
    path: tuple[str, ...]
    lineno: int


def merge_states(*states: TaintState) -> TaintState:
    """BinOp/JoinedStr gibi birden cok parcayi birlestiren ortak kural.

    tainted(herhangi bir parca) -> tainted(sonuc). sanitized_for kesisimi
    alinir (union degil) -- bir parca sql icin temiz, digeri degilse,
    sonucu yanlislikla "sql icin guvenli" saymamak icin.
    """
    tainted_states = [s for s in states if s.tainted]
    if not tainted_states:
        return CLEAN

    combined_path: list[str] = []
    for s in tainted_states:
        for p in s.path:
            if p not in combined_path:
                combined_path.append(p)

    sanitized_sets = [set(s.sanitized_for) for s in tainted_states]
    combined_sanitized = tuple(sorted(set.intersection(*sanitized_sets)))

    primary = tainted_states[0]
    return TaintState(
        tainted=True,
        source=primary.source,
        kind=primary.kind,
        path=tuple(combined_path),
        sanitized_for=combined_sanitized,
    )


class TaintAnalyzer(ast.NodeVisitor):
    def __init__(self, rule_engine: RuleEngine):
        self.rule_engine = rule_engine
        self.env: dict[str, TaintState] = {}
        self.findings: list[Finding] = []

    # ---- statement seviyesi ----

    def visit_Assign(self, node: ast.Assign) -> None:
        value_state = self.analyze_expression(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.env[target.id] = self._extend_path(value_state, target.id)
            # tuple unpacking (a, b = ...) MVP'de desteklenmiyor -- bilincli sinir

    def visit_Expr(self, node: ast.Expr) -> None:
        self.analyze_expression(node.value)

    def _extend_path(self, state: TaintState, name: str) -> TaintState:
        if not state.tainted:
            return state
        if state.path and state.path[-1] == name:
            return state
        return replace(state, path=state.path + (name,))

    # ---- expression seviyesi ----

    def analyze_expression(self, node: ast.AST) -> TaintState:
        handler = getattr(self, f"_analyze_{type(node).__name__}", None)
        if handler is None:
            return CLEAN
        return handler(node)

    def _analyze_Name(self, node: ast.Name) -> TaintState:
        return self.env.get(node.id, CLEAN)

    def _analyze_Constant(self, node: ast.Constant) -> TaintState:
        return CLEAN

    def _source_like(self, node: ast.AST) -> TaintState | None:
        for match in self.rule_engine.classify(node):
            if match.role == "source":
                qname = resolve_qualified_name(node) or "<source>"
                return TaintState(
                    tainted=True, source=qname, kind=match.pattern.kind, path=(qname,)
                )
        return None

    def _analyze_Attribute(self, node: ast.Attribute) -> TaintState:
        return self._source_like(node) or self.analyze_expression(node.value)

    def _analyze_Subscript(self, node: ast.Subscript) -> TaintState:
        return self._source_like(node) or self.analyze_expression(node.value)

    def _analyze_BinOp(self, node: ast.BinOp) -> TaintState:
        return merge_states(
            self.analyze_expression(node.left), self.analyze_expression(node.right)
        )

    def _analyze_JoinedStr(self, node: ast.JoinedStr) -> TaintState:
        parts = [
            self.analyze_expression(v.value)
            for v in node.values
            if isinstance(v, ast.FormattedValue)
        ]
        return merge_states(*parts) if parts else CLEAN

    def _analyze_Call(self, node: ast.Call) -> TaintState:
        matches = self.rule_engine.classify(node)
        qname = resolve_qualified_name(node) or "<call>"

        sink_matches = [m for m in matches if m.role == "sink"]
        if sink_matches:
            self._check_sinks(node, qname, sink_matches)

        source_matches = [m for m in matches if m.role == "source"]
        if source_matches:
            match = source_matches[0]
            return TaintState(
                tainted=True, source=qname, kind=match.pattern.kind, path=(qname,)
            )

        sanitizer_matches = [m for m in matches if m.role == "sanitizer"]
        if sanitizer_matches and node.args:
            inner = self.analyze_expression(node.args[0])
            if not inner.tainted:
                return inner
            new_categories = {
                cat for m in sanitizer_matches for cat in m.pattern.sanitizes_for
            }
            return replace(
                inner,
                path=inner.path + (qname,),
                sanitized_for=tuple(set(inner.sanitized_for) | new_categories),
            )

        # Siradan cagri: MVP intra-procedural oldugu icin arguman taint'i
        # donus degerine tasinmiyor (bilincli bilgi kaybi, v0.2'de kapanacak).
        return CLEAN

    def _check_sinks(self, node: ast.Call, qname: str, sink_matches: list[RuleMatch]) -> None:
        for match in sink_matches:
            rule = match.rule
            pattern = match.pattern
            # Rule'daki TUM sanitizer'ların birleşimi değil, bu sink
            # pattern'inin kendi kabul ettiği kategoriler kullanılıyor.
            required = set(pattern.requires_sanitization_for)

            for arg_index in pattern.dangerous_arguments:
                if arg_index >= len(node.args):
                    continue
                state = self.analyze_expression(node.args[arg_index])
                if not state.tainted:
                    continue
                if required and required.issubset(set(state.sanitized_for)):
                    continue

                self.findings.append(
                    Finding(
                        rule_id=rule.id,
                        cwe=rule.cwe,
                        severity=rule.severity,
                        message=f"{state.source} kaynakli kullanici girdisi, sanitize edilmeden {qname} sink'ine ulasiyor",
                        path=state.path + (qname,),
                        lineno=node.lineno,
                    )
                )
