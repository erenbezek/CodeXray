"""
Taint motoru: TaintState + TaintAnalyzer

Traversal sozlesmesi:
  Expression  -> analyze_expression(node) -> TaintState
  Statement   -> expression tasiyan secili statement visitor'lari expression
                 slotlarini analiz eder; env guncellenir / Finding uretilir

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

from .call_arguments import CallArgumentBinder
from .call_model import CallModel, CallModelRegistry, default_call_model_registry
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
    def __init__(
        self,
        rule_engine: RuleEngine,
        call_model_registry: CallModelRegistry | None = None,
    ):
        self.rule_engine = rule_engine
        self.call_model_registry = (
            call_model_registry
            if call_model_registry is not None
            else default_call_model_registry()
        )
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

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            self.analyze_expression(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        value_state = self.analyze_expression(node.value)
        if not isinstance(node.target, ast.Name):
            return
        combined = merge_states(self.env.get(node.target.id, CLEAN), value_state)
        self.env[node.target.id] = self._extend_path(combined, node.target.id)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is None or not isinstance(node.target, ast.Name):
            return
        value_state = self.analyze_expression(node.value)
        self.env[node.target.id] = self._extend_path(value_state, node.target.id)

    def visit_Raise(self, node: ast.Raise) -> None:
        if node.exc is not None:
            self.analyze_expression(node.exc)
        if node.cause is not None:
            self.analyze_expression(node.cause)

    def visit_Assert(self, node: ast.Assert) -> None:
        self.analyze_expression(node.test)
        if node.msg is not None:
            self.analyze_expression(node.msg)

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

    def _analyze_List(self, node: ast.List) -> TaintState:
        """Analyze elements for nested sinks without tainting the container."""
        for element in node.elts:
            self.analyze_expression(element)
        return CLEAN

    def _analyze_ListComp(self, node: ast.ListComp) -> TaintState:
        self._analyze_comprehension(node.elt, node.generators)
        return CLEAN

    def _analyze_SetComp(self, node: ast.SetComp) -> TaintState:
        self._analyze_comprehension(node.elt, node.generators)
        return CLEAN

    def _analyze_GeneratorExp(self, node: ast.GeneratorExp) -> TaintState:
        self._analyze_comprehension(node.elt, node.generators)
        return CLEAN

    def _analyze_DictComp(self, node: ast.DictComp) -> TaintState:
        self._analyze_comprehension((node.key, node.value), node.generators)
        return CLEAN

    def _analyze_comprehension(
        self,
        yielded: ast.expr | tuple[ast.expr, ast.expr],
        generators: list[ast.comprehension],
    ) -> None:
        yielded_expressions = (
            yielded if isinstance(yielded, tuple) else (yielded,)
        )
        for expression in yielded_expressions:
            self.analyze_expression(expression)
        for generator in generators:
            self.analyze_expression(generator.iter)
            for condition in generator.ifs:
                self.analyze_expression(condition)

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
        if sanitizer_matches:
            sanitized = self._apply_sanitizers(node, qname, sanitizer_matches)
            if sanitized is not None:
                return sanitized

        model = self.call_model_registry.match(node)
        if model is not None:
            return self._apply_call_model(node, qname, model)

        # Siradan cagri: MVP intra-procedural oldugu icin arguman taint'i
        # donus degerine tasinmiyor (bilincli bilgi kaybi, v0.2'de kapanacak).
        # Eslestirilmeyen bir cagrida argumanlardaki nested sink'ler ifade
        # degerlendirmesi sirasinda gorunur olmali; return degeri CLEAN kalir.
        # Rule/call-model eslesmelerinin argumanlari zaten kendi semantik
        # yollarinda analiz edildigi icin burada tekrar dolaşilmaz.
        if not matches:
            for argument in node.args:
                self.analyze_expression(argument)
            for keyword in node.keywords:
                self.analyze_expression(keyword.value)
        return CLEAN

    def _apply_sanitizers(
        self, node: ast.Call, qname: str, sanitizer_matches: list[RuleMatch]
    ) -> TaintState | None:
        """Sanitize the explicitly selected arguments of a sanitizer call.

        Returns ``None`` when no selector binds, so the caller can fall through
        to the call-model path -- a sanitizer whose input we cannot see must not
        silently claim to have sanitized anything.
        """
        binder = CallArgumentBinder(node)
        selected_states: list[TaintState] = []
        new_categories: set[str] = set()

        for match in sanitizer_matches:
            bound = binder.bind_all(match.pattern.input_selectors)
            if not bound:
                continue
            selected_states.extend(self.analyze_expression(arg) for arg in bound)
            new_categories.update(match.pattern.sanitizes_for)

        if not selected_states:
            return None

        inner = merge_states(*selected_states)
        if not inner.tainted:
            return inner
        return replace(
            inner,
            path=inner.path + (qname,),
            sanitized_for=tuple(sorted(set(inner.sanitized_for) | new_categories)),
        )

    def _apply_call_model(
        self, node: ast.Call, qname: str, model: CallModel
    ) -> TaintState:
        """Apply explicit return-value semantics for a known library call."""
        if model.output != "return" or not model.preserves_taint:
            return CLEAN

        binder = CallArgumentBinder(node)
        selected_states = [
            self.analyze_expression(argument)
            for argument in binder.bind_all(model.input_selectors)
        ]
        if not selected_states:
            return CLEAN

        state = merge_states(*selected_states)
        if not state.tainted:
            return CLEAN
        if not model.preserves_sanitization:
            state = replace(state, sanitized_for=())
        return replace(state, path=state.path + (qname,))

    def _check_sinks(self, node: ast.Call, qname: str, sink_matches: list[RuleMatch]) -> None:
        binder = CallArgumentBinder(node)

        for match in sink_matches:
            rule = match.rule
            pattern = match.pattern
            # Rule'daki TUM sanitizer'ların birleşimi değil, bu sink
            # pattern'inin kendi kabul ettiği kategoriler kullanılıyor.
            required = set(pattern.requires_sanitization_for)

            # Her tehlikeli arguman ayri ayri degerlendirilir (merge edilmez):
            # iki farkli argumandan gelen iki ayri veri akisi iki ayri bulgudur.
            for selector in pattern.dangerous_arguments:
                argument = binder.bind(selector)
                if argument is None:
                    continue
                state = self.analyze_expression(argument)
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
