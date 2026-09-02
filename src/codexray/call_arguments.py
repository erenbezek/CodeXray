"""Shared binding between ``ast.Call`` arguments and the selectors naming them.

``CallModel``, ``SinkPattern``, and ``SanitizerPattern`` all need to answer the
same question: "which expression does this call pass as the argument I care
about?".  Before this module each layer answered it separately, and all three
answered it by positional index only -- so ``json.dumps(obj=user_input)``,
``Response(response=user_input)``, and ``html.escape(s=user_input)`` were
invisible to the engine.

The selector is deliberately declarative: a rule or model says *which* argument
it means, and this module resolves it against one concrete call site.  Nothing
here carries security meaning -- that stays in :mod:`codexray.rule_model` and
the vulnerability rules.

Binding is conservative by design: a selector that cannot be resolved to a
concrete expression binds to nothing rather than guessing.  See the
"Shared Call-Argument Binding" entry in ``docs/design-decisions.md``.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ArgumentSelector:
    """Names one *parameter* of a call without knowing the call site yet.

    A parameter may be addressable positionally, by keyword, or both -- which is
    why one selector carries both spellings rather than one selector per
    spelling.  ``(parameter(0, "s"),)`` says "one parameter"; ``(parameter(0),
    parameter(name="s"))`` says "two parameters".  Collapsing those two into the
    same shape is exactly the ambiguity this model exists to remove.
    """

    index: int | None = None
    name: str | None = None

    def __post_init__(self) -> None:
        if self.index is None and self.name is None:
            raise ValueError("an ArgumentSelector needs an index, a name, or both")


def parameter(index: int | None = None, name: str | None = None) -> ArgumentSelector:
    """One parameter, addressable positionally, by keyword, or both."""
    return ArgumentSelector(index=index, name=name)


def positional(index: int) -> ArgumentSelector:
    """A parameter that can only be passed positionally."""
    return ArgumentSelector(index=index)


def keyword(name: str) -> ArgumentSelector:
    """A parameter that can only be passed by keyword."""
    return ArgumentSelector(name=name)


#: Rules and models may keep writing plain ints (``dangerous_arguments=(0,)``).
ArgumentSelectorLike = int | ArgumentSelector


def as_selector(value: ArgumentSelectorLike) -> ArgumentSelector:
    """Normalise the backward-compatible int shorthand: ``0`` -> ``positional(0)``."""
    if isinstance(value, ArgumentSelector):
        return value
    return positional(value)


class CallArgumentBinder:
    """Resolves selectors against one concrete ``ast.Call``.

    Unresolvable selectors return ``None`` instead of a guess.  That keeps the
    engine's unknown-call policy intact: ``*args`` / ``**kwargs`` do not make an
    argument "selected", they make it unknown, and unknown is not tainted.
    """

    def __init__(self, node: ast.Call):
        self.node = node

    def bind(self, selector: ArgumentSelectorLike) -> ast.expr | None:
        """Resolve one parameter to the expression the call passes for it.

        A real call passes a parameter positionally *or* by keyword, never both,
        so the first spelling that resolves is the one actually used and the
        other is not consulted.  Never merges: one parameter, one expression.
        If invalid code supplies both, the positional spelling wins.
        """
        resolved = as_selector(selector)

        if resolved.index is not None:
            bound = self._bind_positional(resolved.index)
            if bound is not None:
                return bound
        if resolved.name is not None:
            return self._bind_keyword(resolved.name)
        return None

    def bind_all(
        self, selectors: Iterable[ArgumentSelectorLike]
    ) -> tuple[ast.expr, ...]:
        """Bind every selector, silently dropping the ones that do not resolve."""
        bound = [self.bind(selector) for selector in selectors]
        return tuple(expr for expr in bound if expr is not None)

    def _bind_positional(self, index: int | None) -> ast.expr | None:
        if index is None or not 0 <= index < len(self.node.args):
            return None
        # A `*args` unpacking shifts every position after it by an unknown
        # amount, so positions from there on cannot be resolved.
        if any(isinstance(arg, ast.Starred) for arg in self.node.args[: index + 1]):
            return None
        return self.node.args[index]

    def _bind_keyword(self, name: str | None) -> ast.expr | None:
        if name is None:
            return None
        for kw in self.node.keywords:
            # kw.arg is None for `**kwargs`; its contents are unknown.
            if kw.arg == name:
                return kw.value
        return None
