"""Generic models for calls whose return value has known taint semantics.

Call models describe library/data-flow behavior only.  Security meaning
(sources, sanitizers, and sinks) remains in :mod:`codexray.rule_model` and
the vulnerability-specific rules.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Iterable, Literal

from .call_arguments import ArgumentSelectorLike, parameter
from .rule_model import CallTarget, matches_target, resolve_qualified_name


CallOutput = Literal["return"]


@dataclass(frozen=True)
class CallModel:
    """Data-flow semantics for one explicitly modelled call target.

    ``input_selectors`` names the *parameters* whose states are candidates for
    the call's return value -- one entry per parameter, resolved through the
    shared :mod:`codexray.call_arguments` binder.  A plain int stays valid and
    means that positional index.  ``receiver_is_input`` independently includes
    the receiver of a method call; the receiver is not an argument selector.
    Only the ``return`` output is supported in this intraprocedural MVP.
    Sanitization is deliberately opt-in: arbitrary wrappers must not inherit a
    security-context marker.
    """

    target: CallTarget | str
    input_selectors: tuple[ArgumentSelectorLike, ...] = (0,)
    receiver_is_input: bool = False
    output: CallOutput = "return"
    preserves_taint: bool = True
    preserves_sanitization: bool = False

    @property
    def target_name(self) -> str:
        if isinstance(self.target, CallTarget):
            return self.target.qualified_name
        return self.target


class CallModelRegistry:
    """Registry for the finite set of explicitly modelled library calls."""

    def __init__(self, models: Iterable[CallModel] = ()):
        self._models = list(models)

    @property
    def models(self) -> tuple[CallModel, ...]:
        return tuple(self._models)

    def register(self, model: CallModel) -> None:
        self._models.append(model)

    def matching_models(self, node: ast.AST) -> tuple[CallModel, ...]:
        qname = resolve_qualified_name(node)
        if not qname:
            return ()

        matches: list[CallModel] = []
        for model in self._models:
            target = model.target
            target = target if isinstance(target, CallTarget) else CallTarget(target)
            if matches_target(qname, target):
                matches.append(model)
        return tuple(matches)

    def match(self, node: ast.AST) -> CallModel | None:
        """Return the first deterministic model matching ``node``."""
        matches = self.matching_models(node)
        return matches[0] if matches else None


DEFAULT_CALL_MODELS: tuple[CallModel, ...] = (
    CallModel(
        target=CallTarget(qualified_name="str"),
        input_selectors=(0,),
        preserves_taint=True,
        preserves_sanitization=False,
    ),
    CallModel(
        target=CallTarget(qualified_name="json.dumps"),
        input_selectors=(parameter(0, "obj"),),
        preserves_taint=True,
        preserves_sanitization=False,
    ),
    CallModel(
        target=CallTarget(qualified_name="len"),
        input_selectors=(0,),
        preserves_taint=False,
        preserves_sanitization=False,
    ),
    # Methods whose return value preserves the receiver's string value.
    *tuple(
        CallModel(
            target=CallTarget(qualified_name=name),
            input_selectors=(),
            receiver_is_input=True,
            preserves_taint=True,
            preserves_sanitization=False,
        )
        for name in (
            "getlist",
            "upper", "lower", "strip", "lstrip", "rstrip", "title",
            "capitalize", "casefold", "swapcase", "splitlines", "zfill",
            "expandtabs", "split", "rsplit", "encode", "decode",
            "removeprefix", "removesuffix", "ljust", "rjust", "center",
            "translate",
        )
    ),
    *tuple(
        CallModel(
            target=CallTarget(qualified_name=name),
            input_selectors=(parameter(1, "default"),),
            receiver_is_input=True,
            preserves_taint=True,
            preserves_sanitization=False,
        )
        for name in ("get", "pop", "setdefault")
    ),
    CallModel(
        target=CallTarget(qualified_name="replace"),
        input_selectors=(parameter(1, "new"),),
        receiver_is_input=True,
        preserves_taint=True,
        preserves_sanitization=False,
    ),
)


def default_call_model_registry() -> CallModelRegistry:
    """Create an isolated registry containing the approved default models."""
    return CallModelRegistry(DEFAULT_CALL_MODELS)
