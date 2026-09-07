"""Reflected/server-side XSS rule for Python + Flask (CWE-79).

The rule deliberately contains only source, sanitizer, and sink patterns.
Taint propagation and finding generation remain in the generic analyzer.
"""

from codexray.call_arguments import parameter
from codexray.rule_model import (
    CallTarget,
    Rule,
    SanitizerPattern,
    SinkPattern,
    SourcePattern,
)


XSS_RULE = Rule(
    id="xss",
    cwe="CWE-79",
    severity="HIGH",
    sources=(
        SourcePattern(
            id="flask-request-input",
            kind="user-input",
            targets=(
                CallTarget(qualified_name="request.args"),
                CallTarget(qualified_name="request.form"),
                CallTarget(qualified_name="request.values"),
                CallTarget(qualified_name="request.json"),
                CallTarget(qualified_name="request.cookies"),
                CallTarget(qualified_name="request.headers"),
                CallTarget(qualified_name="request.data"),
                CallTarget(qualified_name="request.files"),
                CallTarget(qualified_name="request.get_json"),
            ),
        ),
    ),
    sanitizers=(
        SanitizerPattern(
            id="html-text-escape",
            sanitizes_for=("html-text",),
            targets=(
                CallTarget(qualified_name="html.escape"),
                CallTarget(qualified_name="markupsafe.escape"),
                CallTarget(qualified_name="Markup.escape"),
            ),
            # Tek parametre: uc hedefin de ilki `s`, pozisyonel veya keyword.
            input_selectors=(parameter(0, "s"),),
        ),
    ),
    sinks=(
        SinkPattern(
            id="flask-html-response",
            targets=(
                CallTarget(qualified_name="Response"),
                CallTarget(qualified_name="make_response"),
                CallTarget(qualified_name="Markup"),
            ),
            # Tek parametre: Response icin `response`, digerleri icin pozisyonel.
            dangerous_arguments=(parameter(0, "response"),),
            requires_sanitization_for=("html-text",),
        ),
    ),
)
