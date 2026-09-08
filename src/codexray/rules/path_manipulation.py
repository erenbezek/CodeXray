"""Path Manipulation rule for Python + Flask (CWE-22)."""

from codexray.call_arguments import parameter
from codexray.rule_model import (
    CallTarget,
    Rule,
    SanitizerPattern,
    SinkPattern,
)
from codexray.rules.sources import FLASK_REQUEST_INPUT


PATH_MANIPULATION_RULE = Rule(
    id="path-manipulation",
    cwe="CWE-22",
    severity="HIGH",
    sources=(FLASK_REQUEST_INPUT,),
    sanitizers=(
        SanitizerPattern(
            id="safe-basename",
            sanitizes_for=("path",),
            targets=(
                CallTarget(qualified_name="secure_filename"),
                CallTarget(qualified_name="os.path.basename"),
            ),
            input_selectors=(parameter(0, "filename"),),
        ),
    ),
    sinks=(
        SinkPattern(
            id="fs-open",
            targets=(CallTarget(qualified_name="open"),),
            dangerous_arguments=(parameter(0, "file"),),
            requires_sanitization_for=("path",),
        ),
        SinkPattern(
            id="flask-send-file",
            targets=(CallTarget(qualified_name="send_file"),),
            dangerous_arguments=(parameter(0, "path_or_file"),),
            requires_sanitization_for=("path",),
        ),
        SinkPattern(
            id="flask-send-from-directory",
            targets=(CallTarget(qualified_name="send_from_directory"),),
            dangerous_arguments=(parameter(1, "path"),),
            requires_sanitization_for=("path",),
        ),
    ),
)
