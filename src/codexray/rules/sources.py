"""Source patterns shared by more than one rule."""

from codexray.rule_model import CallTarget, SourcePattern


FLASK_REQUEST_INPUT = SourcePattern(
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
)
