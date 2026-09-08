"""Sensitive Data Exposure rule for Python + Flask (CWE-200)."""

from codexray.call_arguments import parameter
from codexray.rule_model import (
    CallTarget,
    Rule,
    SinkPattern,
    SourcePattern,
)


SENSITIVE_DATA_RULE = Rule(
    id="sensitive-data-exposure",
    cwe="CWE-200",
    severity="MEDIUM",
    sources=(
        SourcePattern(
            id="secret-value",
            kind="sensitive",
            targets=(
                CallTarget(qualified_name="password"),
                CallTarget(qualified_name="secret"),
                CallTarget(qualified_name="api_key"),
                CallTarget(qualified_name="token"),
                CallTarget(qualified_name="api_token"),
                CallTarget(qualified_name="private_key"),
                # Django ve Flask konfigurasyon sabitleri konvansiyon geregi
                # BUYUK harflidir; eslestirme buyuk/kucuk harf duyarli oldugu
                # icin varyantlar ayrica sayilir.  Genel cozum (bu source
                # ailesi icin duyarsiz eslestirme) matches_target'i ve dolayisiyla
                # her kurali etkiler -- ayri bir karar.
                CallTarget(qualified_name="PASSWORD"),
                CallTarget(qualified_name="SECRET"),
                CallTarget(qualified_name="API_KEY"),
                CallTarget(qualified_name="TOKEN"),
                CallTarget(qualified_name="API_TOKEN"),
                CallTarget(qualified_name="PRIVATE_KEY"),
                CallTarget(qualified_name="SECRET_KEY"),
                CallTarget(qualified_name="DATABASE_PASSWORD"),
                CallTarget(qualified_name="os.environ"),
                CallTarget(qualified_name="os.getenv"),
                CallTarget(qualified_name="getpass.getpass"),
            ),
        ),
    ),
    sanitizers=(),
    sinks=(
        SinkPattern(
            id="console-or-log",
            targets=(
                CallTarget(qualified_name="print"),
                CallTarget(qualified_name="logging.debug"),
                CallTarget(qualified_name="logging.info"),
                CallTarget(qualified_name="logging.warning"),
                CallTarget(qualified_name="logging.error"),
                CallTarget(qualified_name="logging.exception"),
                CallTarget(qualified_name="logging.critical"),
            ),
            dangerous_arguments=(0,),
        ),
        SinkPattern(
            id="http-response",
            targets=(
                CallTarget(qualified_name="Response"),
                CallTarget(qualified_name="make_response"),
            ),
            dangerous_arguments=(parameter(0, "response"),),
        ),
    ),
)
