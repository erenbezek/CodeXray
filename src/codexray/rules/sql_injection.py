"""SQL Injection kurali (CWE-89) -- motorun pilot kurali.

Yeni bir kategori eklerken bu dosya sablon olarak kullanilabilir:
sources / sanitizers / sinks tanimla, geri kalanini RuleEngine ve
TaintAnalyzer zaten cozuyor.
"""

from codexray.rule_model import (
    CallTarget,
    Rule,
    SanitizerPattern,
    SinkPattern,
)
from codexray.rules.sources import FLASK_REQUEST_INPUT

SQL_INJECTION_RULE = Rule(
    id="sql-injection",
    cwe="CWE-89",
    severity="CRITICAL",
    sources=(FLASK_REQUEST_INPUT,),
    sanitizers=(
        SanitizerPattern(
            id="sql-escape",
            sanitizes_for=("sql",),
            targets=(CallTarget(qualified_name="escape_sql"),),
        ),
    ),
    sinks=(
        SinkPattern(
            id="sqlite-cursor-execute",
            targets=(CallTarget(qualified_name="cursor.execute", module="sqlite3"),),
            dangerous_arguments=(0,),
            requires_sanitization_for=("sql",),
        ),
    ),
)
