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
            # Hedef `cursor.execute` degil `execute`: nitelikli-ad suffix
            # eslestirmesi cursor degiskeninin ADINDAN bagimsiz calissin diye.
            # Olculdu -- `cursor.execute` hedefiyle `c.execute`, `cur.execute`,
            # `db.execute` ve `conn.execute` hicbiri eslesmiyordu; gercek kod
            # bu adlari kullaniyor.
            targets=(
                CallTarget(qualified_name="execute", module="sqlite3"),
                CallTarget(qualified_name="executemany", module="sqlite3"),
            ),
            dangerous_arguments=(0,),
            requires_sanitization_for=("sql",),
        ),
    ),
)
