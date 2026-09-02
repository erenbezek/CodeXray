# CodeXray — Current State

## Current Milestone

**M5.5 — Motor sağlamlaştırma (parameter modeli + konsolidasyon)**

## Working

- Python AST parsing
- `TaintState`
- `TaintAnalyzer`
- `RuleEngine`
- `RuleMatch`
- Intra-procedural taint propagation
- Variable assignment propagation
- Multi-hop propagation
- `BinOp` propagation
- Python f-string (`JoinedStr`) propagation
- Source detection
- Sanitizer handling
- Sink detection
- Taint path generation
- CWE / severity metadata
- SQL Injection rule
- Reflected/server-side XSS rule (Python + Flask)
- Generic `CallModel` / `CallModelRegistry` (explicit call-return propagation)
- Shared call-argument binding (parametre başına tek selector, pozisyonel + keyword)
- Vulnerable / safe examples
- Automated tests
- GitHub Actions CI (`.github/workflows/ci.yml`)

## Test Status

67 passed

## Current SQL Injection Flow

request.args["username"]
        ↓
     username
        ↓
      query
        ↓
cursor.execute(query)

If tainted data reaches the SQL sink without the required SQL sanitization:

Finding → CWE-89

## Current Architecture

Python Source Code
        ↓
       AST
        ↓
 TaintAnalyzer
        ↓
    TaintState
        ↓
    RuleEngine
        ↓
Source / Sanitizer / Sink
        ↓
     Finding

## Important Components

### `src/codexray/rule_model.py`

Contains:

- `Rule`
- `SourcePattern`
- `SanitizerPattern`
- `SinkPattern`
- `RuleMatch`
- `RuleEngine`
- Qualified-name resolution and matching

### `src/codexray/call_arguments.py`

Contains:

- `ArgumentSelector`
- `parameter()` / `positional()` / `keyword()` selector constructors
- `CallArgumentBinder`

Resolves an `ast.Call`'s arguments through one shared abstraction, used by the
`CallModel`, sink, and sanitizer layers alike. One selector names one
*parameter*, which may be addressable positionally, by keyword, or both.

### `src/codexray/call_model.py`

Contains:

- `CallModel`
- `CallModelRegistry`
- The default set of explicitly modelled library calls

### `src/codexray/taint_engine.py`

Contains:

- `TaintState`
- `Finding`
- `TaintAnalyzer`
- Taint propagation
- Sanitizer handling
- Sink checking
- Taint path generation

### `rules/`

Contains vulnerability-specific rules.

Currently implemented:

- SQL Injection
- XSS (reflected/server-side)

### `tests/`

Contains automated tests for:

- Rule matching
- Taint propagation
- Source detection
- Sanitizer behavior
- Sink detection
- SQL Injection behavior
- XSS behavior

### `examples/`

Contains vulnerable and safe example Python code.

## Not Implemented Yet

- CLI scanner
- Path Manipulation
- Sensitive Data Exposure
- AST structural rules
- Presence-check rules
- Dependency scanning
- Inter-procedural analysis
- Control-flow analysis
- Type inference
- Multi-source provenance
- `UNKNOWN` taint state
- LLM triage

## Important Architectural Rules

- Keep security-rule-specific logic out of the taint traversal.
- Prefer adding a new `Rule` over modifying the core engine.
- Keep `TaintState` immutable.
- MVP remains intra-procedural.
- Do not introduce regex-based vulnerability detection as the primary matching mechanism.
- Do not expand project scope without an explicit architectural decision.
- Existing behavior must remain covered by tests.

## Current Limitations

### Qualified-name matching

The MVP does not perform full type inference.

Different objects with similarly named methods may therefore be matched by the same qualified-name heuristic.

### Single-source provenance

When multiple tainted values are merged, provenance is currently simplified to one primary source.

### Unsupported AST expressions

Unsupported expression types may currently be treated as clean.

### No control-flow analysis

Branches and multiple execution paths are not fully modeled.

### No inter-procedural propagation

Taint is currently tracked within a function and is not propagated across function boundaries.

## M5 Milestone Completion

**XSS (reflected/server-side)**

### Goal

Add the first additional taint-based vulnerability rule without introducing SQL-specific logic into the core taint engine.

### Definition of Done

- XSS rule exists
- Source / sanitizer / sink definitions remain separate from traversal logic
- Existing SQL Injection tests remain green
- XSS tests are added
- `pytest` passes
- No unnecessary core-engine changes are introduced

## Current Project Status

CodeXray currently has a working intra-procedural taint-analysis core with functioning SQL Injection and reflected/server-side XSS rules.

It is not yet a complete SAST tool.

The current focus is to validate that the taint engine can support additional vulnerability rules without requiring rule-specific changes to the core engine.
