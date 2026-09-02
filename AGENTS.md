# CodeXray — Agent Instructions

## 1. Read Before Working

Before changing anything:

1. Read `README.md`.
2. Read `AGENTS.md`.
3. Read `docs/current-state.md`.
4. Read `docs/project-context.md`.
5. Read relevant sections of `docs/design-decisions.md`.
6. Inspect the code and tests related to the task.

Do not rely on assumptions when the repository can answer the question.

## 2. Project Scope

Current MVP:

- Python
- AST-based static analysis
- Intra-procedural taint tracking
- Rule-based vulnerability detection

Current working vulnerability rules:

- SQL Injection
- Reflected/server-side XSS

Do not introduce inter-procedural analysis, control-flow analysis, type inference, or other major scope expansions unless explicitly requested.

## 3. Core Architecture Rules

- Keep security-rule-specific logic out of the core taint traversal.
- Prefer adding or modifying a `Rule` instead of hardcoding vulnerability logic into `TaintAnalyzer`.
- Keep `TaintState` immutable.
- Preserve the distinction between source, sanitizer, and sink.
- Preserve context-specific sanitization such as `sanitized_for`.
- Do not replace semantic analysis with regex-based vulnerability detection as the primary mechanism.
- Avoid unrelated refactors.

## 4. Change Discipline

Before modifying code:

- Identify the smallest set of files required.
- Identify existing behavior that must remain unchanged.
- Check relevant tests and design decisions.

When changing architecture:

- Explain why the existing abstraction is insufficient.
- Propose the smallest necessary change.
- Update the relevant documentation.
- Add or update tests.

Do not silently change architectural direction.

## 5. Testing Requirements

Run the existing test suite before implementation.

Run the full test suite again after implementation.

New behavior should have tests covering:

- expected vulnerable behavior
- expected safe behavior
- relevant edge cases

Do not consider a task complete if existing tests regress.

## 6. Security Rule Development

A new vulnerability rule should normally be implemented through the rule system.

The preferred structure is:

```text
Rule
├── sources
├── sanitizers
└── sinks
```

Do not add vulnerability-specific conditions such as:

```python
if function_name == "some_specific_sink":
```

inside the generic taint traversal when the rule system can express the behavior.

## 7. Current MVP Limitations

The following limitations are intentional unless a task explicitly changes them:

- No inter-procedural taint propagation
- No full control-flow analysis
- No full type inference
- Simplified multi-source provenance
- No explicit `UNKNOWN` taint state
- Qualified-name matching is heuristic

Do not "fix" these limitations incidentally while implementing another task.

## 8. Git Workflow

Prefer working on a feature branch.

Recommended flow:

```text
main
  ↓
feature branch
  ↓
implementation
  ↓
tests
  ↓
review
  ↓
pull request
  ↓
human approval
  ↓
merge
```

Do not assume that a successful implementation should be merged automatically.

## 9. Required Completion Report

At the end of a task, report:

### Changed

Files changed and what changed.

### Tests

Exact test command and result.

### Architecture Impact

One of:

- None
- Minor
- Significant

Explain any non-trivial impact.

### New Decisions

Any new architectural or behavioral decision introduced.

### Known Limitations

Anything intentionally incomplete or uncertain.

## 10. Project Owner

The human project owner has final authority over:

- scope
- architecture
- milestones
- acceptance criteria
- merge decisions

Agents may recommend changes, but must not treat recommendations as approved decisions.

When uncertain, stop and explain the uncertainty rather than silently expanding scope.
