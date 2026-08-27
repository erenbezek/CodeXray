# CodeXray — Agent Workflow

## Purpose

This document defines how an agent should work on the CodeXray repository.

The agent is an implementer, reviewer, researcher, or tester. It is not the project owner.

## Before Starting

1. Read `AGENTS.md`.
2. Read `docs/current-state.md`.
3. Read `docs/project-context.md`.
4. Read relevant entries in `docs/design-decisions.md`.
5. Inspect the files directly related to the assigned task.
6. Run the existing test suite before making changes.

## Understand the Scope

Before changing code, identify:

- What the task is.
- Which files should be affected.
- Which architectural rules apply.
- What is explicitly outside the task.

Do not expand the scope without an explicit decision.

## Implementation Rules

- Prefer small, focused changes.
- Keep security-rule-specific logic out of the core taint traversal.
- Prefer adding or modifying a rule over hardcoding vulnerability-specific logic into the engine.
- Preserve the immutable `TaintState` model.
- Preserve the MVP's intra-procedural scope unless the task explicitly changes it.
- Do not replace semantic analysis with regex-based vulnerability detection.
- Avoid unrelated refactors.

## Testing

Before making changes:

```text
Run the existing tests.
```

After making changes:

```text
Run the full test suite again.
```

A task is not complete if existing behavior regresses.

When adding new behavior, add tests that demonstrate:

- The new behavior works.
- Existing behavior still works.
- Relevant safe cases remain safe.
- Relevant vulnerable cases are detected.

## Architecture Changes

If the implementation appears to require changing the core architecture:

1. Stop and identify the architectural reason.
2. Explain why the existing abstraction is insufficient.
3. Check `docs/design-decisions.md`.
4. Propose the smallest architectural change that solves the problem.
5. Do not silently introduce a new architectural direction.

## Git Workflow

Agents should normally work on a feature branch rather than directly on `main`.

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

Do not assume that a technically working change should automatically be merged.

## Completion Report

At the end of the task, report:

### Changed

List the files changed and briefly explain what changed.

### Tests

Report the exact test command used and the result.

Example:

```text
pytest
15 passed
```

### Architecture Impact

State one of:

- None
- Minor
- Significant

If not `None`, explain why.

### New Decisions

List any new architectural or behavioral decision introduced by the work.

### Known Limitations

List anything intentionally left incomplete or any limitation introduced by the implementation.

## When Unsure

Do not silently guess about:

- Project scope
- Architecture
- Security semantics
- Rule behavior
- Whether a limitation should be removed

State the uncertainty and propose an option.

## Project Owner

The human project owner has final authority over:

- Scope
- Architecture
- Milestones
- Acceptance of changes
- Merging changes

An agent may recommend changes but must not treat its own recommendation as an approved architectural decision.
