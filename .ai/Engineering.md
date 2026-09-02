# Engineering Principles

Purpose:

This document contains engineering decision-making principles.

It does not define project workflow.

Workflow (Grill, Spec, Tickets, Review, etc.) should be handled by dedicated skills.

Use these principles when making implementation, testing, architecture, refactoring, and maintenance decisions.

---

## Start Small

Price the change, not the typing.

Consider:

* Data migrations
* Public APIs
* External integrations
* Rollback difficulty
* Operational risk
* Incident potential

Guidelines:

* Cheap to undo → implement something small that runs.
* Expensive to undo → design first.
* Do not treat a generated plan as complete.
* Name at least one thing the plan cannot know.
* Do not spend multiple iterations polishing a specification before implementation starts.

Persist specifications only when:

* Future work depends on them
* Audit requirements exist
* Contracts require them
* Handoffs require them

When recording decisions:

Prefer documenting:

* Why

Over documenting:

* How

---

## When Stuck

Identify the failure mode before acting.

### Code Is Fighting Back

Symptoms:

* Fixing A breaks B
* Repeated edit loops
* Increasing complexity
* Growing frustration

Do:

* Stop adding new work
* Simplify only the files involved
* Re-run the original task

Do not:

* Add more prompt rules
* Rewrite unrelated modules
* Refactor the entire repository

### Context Is Contaminated

Symptoms:

* Old topics leak into new work
* Corrections stop working
* The conversation becomes noisy

Do:

* Start a fresh context
* Bring only the facts required

Do not:

* Continue arguing with old context
* Stack corrective instructions indefinitely

Before blaming code quality:

Rule out:

* Tool failures
* Permission failures
* Wrong-file edits
* Environment problems

---

## Checks Over Instructions

Prefer:

* Formatters
* Linters
* Type systems
* Tests

Over:

* Additional instructions

Checks are exit conditions.

Do not replace verification with explanation.

Continue until:

* Checks pass
* Or a real blocker is identified

Verification mechanisms may include:

* Automated tools
* Fresh review passes
* Human review

Coverage is not quality.

A better question is:

"If this breaks, will a test notice?"

Calibrate quality gates for this repository.

Do not increase process merely because alerts exist.

Do not assume agreement from a model is evidence.

---

## Structure

Understand the existing structure before changing it.

Report:

* What exists
* Dependencies
* Usage relationships

Do not repartition modules unless requested.

If restructuring is requested:

1. Describe the current structure.
2. Propose a change.
3. Wait for confirmation.
4. Implement.

Dependency direction is a design tool.

When dependencies become problematic:

* Invert dependencies
* Introduce interfaces
* Split modules

If a module cannot be described clearly in one sentence:

Consider splitting it.

Names are not guarantees.

Do not trust a module merely because its name sounds correct.

---

## Split Work Only When It Pays

Split work only when it provides a clear benefit.

Valid reasons:

* Smaller context
* Parallel execution

Invalid reasons:

* More specialization
* More roles
* More process

Prefer one responsibility per working context.

Use fresh contexts to:

* Review
* Harden
* Verify

Hand off artifacts, not conversations.

Avoid multi-agent pipelines for trivial changes.

---

## Understand Human Practices Before Copying Them

Before adopting a process, ask:

"What human limitation is this compensating for?"

Examples:

### Memory

Keep:

* Verification goals

Not necessarily:

* Human execution order

### Fatigue

Keep:

* Reliability requirements

Not necessarily:

* Human workflows

### Typing Speed

Keep:

* Desired outcome

Not necessarily:

* Human mechanics

### Code Quality

Keep:

* The property being protected

Prefer:

* Automated enforcement

Over:

* Ritualized process

If humans remain involved, their constraints still matter.

Do not remove a practice without understanding why it exists.
