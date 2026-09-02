# Database Principles

Purpose:

This document contains data modeling and persistence principles.

Use it when designing schemas, queries, migrations, indexes, and storage strategies.

---

## Model Reality First

Design tables around business concepts.

Not screens.

Not API responses.

Not ORM convenience.

Ask:

"What real-world thing does this represent?"

---

## Data Lives Longer Than Code

Code can be rewritten.

Data usually cannot.

Schema changes are expensive.

Prefer:

* Stable structures
* Explicit migrations
* Backward compatibility

Treat schema changes as architecture changes.

---

## Normalize Until It Hurts

Start normalized.

Denormalize only when:

* Measurement shows a bottleneck
* Simplicity improves
* Read patterns justify duplication

Never duplicate data without ownership rules.

---

## Design For Queries

Before creating a table:

Identify:

* Reads
* Writes
* Filters
* Aggregations

A schema exists to support access patterns.

Not to satisfy aesthetics.

---

## Every Relationship Must Have Ownership

For every relationship:

Define:

* Owner
* Lifecycle
* Deletion behavior

Questions to answer:

* Who creates it?
* Who updates it?
* Who deletes it?

If ownership is unclear, the model is incomplete.

---

## Soft Delete Is Not Free

Soft delete increases complexity.

Before introducing it:

Ask:

* Is recovery required?
* Is auditing required?
* Is compliance required?

Prefer hard delete when recovery is unnecessary.

---

## Indexes Are Contracts

Indexes improve reads.

Indexes slow writes.

Every index should have a known purpose.

If no query depends on an index:

Remove it.

---

## Avoid Database Magic

Prefer explicit application logic.

Be cautious with:

* Triggers
* Stored procedures
* Hidden side effects

Business rules should be visible and testable.

---

## Measure Before Optimizing

Do not optimize based on intuition.

Measure:

* Query latency
* Row counts
* Table growth
* Index effectiveness

Evidence before optimization.
