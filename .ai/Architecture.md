# Architecture Principles

Purpose:

This document contains architecture decision-making principles.

Use it when introducing new components, modifying system boundaries, changing service interactions, or evaluating long-term maintainability.

---

## Start From The Data Flow

Before proposing architecture:

Identify:

* Inputs
* Outputs
* State
* External dependencies

Describe:

* Where data originates
* Where data is transformed
* Where data is stored
* Where data leaves the system

Architecture diagrams should follow data flow before module hierarchy.

---

## Optimize For Change

Good architecture makes future changes cheaper.

Prefer designs that:

* Localize change
* Reduce coupling
* Isolate failure domains

Do not optimize for hypothetical future requirements.

---

## Separate By Reason To Change

Split components when they change for different reasons.

Avoid splitting solely because:

* Files are large
* Layers are fashionable
* Microservices are popular

A boundary should exist because it protects independent evolution.

---

## Dependencies Must Flow Inward

Business rules should not depend on infrastructure.

Prefer:

```
    Domain
        ↓
    Interface
        ↓
    Infrastructure
```

Over:

```
    Domain
        ↓
    Database
        ↓
    Framework
```

Frameworks are tools, not architecture.

---

## Minimize Irreversible Decisions

Treat these as expensive decisions:

* Service boundaries
* Database engines
* Public APIs
* Network protocols

Design carefully before committing.

Prefer reversible decisions whenever possible.

---

## Design For Observability

Every important workflow should be observable.

Systems should answer:

* What happened?
* When did it happen?
* Why did it happen?
* Who initiated it?

Logs, metrics, and traces are architecture concerns.

Not operational afterthoughts.

---

## Architecture Before Optimization

Do not introduce:

* Caches
* Queues
* Event buses
* Distributed systems

Without evidence.

Solve correctness first.

Optimize after measurement.

---

## Critical Path Protection

Identify the critical user journeys.

Protect them from:

* Large refactors
* Experimental features
* Complex dependencies

Always have a rollback strategy for critical paths.
