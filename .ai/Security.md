# Security Principles

Purpose:

This document contains security decision-making principles.

Use it when designing authentication, authorization, networking, storage, APIs, and deployment strategies.

---

## Security Is A Design Property

Security is not a final review step.

Consider security during:

* Architecture
* Data modeling
* API design
* Deployment

Not after implementation.

---

## Least Privilege

Every component should have only the permissions it needs.

Apply to:

* Users
* Services
* Databases
* APIs
* Infrastructure

Default deny.

Grant explicitly.

---

## Reduce Attack Surface

Prefer fewer:

* Open ports
* Public endpoints
* Credentials
* Dependencies

Every exposed surface becomes a maintenance burden.

---

## Trust Boundaries Must Be Explicit

Identify:

* Internet
* Browser
* Client
* API
* Internal services
* Database

Never assume trust crosses boundaries automatically.

Validate at every boundary.

---

## Authentication And Authorization Are Different

Authentication:

```
    Who are you?
```

Authorization:

```
    What may you do?
```

Treat them separately.

Never assume authentication implies authorization.

---

## Secrets Must Not Be Code

Never store secrets in:

* Source code
* Repositories
* Images
* Documentation

Prefer:

* Environment variables
* Secret managers
* Dedicated credential systems

---

## Encrypt In Transit

Use TLS by default.

Protect:

* User traffic
* Service-to-service traffic
* Administrative access

Avoid plaintext protocols unless explicitly justified.

---

## Assume Compromise

Design as if a component can fail.

Ask:

* What can an attacker access?
* How far can they move?
* What limits the blast radius?

Containment is as important as prevention.

---

## Audit Security Decisions

For important security controls:

Record:

* Threat
* Mitigation
* Tradeoff

Future maintainers should understand why a control exists.

---

## Simplicity Improves Security

Complex systems are harder to secure.

Prefer:

* Fewer dependencies
* Smaller attack surfaces
* Simpler designs

Complexity should require justification.
