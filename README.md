# `auth-core` Engine — Vittavaan Platform

Centralized identity provider, session management engine, and access control library for the **Vittavaan** financial platform.

## 🏰 Architectural Vision: The Security Gatehouse
`auth-core` serves as the centralized gatekeeper for the broader platform ecosystem:
* **The Compound:** Downstream business modules (*WealthOS*, *LoanDesk*, *BusinessLedger*, *Insights*).
* **The Gatehouse (`auth-core`):** Validates identities, checks security risk levels, enforces MFA, and issues verified, short-lived access passes (JWTs).
* **Zero-Trust Downstream:** Downstream microservices do not handle credentials or MFA; they statelessly verify incoming JWT passes issued by `auth-core`.

## 📌 Documentation Index
* 📖 [Module Specification v2.1.0](./docs/specifications/auth_module_specification_v2.1.md)
* 🔄 [UC-101: Password Authenticate Sequence Diagram](./docs/use-cases/primary_auth_flows/UC-101.md)

## 🛠️ Technology Stack
* **API Gateway & Core Logic:** Python (FastAPI)
* **High-Throughput Verification:** Go (Golang)
* **Identity Store:** PostgreSQL
* **Caching & Ephemeral State:** Redis