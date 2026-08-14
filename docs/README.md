# Auth-Core Documentation

**Status:** Draft for stakeholder review

**Canonical product name:** Vittavaan

**System:** `auth-core` Authentication and User Management Engine

This directory is the source of truth for the planned `auth-core` platform. The documents describe what the system must do, how it will be structured, how it will be secured, how web and mobile clients will reuse the same services, and how the MVP will progress to AWS production.

No document in this review set represents a production certification. Security, privacy, and financial-industry claims must be independently validated before real customer or financial data is processed.

## Start Here

| Audience | Recommended document |
|---|---|
| Business stakeholders | [Project Overview](./product/project_overview.md) |
| Product and design | [Screen and Experience Inventory](./product/screen_inventory.md) |
| Engineers | [System Architecture](./architecture/system_architecture.md) |
| Security reviewers | [Security Architecture](./architecture/security_architecture.md) |
| API consumers | [API Contract](./specifications/auth-core_api_spec.md) |
| Database engineers | [Data Architecture](./architecture/data_architecture.md) |
| DevOps engineers | [Deployment Architecture](./architecture/deployment_architecture.md) |
| Project contributors | [Implementation Roadmap](./delivery/implementation_roadmap.md) |

## Documentation Catalog

### Product and Scope

- [Project Overview](./product/project_overview.md) - Plain-language purpose, users, outcomes, and boundaries.
- [Screen and Experience Inventory](./product/screen_inventory.md) - Existing wireframes, missing experiences, and approval rules.
- [Glossary](./product/glossary.md) - Plain-language definitions of security and platform terms.

### Requirements and Contracts

- [SRS v2.1](./specifications/auth_module_specification_v2.1.md) - Approved source requirements.
- [API Contract](./specifications/auth-core_api_spec.md) - Planned REST endpoints, headers, tokens, and errors.
- [Methods Inventory](./specifications/auth-core_methods_inventory.md) - Planned entity, control, and boundary operations.
- [Database and Redis Specification](./specifications/auth-core_db_schema.md) - Target data structures and retention rules.
- [Requirements Traceability](./specifications/requirements_traceability.md) - Use cases mapped to APIs, services, screens, and tests.
- [Specification Reconciliation](./specifications/specification_reconciliation.md) - Resolved gaps and decisions across the source blueprints.

### Architecture and Diagrams

- [System Architecture](./architecture/system_architecture.md) - Context, containers, EBC components, and dependency rules.
- [Data Architecture](./architecture/data_architecture.md) - PostgreSQL, Redis, audit, encryption, and ERD.
- [Security Architecture](./architecture/security_architecture.md) - Threat boundaries, controls, token security, and governance.
- [Client Reuse Strategy](./architecture/client_reuse_strategy.md) - Web-first delivery with future Expo mobile reuse.
- [Deployment Architecture](./architecture/deployment_architecture.md) - Local, free staging, and AWS production designs.
- [Technology Stack](./architecture/technology_stack.md) - MVP and production technologies and rationale.
- [System Sequence Diagrams](./use-cases/auth-core_sequence_diagram.md) - Time-ordered interaction flows.
- [Functional Flowcharts](./use-cases/auth-core_functional_flowchart.md) - Decision and execution flows.

### Delivery and Operations

- [Implementation Roadmap](./delivery/implementation_roadmap.md) - Milestones, deliverables, and acceptance gates.
- [Testing Strategy](./delivery/testing_strategy.md) - Unit, integration, contract, browser, mobile, and security testing.
- [Environment and Credentials](./operations/environment_and_credentials.md) - Tools, configuration, providers, and secrets.
- [Git and Documentation Workflow](./operations/git_and_documentation_workflow.md) - Branch, commit, review, and publishing rules.
- [AWS Production Readiness](./operations/aws_production_readiness.md) - Migration prerequisites and operational controls.

## Document Governance

1. Requirements, architecture, API contracts, and diagrams are reviewed before implementation.
2. Material changes require an Architecture Decision Record or specification revision.
3. OpenAPI will become the machine-readable API source of truth during implementation.
4. Documentation changes accompany the code that changes behavior.
5. Proposed UI screens or material wireframe changes require stakeholder permission before design work begins.
