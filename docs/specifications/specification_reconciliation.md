# Specification Reconciliation Register

## Purpose

The original SRS, sequence diagrams, methods inventory, database blueprint, API notes, functional flowchart, and wireframes were created at different levels of detail. This register records how the consolidated documentation resolves gaps without silently rewriting the approved business intent.

## Resolution Rules

1. The SRS use-case behavior and security intent take precedence over abbreviated examples.
2. The API contract defines external behavior; internal method names may evolve.
3. Durable state needed for security evidence is stored in PostgreSQL, not only Redis.
4. Sensitive workflow examples are hardened when the original model could not satisfy its own requirement.
5. Vittavaan is canonical; GroX remains only in the supplied visual reference until approved assets are revised.

## Reconciled Items

| Topic | Source gap or conflict | Consolidated decision |
|---|---|---|
| Product name | Wireframes use GroX; SRS and repository use Vittavaan. | Vittavaan is canonical across code, claims, URLs, and future UI revisions. |
| API coverage | Initial API notes specify a small subset of 30+ use cases. | Expanded endpoint inventory covers registration, federation, MFA, sessions, tenancy, governance, and privacy. |
| Refresh replay | Original table stores only current refresh hash, making old valid generations indistinguishable. | Store every generation hash and consumption state; replay revokes the family atomically. |
| Organizations | SRS includes invitations and permission catalog; initial DDL omits them. | Add invitations and canonical role/permission catalog tables. |
| Four-eyes reset | Methods require a durable delayed approval; initial DDL has no request table. | Add governed requests with initiator, distinct approver, execute-after, and worker execution. |
| Session scoping | Organization offboarding requires tenant-scoped revocation; original session lacks organization/JTI detail. | Add active organization, access JTI, activity, and revocation timestamps. |
| Passkeys | MFA record is insufficient for complete WebAuthn metadata. | Add dedicated WebAuthn credential fields/table and Redis challenges. |
| Audit WORM | Trigger alone is not full WORM storage. | Combine database privileges/trigger with production immutable export after retention approval. |
| RLS | Database overview claims RLS but initial DDL defines no policies. | Document transaction-local tenant context, policies, dedicated roles, and direct isolation tests. |
| Asynchronous work | Email, delayed reset, privacy export, and cleanup need reliable execution. | Add transactional outbox and worker; map to SQS/EventBridge in AWS. |
| Client handling | Web/mobile target exists but shared contract and storage differences are not explicit. | One headless API and generated SDK; cookie/CSRF for web, Keychain/Keystore bearer flow for mobile. |
| MFA reset delay | “Approve after cooldown” wording could imply approval itself must wait. | Approval may occur earlier, but execution cannot occur before 12-hour execute-after and is revalidated. |
| Device fingerprint | Mandatory header could be treated as trusted identity. | Treat as privacy-reviewed risk input only; never sole proof or authorization. |
| GDPR backup purge | Application cannot mutate immutable managed backups directly. | Anonymize live data and enforce approved snapshot retention/expiry operationally. |
| Staging providers | Hosting and integration vendors were unspecified. | Render + Neon + Upstash + Resend/Twilio/Turnstile/OIDC sandbox adapters; no production data. |
| AWS target | “AWS/Vault” alternatives were unresolved. | Production defaults to AWS ECS, RDS, ElastiCache, KMS, Secrets Manager, SES/SNS, WAF, CloudWatch. |

## Decisions Requiring Later Approval

- Production SLO, RTO, and RPO values.
- Legal retention durations and jurisdictions.
- Aurora versus standard RDS PostgreSQL.
- SNS versus another production SMS provider.
- Exact external risk-intelligence service.
- New and materially changed web/mobile wireframes.
- Go verifier deployment as standalone service, sidecar, gateway integration, or reusable library after performance testing.
