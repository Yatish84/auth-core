# AWS Production Readiness

## Purpose

This checklist governs the transition from the low-cost demonstration environment to a production environment suitable for real Vittavaan users. Passing staging tests does not imply production readiness.

## Account and Governance

- AWS Organizations account structure for production, non-production, logging, and security.
- IAM Identity Center, MFA, least privilege, break-glass process, and access reviews.
- GitHub OIDC deployment roles with environment approvals.
- Cost budgets, anomaly detection, tagging, and owner contacts.
- Approved regions and data-residency/legal review.

## Network and Edge

- VPC across multiple availability zones.
- Private subnets for ECS tasks, RDS, and ElastiCache.
- Restricted security groups and controlled egress.
- Route 53, ACM TLS, CloudFront, AWS WAF, Shield baseline, and rate-based rules.
- No public database or Redis endpoints.

## Compute and Supply Chain

- ECS Fargate services with autoscaling, health checks, deployment circuit breaker, and immutable image digests.
- ECR scanning, SBOMs, signed provenance, minimal non-root images, and read-only filesystems where possible.
- Separate API, verifier, and worker task roles.
- Capacity, timeout, retry, and graceful-shutdown tests.

## Data and Cryptography

- RDS PostgreSQL/Aurora multi-AZ, encryption, backups, PITR, maintenance windows, and parameter review.
- ElastiCache TLS/auth, subnet isolation, failover, memory and eviction policy review.
- KMS keys with rotation, separation of signing/encryption purposes, and tightly scoped grants.
- Secrets Manager rotation and no static credentials in task definitions.
- S3 Object Lock or equivalent approved immutable audit retention.

## Messaging and Integrations

- SES domain verification, SPF, DKIM, DMARC, bounce/complaint handling, and production access.
- SNS or approved SMS provider with spend limits, regional compliance, consent, and fraud monitoring.
- Production OIDC applications and verified redirect domains.
- Provider outage, retry, idempotency, and circuit-breaker policies.

## Monitoring and Incident Response

- CloudWatch dashboards, alarms, structured logs, metrics, traces, and redaction tests.
- Alerts for token replay, account attacks, admin actions, provider failures, queue backlog, database pressure, and key lifecycle.
- Central security logging, GuardDuty/Security Hub integration as approved.
- On-call ownership, severity model, incident runbooks, and evidence preservation.
- Key compromise, credential leak, account takeover, and mass revocation procedures.

## Reliability and Recovery

- Business-approved SLOs, RTO, and RPO.
- Restore tests from backups, not merely backup-success indicators.
- Database migration rollback/forward-fix rehearsal.
- Queue replay and idempotency validation.
- Region and availability-zone failure analysis.
- Documented degraded behavior when Redis or providers are unavailable.

## Security, Privacy, and Launch Gates

- Independent penetration test and threat-model sign-off.
- RLS and cross-tenant authorization review.
- Privacy impact assessment, retention schedule, data-processing agreements, and legal approval.
- Accessibility and customer-support readiness.
- Load/capacity test and cost model.
- Production smoke test, rollback plan, and executive launch approval.
