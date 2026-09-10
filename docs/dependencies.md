# Runtime dependencies

- PostgreSQL is the authoritative store for customer, credential, consent, idempotency, and outbox state.
- Tenant Admin is called synchronously during registration to confirm tenant status and resolve immutable consent-document metadata.
- Argon2id is used for password hashing.
- Redis provides distributed login and PIN velocity limits in production. It is not authoritative for durable account lockout state.
- VerifyMe is the first external NIN/BVN verification provider behind the provider-neutral `KycProvider` boundary. Only redacted normalized results cross into persistent workflow state.
- RabbitMQ carries versioned notification requests through a durable quorum queue, manual acknowledgements, bounded delayed retries, and a dead-letter queue.
- Brevo sends transactional email, Termii sends SMS, and Firebase Admin sends FCM push messages. Provider credentials use environment/secret-manager injection and are never persisted or logged.

## Assumptions

- The Tenant Admin internal endpoints are reachable only on the private service network and require a short-lived service bearer token.
- Consent documents are immutable once published. Auth stores their external IDs and evidence metadata without a cross-service foreign key.
- Customer onboarding is progressive. Names may remain absent until profile completion or a later KYC/product eligibility gate requires them.
- Redis is deferred until an ephemeral-state use case exists; it is not a source of truth for registration or profile data.
- A-04 introduces Redis for velocity limits. Local tests use the equivalent in-memory adapter; production configuration requires Redis.
- A-05 also stores OTP delivery secrets encrypted with AES-256-GCM and a Redis TTL. PostgreSQL and RabbitMQ retain only keyed hashes and challenge references respectively.
- JOSE provides RS256 JWT signing and verification. Production injects the active private key and a `kid`-indexed public-key rotation set; private keys are never stored in PostgreSQL.
- Progressive KYC may start without profile names. Existing names are sent for provider matching; tenant/product eligibility may require profile completion independently.
- The A-09 bootstrap selects VerifyMe statically because it is the only enabled KYC provider in the first release. T-05 will supply the Tenant Admin-backed provider resolver and must never advertise an unavailable provider.
- A `PENDING` ambiguous provider result requires later inquiry or reconciliation. It is not automatically treated as a customer verification failure.
- Notification templates are tenant-overridable with global fallbacks. OTP templates resolve ephemeral codes from the encrypted TTL store and never persist rendered secrets.
- A-10 uses the existing notification/inbox tables plus approved `AUTH-DB-18` append-only per-target delivery attempts. Retention maintenance cannot remove legal-held records.
