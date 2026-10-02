# Parc Auth & Customer

Plain Express and strict TypeScript service responsible for customer identities, credentials, sessions, customer profiles, KYC workflow references, consent, trusted devices, notification preferences, and identity-related fraud signals.

Administrator identities remain in Tenant Admin. This service verifies administrators through Tenant Admin's synchronous internal API and issues the platform JWTs.

## Commands

```bash
yarn install --frozen-lockfile
yarn dev
yarn validate
yarn start
```

`GET /health` is process liveness. `GET /ready` is dependency readiness.

The A-03 customer lifecycle provides:

- `POST /v1/customers/register` for tenant-validated, idempotent progressive registration;
- `GET /v1/customers/me` for the authenticated customer profile; and
- `PATCH /v1/customers/me` for idempotent profile enrichment.

Registration requires Tenant Admin to confirm that the tenant is active and that every submitted consent ID identifies an active immutable document belonging to that tenant. First and last names are intentionally nullable until later profile-completion or product/KYC gates. Passwords are Argon2id hashes; idempotency request fingerprints are keyed HMACs.

JWT issuance and cryptographic access-token verification arrive in A-06. Until then, the profile routes use the `AccessTokenVerifier` boundary and the production bootstrap rejects bearer tokens rather than trusting gateway-added identity headers.

Redis is not required by A-03: PostgreSQL owns durable registration idempotency and customer state. Redis is reserved for ephemeral OTP, passkey/challenge, and rate-limit state in the relevant authentication phases.

The A-04 authentication slice adds enumeration-resistant phone/email password verification, durable login-attempt auditing and lockout state, security-event outbox records, transaction-PIN setup/verification/rotation, recent-PIN reuse prevention, and Redis-backed distributed velocity limits. Progressive `PENDING` customers may authenticate so they can continue onboarding; product and KYC authorization gates must still enforce their incomplete status.

Development may use the in-memory limiter with `RATE_LIMIT_STORE=memory`. Production configuration is rejected unless `RATE_LIMIT_STORE=redis`. Password login delegates successful token/session creation through `AuthResultIssuer`; the production bootstrap intentionally keeps that issuer unavailable until A-06 supplies asymmetric JWT and refresh-session issuance.

The A-05 passwordless flow supports login, phone verification, email verification, password reset, and step-up OTP purposes. Requests are enumeration-resistant and idempotent; verification is tenant-bound, rate-limited, expiring, attempt-limited, and single-use under concurrency. PostgreSQL retains only a keyed hash. The plaintext code is AES-256-GCM encrypted in the TTL-bound OTP secret store, while notification outbox events carry only the challenge ID—never the OTP.

The A-06 session layer issues RS256 access tokens with `kid`, issuer, audience, subject, tenant, session, subject-type, and authentication-method claims. Access tokens live for 15 minutes and are accepted only while their PostgreSQL session remains active. Refresh values are random opaque secrets retained only as keyed hashes, rotate on every use, and trigger whole-family compromise and revocation when reused. Logout immediately revokes the current session, introspection checks both JWT validity and live session state, and revocations are published through the transactional outbox.

## Service-to-service tokens

Auth is the issuer for all internal calls. `POST /internal/v1/oauth/token` accepts RFC 7523 `private_key_jwt` client assertions: each service signs a 60-second ES256 assertion with its own private key, and Auth verifies it against the public keys registered in `SERVICE_CLIENT_KEYS_JSON`. Assertion `jti` values are single-use through the configured rate-limit store.

- `client_credentials` issues a service-only token for background and pre-login work.
- RFC 8693 token exchange issues a delegated token: the caller presents the user's access token (BFFs) or a delegated token issued to it (domain services). Auth checks the live session, the subject's tenant, and the user's entitlement to every requested scope. Administrators are checked against their current Tenant Admin permissions.

Tokens are RS256, bound to one audience, and live at most 300 seconds. Delegated tokens never outlive their subject token. The client policy and scope catalogue in `src/security/scope-catalogue.ts` are a reviewed copy of `parc-contracts/security/scopes.v1.json`. Auth's own calls to Tenant Admin use locally signed service tokens. Its internal routes accept only issued tokens, validated by the shared `src/security/parc-service-auth.ts` module with explicit route policies.

Development generates an ephemeral RSA key pair at startup. Production requires `JWT_PRIVATE_KEY_BASE64`, `JWT_PUBLIC_KEYS_JSON`, and `JWT_ACTIVE_KID`; retaining prior public keys in the JSON set provides controlled verification overlap during signing-key rotation.

The A-09 KYC slice exposes authenticated, tenant-bound initiation and status endpoints for NIN and BVN verification. `KycProvider` keeps provider behavior behind a replaceable boundary, with VerifyMe as the first adapter. The service requires an active customer-owned KYC consent, uses keyed identifier hashes, retains only masked identifiers and redacted results, signs normalized evidence, and emits a privacy-minimized KYC status event. Provider timeouts and non-definitive failures remain `PENDING`; they are never converted into a failed identity decision.

VerifyMe's API key and all KYC hashing/signing secrets must come from a production secret manager. Key IDs and provider configuration versions are persisted with evidence so verification and controlled rotation remain possible. The initial static provider resolver is intentionally replaceable by Tenant Admin's provider-catalog resolution when T-05 is implemented; unavailable providers must never be returned by that resolver.

The A-10 notification worker consumes `notification.requested.v1` from a durable RabbitMQ quorum queue with manual acknowledgement, exponential retry with jitter, and a service-owned dead-letter queue. Brevo, Termii, and Firebase Cloud Messaging implement provider-neutral email, SMS, and push boundaries. Delivery is idempotent at the inbox and per-target levels; successful push targets are not resent when another target requires retry.

OTP values remain encrypted and TTL-bound in the configured secret store. They are rendered only in memory immediately before provider submission. PostgreSQL stores masked destinations, keyed target hashes, content placeholders, append-only attempt evidence, provider references, and retention deadlines—never an OTP, full destination, provider credential, or raw provider response.
