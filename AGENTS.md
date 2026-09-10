# Auth Customer service instructions

## Ownership

Own credentials and sessions, customer identity/profile, KYC references and workflow state, consent, trusted devices, referrals, notification preferences and identity-related fraud signals. Own only the `parc_auth_customer` database.

## Security and privacy rules

- Hash passwords with the approved adaptive password hash; never encrypt or log plaintext passwords.
- Store refresh/session tokens as hashes where feasible, rotate them, support revocation, and protect against replay.
- OTPs are short-lived, purpose-bound, rate-limited, attempt-limited and never logged.
- BVN/NIN and verification artifacts are highly sensitive. Minimize collection, encrypt protected fields, restrict access, redact logs and store provider references instead of unnecessary raw responses.
- Consent records capture purpose, policy/version, channel and timestamp. Do not silently broaden consent.
- Authentication responses must not reveal whether an account exists beyond approved product behavior.
- Emit customer/KYC lifecycle events without unnecessary personal data.

## Database and delivery

- Canonical migrations: `db/migrations/`; generated snapshot: `db/schema/current.sql`.
- Test account enumeration resistance, rate limits, session rotation/revocation, authorization, tenant isolation, idempotency and provider failure handling.
- Update auth/customer contracts before changing externally observable shapes.
