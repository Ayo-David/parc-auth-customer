# Persistence enforcement

All domain repository work runs inside `withTenantTransaction`. It validates a UUID tenant identifier and uses transaction-local `set_config('app.tenant_id', ..., true)` before invoking repository code. Runtime and worker connections use their corresponding non-owner, non-`BYPASSRLS` database roles; migration credentials are never used by the service.

Application layers added in subsequent Auth tasks must also enforce:

- Canonical phone identifiers use E.164 form; emails use the documented lowercase canonical form before repository access.
- Passwords, PINs, OTPs, session tokens, refresh tokens and challenges reach repositories only as approved hashes. Raw values are never logged or persisted.
- BVN/NIN evidence is reduced to masked values, separately keyed hashes, provider references, consent references, result digests/signatures and key versions. Generic metadata and webhook JSON are allow-listed and redacted before storage.
- Provider requests record the Tenant Admin configuration version used for routing.
- Session refresh uses an atomic token-family rotation; detected reuse compromises and revokes the whole family.
- Authentication challenges are purpose-bound, attempt-limited, short-lived and atomically consumed.
- Retention workers clear ordinary notification content at 90 days, retain delivery metadata for at most 12 months, purge raw webhooks after 30 days, retain security logs for 24 months, and preserve regulated evidence for its approved period. Legal holds suspend deletion.
- Inbox handlers acquire a unique event receipt before side effects. Domain writes and outbox inserts share one database transaction.
