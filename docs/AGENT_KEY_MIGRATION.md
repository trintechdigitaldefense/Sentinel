# Legacy agent API-key migration

## Security behavior

Agent API-key records must contain a valid `expires_at` timestamp. A registry entry created before expiry enforcement that has no `expires_at` is classified as legacy and is rejected by both `verify_key()` and `resolve_agent_id()`. It is not automatically extended, assigned a synthetic expiry, or grandfathered into authentication.

The operator status command reports legacy entries:

```bash
python3 sentinel.py agent-key status
```

The output includes `legacy_agents` and `migration_required_count`. It never prints stored key hashes or raw credentials.

## One-agent-at-a-time migration

1. Back up the central agent-key registry and protect the backup with owner-only permissions. Do not hand-edit hashes or add expiry timestamps to old records.
2. Identify the agent ID in `legacy_agents`. Confirm the asset owner and the authorized SSH or console path to that host.
3. On the central host, issue a replacement for that same ID:

   ```bash
   python3 sentinel.py agent-key <agent-id>
   ```

   The command returns a new raw key once. Reissuing an ID immediately replaces its registry record and invalidates the previous key; this is a credential rotation, not a grace-period migration.
4. Transfer the replacement credential to the authorized agent through the approved SSH deployment path or another protected channel. Do not paste it into tickets, chat, shell history, source control, or email. Configure the agent with the HTTPS central URL and the correct CA trust (`agent.tls_ca`) if the central uses a private CA.
5. Restart the agent service and confirm a fresh check-in at the central host. Confirm the expected agent ID and timestamp; a local process being active is not proof of successful central authentication.
6. Confirm `migration_required_count` no longer includes that ID. Proceed to the next agent.
7. After all expected agents have migrated, review stale-agent records and remove obsolete deployment bundles and credential sidecars according to the organization's retention policy.

## Recovery and outage handling

- Reissuing a credential invalidates the previous credential immediately. Schedule the replacement with access to the remote host so that the new key can be installed promptly.
- If transfer or restart fails, do not restore a legacy key by adding an expiry. Reissue a new key and repeat the controlled enrollment.
- A corrupt or unreadable key registry is a stop condition. Preserve it for recovery; the authentication code deliberately fails closed rather than resetting it.
- Legacy shared-token configurations are a separate concern from legacy entries in `agent_keys.json`. Shared-token authentication is accepted only by the loopback central listener. Do not expose a shared token as a substitute for an expiring per-agent key on a network-facing listener.

This procedure is an operator migration guide. It does not claim that every existing remote host has been migrated.
