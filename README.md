# heain-console

Web screens for heain-core's admin plane (Step 5b, 2026-10-08), served behind [heain-gateway](https://github.com/heainframework/heain-gateway).

People sign in at the gateway, with a password plus TOTP, or OIDC. The console then relays them to core, and core decides everything: the person's roles, four-eyes, P5 and MFA. The console holds no state and no power of its own.

Built on [heain-sdk](https://github.com/heainframework/heain-sdk) v1. It passes the heain conformance suite. Run it however you like: a plain process, a service unit, or a container (Docker is not required).

## Author decisions (2026-10-08)

1. **Who a person is in core.** A person is `user:<gateway account id>`, listed in core's `roles.admins` / `roles.approvers` through P5 like a certificate identity.
   - Gateway roles give no power in core.
   - A client certificate whose CN starts with `user:` never matches.
2. **MFA is required.** Core accepts a relayed person only if they signed in with `pwd+totp` or `oidc:*`. This is the 2b key `console.auth_methods`, a security-admin's.
3. **Plain HTML/JS, embedded in the binary.**
   - No npm, no build step, no CDN.
   - A strict CSP: `default-src 'none'; script-src 'self'; ...; frame-ancestors 'none'`.
   - No inline script. Text is set with `textContent` only.
4. **The screens:**
   - **Overview:** who you are, the fleet, active alerts.
   - **Approvals:** approve or reject P5 items.
   - **Config:** list, change a 2a key or propose a 2b key, history.
   - **Apps.**
   - **Rollouts:** pause, resume, abort.
   - **Audit:** verify the chain, records, recent events.
   - **Reports:** heain-report dashboards and their CSV.

   A node selector runs every screen on a node of the subtree (remote admin through the Master).

## How a request travels

```
browser --(cookie + CSRF)--> heain-gateway --(mTLS + X-Heain-User assertion)--> heain-console
heain-console --(mTLS, its app certificate; X-Heain-User + X-Heain-User-Cert)--> heain-core /v1/app/admin/<path>
heain-core: verifies the gateway's certificate and signature, the assertion's freshness and audience, the sign-in
            method; then serves /v1/admin/<path> as user:<account> (roles, four-eyes, P5; audited as admin.console)
```

| Endpoint | |
|---|---|
| `GET /ui/{path...}` | the screens (expose it as an anonymous route) |
| `GET`, `POST`, `PUT`, `DELETE /v1/core/{path...}` | core's `/v1/admin/<path>`, run as the signed-in person; only people (an app gets 401) |

The screens call the gateway's `/auth/*` to sign in, and heain-report's exposed routes for dashboards, from the same origin.

## Setting it up

1. Admit heain-console like any app. Then, through P5:
   - `console.apps: ["heain-console"]` (a security-admin's);
   - `gateway.exposures` (a policy-admin's): `GET /ui/{path...}` with `"auth": "anonymous"`, and `GET`, `POST`, `PUT`, `DELETE /v1/core/{path...}` with the gateway role your admins have (for example `"roles": ["console"]`). Optionally add heain-report's `GET /v1/reports` and `GET /v1/dashboards/{id}`.
   - `roles.admins` and `roles.approvers`: the people, as `user:<account>` (a security-admin's).
2. Run it:
   ```sh
   go build -o heain-console ./cmd/heain-console
   ./heain-console     # app plane on :19590 (HEAIN_LISTEN)
   ```
3. Open `https://<gateway>/api/heain-console/ui/`.

## Tests

```sh
go test ./...
bash scripts/live_5b.sh   # needs ~/heain-core, ~/heain-sdk, ~/heain-gateway, ~/heain-database, ~/heain-report; ~3 min
```

The live test runs a real G ← Z tree with heain-database, heain-gateway, heain-console and heain-report. It covers:

- core trusting the gateway and the console;
- the screens with their CSP;
- anna (MFA) acting as `user:anna`: a 2a change, and a 2b proposal that boss, an Approver only, approves;
- refusals:
  - a password-only sign-in;
  - a person with no admin role;
  - a change without the CSRF token;
  - an app calling the console;
  - an app outside `console.apps` calling core's relay;
  - a client certificate named `user:anna`;
- remote admin to Z;
- a heain-report dashboard;
- core's audit of every relay.

**Known limit (accepted 2026-10-08):** for the 2 minutes an assertion lives, a compromised console could replay it for other requests of the same person. Core audits each request with the assertion id, and a console is trusted only through `console.apps`.
