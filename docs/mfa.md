# Two-factor authentication (TOTP)

KLLDAP can demand a time-based one-time password (TOTP, RFC 6238: SHA-1, six digits,
30-second steps, one step of clock skew) as a second factor on every door: the web login,
the `/auth/simple/login` endpoint scripts use, and LDAP simple bind. The secret is sealed
with a key derived from the server's private key and kept in the `totp_secret` /
`mfa_type` columns that were always there; nothing happens until `enable_mfa` says so.
Kerberos logins are a separate system and never see the factor (below).

## Modes

`enable_mfa` in the config file, `LLDAP_ENABLE_MFA` in the environment, `--enable-mfa` on
the command line:

| Value | Effect |
|---|---|
| `false` (default) | Off. Enrollment is refused and nothing is ever split: a password that happens to end in `:123456` is the whole password. |
| `true` | Users may enroll an authenticator; only enrolled users must present a code. |
| `"always"` | Every user must enroll. Until they do, the web login admits them flagged `mfaEnrollmentRequired` and the API is confined to reading their own user and enrolling, while `/auth/simple/login` and LDAP bind refuse them with *MFA enrollment required*. |

While the mode is `true` or `"always"`, KLLDAP creates the group `lldap_mfa_disabled` at
startup if it does not already exist, and its name is load-bearing: it cannot be renamed or
deleted. With MFA off it is not created, and a group of that name is an ordinary group.
Members are exempt under both positive modes: they authenticate with the password alone
even if enrolled. The combined `password:code` string is not split for them, so it is a
wrong password — use the bare password. Put service accounts there, and keep one admin
exempt or unenrolled as the break-glass.

## Enrollment

From your profile page, **Set up two-factor** opens the enrollment page. It first asks
for your current password, which the page proves to the server with an OPAQUE login
that makes no session (the password does not leave the browser). Then it shows a QR code
(issuer `KLLDAP`) and the base32 secret for manual entry. Scan or type it into an
authenticator app, then confirm within five minutes by entering `yourpassword:123456`;
the page says whether the code matches before you submit, and the server checks the
password again. Nothing is stored before the confirmation. Replacing an authenticator
(**Reconfigure two-factor**) first asks for a code from the one being replaced, so a
stolen session cannot rebind the account to another device; if the old one is gone, an
administrator's **Reset two-factor** on the user's page or the password-reset e-mail
clears the factor. **Reset two-factor** on your own page needs `password:code` too and is
absent under `"always"`, where an account may not be left without a factor. Under
`"always"` a web login that has not enrolled lands on the enrollment page and nothing else
renders until it completes.

Over GraphQL the same steps are `startMfaEnrollment(currentCode, enrollmentProof)` (the
`otpauth://` URI, the base32 secret and a `state` string valid for five minutes),
`finishMfaEnrollment(state, code)`, `resetOwnMfa(code)` and the administrative
`resetUserMfa(userId)`. A first enrollment needs `enrollmentProof`: a login that asks for
one with `"enrollmentProof": true`, at `/auth/simple/login` or at
`/auth/opaque/login/finish`, returns it as `enrollmentProof` in its answer. A replacement
needs `currentCode` instead.

## Logging in

The web login asks for the password, then, when the account has a factor, for the code in
a second step. A wrong code keeps that step open for another try. The other doors take the
code appended to the password with a colon:

```text
yourpassword:123456
```

That combined form is for LDAP simple bind and `/auth/simple/login`; the web login's
password field takes the password alone (the combined form fails there as a wrong password,
and the page says the code comes next). The change-password page takes the current
password alone too.

| Door | Code missing | Code wrong | Code replayed / attempts spent |
|---|---|---|---|
| Web login (`/auth/opaque/login/finish`) | `200 {"mfaRequired": true}` and no token; the page then makes a new login that carries the code in `totp_code` | `401` | `401`, naming the reason |
| `/auth/simple/login` | `401` … *TOTP code required* | `401`, body *Invalid TOTP code* | `401` … *already used* / *Too many TOTP attempts* |
| LDAP simple bind | `invalidCredentials`, diagnostic *TOTP code required: append ':' and the code* | `invalidCredentials`, empty diagnostic | `invalidCredentials`, *TOTP code already used, wait for the next one* / *Too many TOTP attempts, wait for the next one* |

Every diagnostic comes after the password verified; a wrong password stays a plain
`invalidCredentials`, so a password guess learns nothing about the factor.

**A password check without a session.** `/auth/opaque/login/finish` takes an optional
`"session": false`. That finish does what any finish does: it verifies the password, checks
a code sent in `totp_code`, admits or refuses the user (while Kerberos is unavailable only
admins are admitted, answered `503`), and mints a proof when asked. It makes no session: no
token, no refresh token, no cookie, and it writes one row: the `login` success row, or the
refusal's. A verified finish answers
`200 {"verified": true}`, with `enrollmentProof` when one was asked for and
`mfaEnrollmentRequired` as a session finish would have it; the other answers are those of
the table above. Without the field a finish makes a session, as before. The enrollment,
reset-two-factor and change-password pages use it to have the server check the password,
and each finishes every login it starts. `/auth/simple/login` has no such field.

**Service accounts.** An enrolled account rejects the bare password on every door. Anything
that stores a static password — the Keycloak federation bind user, SSSD's
`ldap_default_bind_dn`, lldap-cli, mail, VPN — must not be enrolled or must sit in
`lldap_mfa_disabled`. Under `"always"`, populate the group before switching.

## Single-use codes and attempts

A verified code is refused for the rest of its 90-second acceptance window (*already
used*). An account gets five code attempts per 30-second step; once spent, the next
attempts fail with *Too many TOTP attempts* until the next step, right code or not. Only
failed verifications count, a replay costs nothing, and the counter is reached only after
the password verified, so it cannot lock out someone whose password the attacker lacks.
Both records live in memory in the running process: they reset on restart and are not
shared between replicas. Enrollment confirmation is not attempt-limited; it confirms a
seed the client already holds.

## Resetting

| Actor | Can reset | Needs a code |
|---|---|---|
| Admin (`resetUserMfa`) | any user; themselves only when the mode is not `"always"` | no |
| Password manager (`resetUserMfa`) | non-admin users, never themselves | no |
| The user (`resetOwnMfa`) | themselves, unless the mode is `"always"` | yes |

Three more paths clear a factor. A **password reset by e-mail** clears it once the new
password is committed (abandoning the reset keeps it). `--force-ldap-user-pass-reset=true`,
the one-shot break-glass, clears the admin's factor along with the password. A changed
private key accepted with `--force-update-private-key=true` clears every factor, because the
sealed secrets died with the old key (one `mfa_reset` row, `private key changed`); without
the flag the server refuses to start, as it does for passwords.

## Kerberos

The KDC authenticates on its own keys: `kinit`, SSSD's Kerberos logins and Keycloak's
Kerberos federation never see the second factor, and a Kerberos password change does not
touch it. The factor guards the directory doors — web, GraphQL, LDAP — so keep the accounts
that bind to LDAP on behalf of those systems exempt. OTP pre-authentication (RFC 6560) is
out of scope.

## What is recorded

One row per ceremony, in the same table as everything else ([logging.md](logging.md)): a
`bind` / `login` success carries detail `totp` when a code was verified, or
`mfa enrollment pending` for a web login admitted under `"always"`; a web finish that makes
no session adds `no session` (`no session` alone, or `totp; no session`). Failures are
`invalid totp`, `totp replayed`, `totp attempts exceeded`, `totp re-enrollment required`
(the sealed secret no longer opens) and `mfa enrollment required`. The challenge itself —
password right, code missing — is the failure row `totp code required`. Enrollment and
resets are `mfa_enroll` (`started`, `totp`, `replaced`, and the refusals, among them
`password proof required` and `enrollment busy`) and `mfa_reset` (`self`,
`password reset`, `forced admin reset`, `private key changed`; an administrative reset has
no detail — the actor says who). A reset that finds no factor to clear records nothing.

## Configuration

```toml
# lldap_config.toml
enable_mfa = false
# enable_mfa = true
# enable_mfa = "always"
```

`LLDAP_ENABLE_MFA=true` or `LLDAP_ENABLE_MFA=always` in the environment, `--enable-mfa` on
the command line. The parameters — SHA-1, six digits, 30 seconds, ±1 step, a five-minute
enrollment, a 90-second replay window, five attempts per step, issuer `KLLDAP` — are fixed.

## Standards

| Requirement | Source | Status |
|---|---|---|
| HMAC-SHA-1, six digits, 30-second step | RFC 6238 §4–5 | Met; the RFC's Appendix B vectors are unit tests. |
| Validation window of at most one step either side | RFC 6238 §5.2 | Met: ±1 step, a code is accepted for 90 seconds. |
| Throttle failed verification attempts | RFC 4226 §7.3 | Met: five attempts per 30-second step, per account. |
| Resynchronisation for counter drift | RFC 4226 §7.4 | Not applicable to time-based codes; the ±1 step window absorbs clock drift. |
| Authenticator secrets stored in encrypted form | NIST SP 800-63B §5.1.4.2 | Met: sealed with AEAD under a key HKDF-derived from the server's private key, a per-enrollment salt and the user UUID as associated data; never returned on any interface. |
| Replay resistance | NIST SP 800-63B §5.2.8 | Met: a verified code is refused for the rest of its window, at every door. |
| No more than 100 consecutive failed attempts | NIST SP 800-63B §5.2.2 | **Not met** — see below. |
| One-time use, bounded validity, approved algorithm, protected key | OWASP ASVS V2.8.2–5 | Met, as above. |

## Limitations

- No cap on consecutive failures and no lockout: the limiter paces guessing (five per
  30-second step) instead of counting failures toward a ceiling — RFC 4226 §7.3's delay
  scheme, chosen because a lockout turns a wrong digit into a denial of service, and the
  counter is reachable only after the password verified. For a hard ceiling, rate-limit
  `/auth/*` at the reverse proxy or point fail2ban at the failed `bind` / `login` rows.
- A first enrollment proves the password with the OPAQUE login finish. The plaintext is
  nowhere on the server for that path. The finish returns a five-minute proof, and only
  when the login asked for it and the user has no factor. `startMfaEnrollment` requires
  that proof; a session is not enough. Replacing a factor still requires the current code
  and ignores a proof. The confirmation step's password check is a finish at the server
  that makes no session. A user with no factor can also ask `/auth/simple/login` for the
  same proof. Under `"always"` that door refuses a user who has not enrolled, and the proof
  comes from the OPAQUE finish, which is the door that admits them.
- A proof is used once on each server: the server that accepts it remembers it until it
  expires, and another server with the same key can accept the same proof once within
  those five minutes. A server remembers at most 1024 live proofs. While all 1024 are
  live, it refuses a first enrollment with *Too many enrollments in progress: try again
  shortly*, logs a warning and an `enrollment busy` row, and does not use up the proof
  presented, which works once the oldest expire.
- Servers that share a database need synchronised clocks. A server accepts a proof whose
  expiry is up to 60 seconds further away than its own clock allows, and no more.
- The replay and attempt records are per process and in memory.
- No recovery codes: recovery is an administrator, the password-reset e-mail, or the exempt
  group.
- Sessions and refresh tokens minted before an enrollment stay valid until they expire.
- Administrators can exempt themselves through `lldap_mfa_disabled` — the deliberate
  break-glass.
- Turning the mode back to `false` strands the combined format: the whole string is the
  password again, and enrolled users must sign in with the password alone. The same is
  true of `lldap_mfa_disabled` members who are still enrolled.
- The migration tool does not do TOTP: run it as an unenrolled account under `true`, an
  exempt one under `"always"`.

## What builds on it

`MfaBackendHandler::mfa_requirement(user)` is the one place the doors ask what a login must
present; the group policies plug in there — a requirement per group, the failure tracker at
the log sink, an `mfa_enrolled_at` check that ends older sessions, a persisted last step for
replicas, recovery codes. The engine (`crates/mfa`), the handler and the doors are
LLDAP-neutral; the exempt group and the Kerberos notes are KLLDAP's.
