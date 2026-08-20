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

Members of the built-in group `lldap_mfa_disabled` (created at boot like the other
built-ins) are exempt under both positive modes: they authenticate with the password
alone even if enrolled. The combined `password:code` string is not split for them, so
it is a wrong password — use the bare password. Put service accounts there, and keep
one admin exempt or unenrolled as the break-glass.

## Enrollment

Over GraphQL today; the web page follows. `startMfaEnrollment(currentCode)` returns the
`otpauth://` URI (issuer `KLLDAP`) to show as a QR code, the base32 secret for manual entry,
and a sealed `state` valid for five minutes; `finishMfaEnrollment(state, code)` proves the
authenticator holds the seed and stores the factor — nothing is persisted before that.
Replacing an authenticator needs a code from the one being replaced, checked at
`startMfaEnrollment` and recorded in the sealed state, so a stolen session cannot rebind
the account to another device. If the old one is gone, an administrator resets the factor
or the password-reset e-mail clears it.

## Logging in

Append a colon and the current code to the password:

```text
yourpassword:123456
```

| Door | Code missing | Code wrong | Code replayed / attempts spent |
|---|---|---|---|
| Web login (`/auth/opaque/login/finish`) | `200 {"mfaRequired": true}` and no token; the client retries with the code in `totpCode` | `401` | `401`, naming the reason |
| `/auth/simple/login` | `401` … *TOTP code required* | `401` | `401` … *already used* / *Too many TOTP attempts* |
| LDAP simple bind | `invalidCredentials`, diagnostic *TOTP code required: append ':' and the code* | `invalidCredentials`, empty diagnostic | `invalidCredentials`, *TOTP code already used, wait for the next one* / *Too many TOTP attempts, wait for the next one* |

Every diagnostic comes after the password verified; a wrong password stays a plain
`invalidCredentials`, so a password guess learns nothing about the factor.

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
`mfa enrollment pending` for a web login admitted under `"always"`; failures are
`invalid totp`, `totp replayed`, `totp attempts exceeded`, `totp re-enrollment required`
(the sealed secret no longer opens) and `mfa enrollment required`. The challenge itself —
password right, code missing — records nothing. Enrollment and resets are `mfa_enroll`
(`started`, `totp`, `replaced`, and the refusals) and `mfa_reset` (`self`,
`password reset`, `forced admin reset`, `private key changed`; an administrative reset has
no detail — the actor says who).

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

## Limitations

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
- The web app's login form, change-password page and enrollment page are the next change;
  until then enrolled users sign in over the API and LDAP, and enroll or reset over GraphQL.

## What builds on it

`MfaBackendHandler::mfa_requirement(user)` is the one place the doors ask what a login must
present; the group policies plug in there — a requirement per group, the failure tracker at
the log sink, an `mfa_enrolled_at` check that ends older sessions, a persisted last step for
replicas, recovery codes. The engine (`crates/mfa`), the handler and the doors are
LLDAP-neutral; the built-in group and the Kerberos notes are KLLDAP's.
