# Organizational-unit policies

KLLDAP can attach a named policy of **items** to an OU, including the domain root
(`dc=example,dc=com` → the empty key `""`). An object resolves each item by walking its
OU chain. The lockout items (`lockout-threshold`, `lockout-duration-seconds`) are
enforced at every door ([Lockout](#lockout)), and `enable-mfa` at the directory's doors
([Second factor](#second-factor)); **the other items are stored and resolved but not
enforced yet**. Each later pass consumes the same resolution at its seam.

## Resolution

The chain is root-first: `people\labs` walks `""` → `people` → `people\labs`. Closest
wins: the deepest OU that sets an item is the source. An OU may **block inheritance**;
the chain then restarts at that OU (its own policy still applies). The root cannot block.
One policy per OU; a policy may still be linked to many OUs. Server-scope items (none in
v1) always resolve from the root only.

Example: root policy sets `enable-mfa=off`, `people\labs` sets `enable-mfa=always`. A
user in `people\labs` sees `always` with source `people\labs`. If `people\labs` blocks
inheritance, root's other items no longer apply there.

## Using it

GraphQL: admins and read-only admins read, admins write. `clearOuPolicy` and
`effectivePolicyItems` answer `Unknown OU` for an OU that is not registered. Item values are strings: bools `true`/`false`, ints base-10 in range,
enums exact tokens, lists comma-separated. `login-hours` is empty (always) or
`;`-separated `DAY[-DAY] HH:MM-HH:MM` (`mon-fri 08:00-18:00`). `allowed-networks` is
comma-separated CIDR with an explicit prefix.

```graphql
{ policyItemCatalog { key scope defaultValue enforced description } }
mutation { createPolicy(name: "Hours", items: [{key: "enable-mfa", value: "always"}]) { id } }
mutation { setOuPolicy(ou: "", policyId: 1) { ok } }
mutation { setOuPolicyInheritance(ou: "people", blocked: true) { ok } }
{ effectivePolicyItems(ou: "people\\labs") { key value enforced sourceOu sourcePolicyName } }
{ ouPolicyStates { ou policyId policyName blockInheritance } }
```

`ou` `""` is the domain root. `linkedOus` on a policy uses the same keys.

## Pages

Admin navbar **Policies** — one workbench page at `/policies`. The left pane is the OU
tree (root shown as the uppercase domain from `/settings`, e.g. `EXAMPLE.COM`; `All` if
the field is empty), with the same branch glyphs as the users/groups OU selector. Each
row carries at most one chip: a **solid** colored chip is the policy set on that OU, a
**dashed** faded `↓ Name` chip is the governing policy inherited from above, and a red
stop icon marks an OU that blocks inheritance. Chip colors are per policy, so OUs
sharing one match at a glance.

The right pane inspects the selected OU. **Rules above blocked/inherited** is the block
toggle (not on the root). An OU with its own policy shows it as a tinted card with
Edit / Swap / Remove; one without shows where its rules flow in from and an **Attach a
policy** button opening the picker (attach = replace — an OU holds one policy). Picking
also offers **Make a new policy and attach it here**. The editor edits name,
description and the catalog rules as tick-to-set rows; editing a policy linked to
several OUs warns that changes apply to all of them, and **Delete this policy
everywhere** confirms before deleting (OUs fall back to inherited policies). Switching
OUs discards an unsaved draft.

**Current OU policy** always lists every catalog item with its resolved value and
source (`Policy · OU`, or `built-in default`) straight from `effectivePolicyItems` —
the page never recomputes closest-wins values client-side.

Users and groups still filter on the sentinel value `All`; only the visible label of
that option is the domain name.

## Second factor

`enable-mfa` (`off`, `enabled`, `always`) is the OU's value of `enable_mfa`
([mfa.md](mfa.md#modes)). A user's value comes from one resolution path: the server-wide
`enable_mfa` if one is set, which overrides every OU; else the user's OU, by the inheritance
above; else `off`. Members of `lldap_mfa_disabled` give no code whatever their value. The
directory's doors follow the user's value:

| Door | A user with a factor (`enabled` or `always`) | `always`, a user without one |
|---|---|---|
| LDAP bind, `/auth/simple/login` | `password:code` | refused, *MFA enrollment required* |
| Web login | the code step | admitted only to enroll (`mfaEnrollmentRequired`) |
| Token refresh and use | as the session was made ([mfa.md](mfa.md#modes)) | confined to reading their own user and enrolling |
| kinit, renewals, service tickets | a ticket within `mfa_proof_window` of a sign-in with the code ([kerberos.md](kerberos.md#a-second-factor-and-kinit)) | refused (error 12) until the user enrols, which opens the window |

A user whose value is `off` gives no code and cannot enroll (*MFA is disabled for this
user*); one whose value is `always` cannot reset their own factor. Where the server-wide
value is set, the policy page says so above the OU's items: it overrides their
`enable-mfa`. 0.8.0 called the item `require-mfa` (`off`, `enrolled`, `always`): a stored
policy is carried over at start (`enrolled` becomes `enabled`; where both names are present
`enable-mfa` is kept), and `require-mfa` given to `createPolicy` or `updatePolicy` is refused
with a message naming `enable-mfa`.

What it costs: every server reads the policies once every 30 seconds, whatever is set, and
that one small read (with the lockout's counting period beside it) serves this item and the
lockout alike. The doors read the value from the policy cache, and only while some OU's policy
sets it above `off` and nothing is set server-wide; where no OU sets it or a lockout
threshold, the doors themselves read nothing for either. With Kerberos on and `enable_mfa`
set server-wide to `enabled` or `always`, every server also keeps each user's factor and
group in memory, refilled about every 30 seconds, because the KDC judges from memory alone.
Linking, editing or removing a policy, and moving a user to another OU, apply at the user's
next sign-in: at once on the server that made the change, within about 30 seconds on the
others. Where no OU set the item
before, another server resolves every user to `off` until its read sees the change, for up
to those 30 seconds. Until a starting server has read the item once, and whenever a user's policy cannot
be read, the directory's doors refuse the users whose value an OU could set (`policy:
unreadable`), token refresh and use among them, and the server reads the policies again every
second until it can. With `enable_mfa` set server-wide the OUs' item takes no part in the
decision and nothing is refused for it; where Kerberos is on, the memory described above is
still kept for the KDC.

At start the server warns once with the number of OUs that set `enable-mfa` to `enabled` or
`always` while nothing is set server-wide; the warning names no OU.

## Lockout

`lockout-threshold` (0 turns it off) and `lockout-duration-seconds` (0 holds a lock until an
admin unlocks) lock a user after that many wrong passwords in a row. One counter per user, in
the table `login_lockouts`, serves every door: LDAP bind, `/auth/simple/login`, the web login,
kinit and the tickets asked with a user's ticket (renewals and service tickets), token refresh
and token use. A wrong TOTP code counts once, like a wrong password; a code used before, a code
past the limiter, a code refused because the database could not answer (`totp: unreadable`) and
the right password without its code count nothing ([mfa.md](mfa.md)). A
success clears the count, and the next failure after an unlock counts from 1. For a user who
must give a second factor at the directory's doors (enrolled, their `enable_mfa` value
`enabled` or `always`, and not in `lldap_mfa_disabled`), a Kerberos ticket (asked with the
password alone) does not reset the count, nor does it for a user whose factors or value the
server has not read yet. When a timed
lock runs out the count stays where it was, so one more wrong password locks again for the
whole duration. Every user can be locked, admins included.

Counting starts when the first OU policy with a lockout threshold takes effect (linked to an
OU, the root included), for all users, from zero: the change that links it, or raises its
threshold from 0, clears every stored count and every logged lock in its own transaction,
starts a new counting period, and touches nothing an administrator set. Before that nothing is
counted: where no OU sets a threshold, no door reads or writes anything for the lockout; each
server reads the policies once every 30 seconds. Once counting is on, the failures of users
with no threshold of their own are counted too, so a threshold added to another OU, or a move
under one, applies at once to the failures already counted. The lock is computed, so lowering
or raising a threshold applies at once. Removing the last threshold stops counting. Until a
starting server has read the policies once, every door refuses the users the lockout judges
(`policy: unreadable`), and the server reads them again every second.

While locked, LDAP bind and `/auth/simple/login` answer as for a wrong password (49, 401),
whether the password given is right or wrong, but at once: a locked user's bind skips the
password work a wrong password takes, so the time to answer shows the lock. The web login's
first step answers as for a name with no password, so the browser fails as for a wrong
password, and the finish of a start made before the lock answers as a proof that does not
verify. A token refresh or use is refused. kinit, a renewal, a service ticket and an
S4U2Self for the user get error 18 (`CLIENT_REVOKED`, "Client's credentials have been
revoked") before the KDC looks at any password; that is not the wrong-password answer (24),
and anyone can see it without a password. An S4U2Self never counts. Nothing a locked user
sends is counted. The reason is in the log: a `locked out` row for each refusal (refusals of
the same kind from one peer coalesce in a flood, [logging.md](logging.md)), and one
`account_lock` row when a counted failure brings the stored count to the threshold.

The web login counts each attempt when it starts, because the browser checks a wrong password
itself and sends nothing more. The start's +1 is kept beside the user's stored count, never in
it, and counts at every door at once, so starts that are never finished lock the user as they
come; such a lock gets its `account_lock` row when the starts join the stored count, about 10
seconds after they began. A finish whose proof
verifies removes its own start's +1, once, and changes nothing else; the same finish sent
again finds nothing to remove. A sign-in that completes (the password and every factor
verified), at any door, also drops the user's starts made before it on that server, so a
wrong web attempt before a right one never comes back, as a wrong bind before it does not; a
finish that stops at "code required" drops nothing. A finish on a server that does not hold its
start writes the start's id to the user's row, with whether the sign-in completed there. A
start that no finish removes within 10 seconds joins the stored count as a failure at the
start's time, unless the row holds its id, or the id of a later start of the same user made on
the same server whose sign-in completed: with two servers, a sign-in whose steps start and
finish on either of them never counts against the user. With three or more, a sign-in whose
two steps went through three servers can leave one count, which the user's next sign-in
clears. At most 32 starts per user are held at once; a start beyond them joins the count at
once. The `account_lock` row of a lock that starts reach carries the peer of the start that
reached it. Every page
that starts a login also finishes it; a finish without a session (a page checking the
password) is judged and counted as any finish. At a threshold of 1 a sign-in in progress
counts until it finishes, so the same user's other requests in that instant are refused, and
a page left during a sign-in counts once.

To unlock: GraphQL `mutation { unlockUser(userId: "bob") { ok } }` (admins), the host tool
`lldap unlock --config-file <config> bob`, or kadmin `modprinc -unlock` on the user's principal.
Each writes one `account_unlock` row in the unlock's transaction, stamped with the clock of the
server, or of the host tool's own process. A password change does not unlock. An unlock by the
host tool or by another server takes effect at this server's next sign-in attempt at the
directory's doors, and for Kerberos within a moment of the next attempt. Such an unlock wins
over every failure counted before it, also the ones this server had not written yet.

Under a threshold, each count is written before the door answers, and the door waits at most
250 ms for that write in all. When the database takes longer, the door answers anyway and the
count is owed: it is tried again about a second later, and a crash before then loses it. Other
counts are owed and written within about a second: those of a user with no threshold, and a
web start's +1 once its 10 seconds are over. Each write carries the user's state as it stands
(the count, the last failure, the lock), so a late or repeated write never counts twice; a
write never undoes a later unlock, stores nothing for a user who no longer exists or for another
account made since under the same name, and stores nothing from an earlier counting period,
even when it meets the change that starts a new one. A write the database refuses is kept in
memory and tried again until it is taken; the server log says so once at WARN, with the cause, and once
at INFO when they are stored again, with how many users' rows waited. The counts in memory are
what the doors judge with while the server runs; a door about to refuse a locked user first
reads that user's stored row, at most once a second. A clean stop writes what is owed, every
start still held included, within a second, so a sign-in in progress at that moment counts once
(the user's next sign-in clears it). A crash or a power cut loses what is still owed: the
last second or so of counts, a count whose write took longer than 250 ms, and up to the last
10 seconds of web starts.

With several servers on one database (only with Kerberos disabled), each server counts the
attempts it sees exactly, the servers agree within 30 seconds, and a guesser who spreads the
attempts over N servers gets at most N times the threshold before every server refuses. A
table that cannot be read refuses the attempt (`policy: unreadable`).

## What is recorded

`policy_change` rows: creating/updating/deleting a policy (target = name; detail
`created` / `updated: {field names}` / `deleted`), attaching or clearing an OU
(target = the OU, or `(root)`; detail `policy set: {name}` / `policy cleared: {name}`),
inheritance toggles, and dropping state when an OU is deleted (`ou removed`). A
no-op inheritance toggle is not logged.

## Configuration

None. The surface is always on (reads for admins and read-only admins, writes for admins).
The lockout is in force wherever an OU sets a threshold, and `enable-mfa` wherever an OU sets
it, unless `enable_mfa` is set server-wide, which overrides it. `lldap_mfa_disabled` is made
at start when `enable_mfa` is set server-wide to `enabled` or `always`; otherwise by
whichever server first reads an OU's `enable-mfa` above `off` (at the change, or at its
30-second read), never while the policies are not read.

## Limitations

- Only the lockout and `enable-mfa` are enforced. The other items carry `enforced: false` and
  say so in their descriptions; per-item passes follow.
- A lock's duration runs from the last counted attempt, and a web start counts as one until
  its finish takes it back, so the duration can run from a start that then succeeded.
- Kerberos already tells whether a principal exists (an unknown one gets a different error);
  a lock does not change that.
- Depth is root / primary / secondary with one policy each — no AD multi-link stacking.
- `updatePolicy.items` is a wholesale replace.
- Policy applies per OU, not per object.

## What builds on it

`PolicyBackendHandler::get_policy_levels` plus `resolve_effective_items` is the seam
each later enforcement pass consumes (per-OU MFA, lockout, login hours, networks,
inactivity).
