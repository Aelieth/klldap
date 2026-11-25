# Organizational-unit policies

KLLDAP can attach a named policy of **items** to an OU, including the domain root
(`dc=example,dc=com` → the empty key `""`). An object resolves each item by walking its
OU chain. The lockout items (`lockout-threshold`, `lockout-duration-seconds`) are
enforced at every door ([Lockout](#lockout)), `enable-mfa` at the directory's doors
([Second factor](#second-factor)), `password-min-length` wherever a new password is
set ([Password length](#password-length)), `login-hours` at every sign-in door ([Login
hours](#login-hours)), `allowed-networks` at every door but a service's request for a user
([Allowed networks](#allowed-networks)), and `inactivity-days` at every door
([Inactivity](#inactivity)).

## Resolution

The chain is root-first: `people\labs` walks `""` → `people` → `people\labs`. Closest
wins: the deepest OU that sets an item is the source. An OU may **block inheritance**;
the chain then restarts at that OU (its own policy still applies). The root cannot block.
One policy per OU; a policy may still be linked to many OUs. Server-scope items (none in
v1) always resolve from the root only.

Example: root policy sets `enable-mfa=off`, `people\labs` sets `enable-mfa=always`. A
user in `people\labs` sees `always` with source `people\labs`. If `people\labs` blocks
inheritance, root's other items no longer apply there.

**How a sign-in is judged.** At the LDAP bind and `/auth/simple/login` a member of
`lldap_disabled` is refused, then a locked user, before the password is checked. Then the
password. After a right password the OU's items are judged in this order: the lockout,
`inactivity-days`, `allowed-networks`, `login-hours` (an item not read yet refuses first, as
`policy: unreadable`). The first that refuses is the one the log row names, and the answer is a
wrong password's. Only then is a code or an enrolment asked for, and with the code the items are
judged again. Last, on a server whose realm did not open and which is admin-only, only members
of `lldap_admin` are let in; a directory-only server lets everyone in
([kerberos.md](kerberos.md#when-the-realm-cannot-open)). At the web login the items are judged in
the same order when the sign-in starts, and a refused user's sign-in fails as a wrong password's
does. At Kerberos every item is judged before the password (error 18), then the second factor's
window (error 12). A refusal by an item neither counts toward the lockout nor clears its count.

## Using it

GraphQL: admins and read-only admins read, admins write. `clearOuPolicy` and
`effectivePolicyItems` answer `Unknown OU` for an OU that is not registered. Item values are strings: bools `true`/`false`, ints base-10 in range,
enums exact tokens, lists comma-separated. `login-hours` is empty (always) or
`;`-separated `DAY[-DAY] HH:MM-HH:MM` (`mon-fri 08:00-18:00`; [Login hours](#login-hours)).
`allowed-networks` is comma-separated CIDR with an explicit prefix.

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

Beside the `login-hours` rule the editor shows the zone it is judged in (*judged in UTC*, from
`/settings`); beside `allowed-networks` it shows the address the server sees you as (*The server
sees you as 172.17.0.1*, or *unknown*): check it before you save a list. A save's `warnings` show
under its success line; when the page's next request is then refused, one line says so and names
`lldap policy-unlink` on the host as the way back. Only `allowed-networks` is checked against you at
a save: a `login-hours` value that applies to you and leaves out the present moment gives no
warning, and refuses your next request. An `inactivity-days` of 0 shows as *off*.

On a user's page an admin sees whether the doors refuse that user now, from the admin-only GraphQL
field `User.signInState`, answered under `user(userId)` only (null in a list of users, and for
anyone else, read-only admins included): *Locked until
2027-01-15 08:10:00 UTC* (or *Locked until an admin unlocks* under a duration of 0) with an
**Unlock** button, and *Inactive since 2027-01-14* (the date the idle time passed the limit) with a
**Re-enable after inactivity** button. Each button shows only with its state; when the state cannot
be read, both show. The result line (*Unlocked bob*, *Re-enabled bob*) lasts until the next action.

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
next sign-in: at once on the server that made the change (or when a refill in progress ends),
within about 30 seconds on the others. Where no OU set the item
before, another server resolves every user to `off` until its read sees the change, for up
to those 30 seconds. Until a starting server has read the item once, and whenever a user's policy cannot
be read, the directory's doors refuse the users whose value an OU could set (`policy:
unreadable`), token refresh and use among them, and the server reads the policies again every
second until it can. A user the policy cache does not hold yet is read from the database at the
sign-in, and a read that has not answered within 2 seconds (while `ou_policies` or `policies` is
locked, say) is refused the same way, at every directory door and for the lockout too, and the
database ends that read's own wait, so a long lock does not use up the server's connections.
With `enable_mfa` set server-wide the OUs' item takes no part in the decision and nothing is
refused for it; where Kerberos is on, the memory described above is still kept for the KDC.

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
under one, applies at once (or when a refill in progress ends) to the failures already
counted. The lock is computed, so lowering or raising a threshold applies at once. Removing
the last threshold stops counting. Until a starting server has read the policies once, every
door refuses the users the lockout judges (`policy: unreadable`), and the server reads them
again every second. The same holds when the reads that turn counting on fail: from that change
until they succeed.

While locked, LDAP bind and `/auth/simple/login` answer as for a wrong password (49, 401),
whether the password given is right or wrong, but at once: a locked user's bind skips the
password work a wrong password takes, so the time to answer shows the lock. The web login's
first step answers as for a name with no password, so the sign-in fails as for a wrong
password, and the finish of a start made before the lock answers as a proof that does not
verify. A token refresh or use is refused. kinit, a renewal, a service ticket and an
S4U2Self for the user get error 18 (`CLIENT_REVOKED`, "Client's credentials have been
revoked") before the KDC looks at any password; that is not the wrong-password answer (24),
and anyone can see it without a password. An S4U2Self never counts. Nothing a locked user
sends is counted. The reason is in the log: a `locked out` row for a refusal, kept for each
user's first 8 from one client address at one kind of door and counted in a `sign_in_flood`
row pair past that ([logging.md](logging.md#rows)), and always one
`account_lock` row when a counted failure brings the stored count to the threshold. At LDAP
bind and `/auth/simple/login` an empty password, or `:` and a code alone, is refused before
the lock is read, locked or not: LDAP answers 53 (*unwillingToPerform*), `/auth/simple/login`
401 as for a wrong password, with one `bind` row `no password given` and no `locked out` row;
it is never counted.

The web login counts each attempt when it starts. The start's +1 is kept beside the user's
stored count, never in it, and counts at every door at once, so starts that are never finished
lock the user as they come; such a lock gets its `account_lock` row when the starts join the
stored count, about 10
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

To unlock: GraphQL `mutation { unlockUser(userId: "bob") { ok } }` (admins), the **Unlock**
button on the user's page while the user is locked ([Pages](#pages)), the host tool
`lldap unlock --config-file <config> bob` run as the user the server runs as
([Getting back in from the host](#getting-back-in-from-the-host)), or kadmin `modprinc -unlock`
on the user's principal.
Each writes one `account_unlock` row in the unlock's transaction, stamped with the clock of the
server, or of the host tool's own process. A password change does not unlock. An unlock by the
host tool or by another server takes effect at this server's directory doors within a second
(it looks at a held lock again at most once a second for each user), and for Kerberos within a
moment of the next attempt. Such an unlock wins over every failure counted before it, also the
ones this server had not written yet.

Under a threshold, each count is written before the door answers, and the door waits at most
250 ms for that write in all. When the database takes longer, the door answers anyway and the
count is owed: it is tried again about a second later, and a crash before then loses it. After
one such wait the KDC stops waiting: until a count's write, a door's or the background
writer's, lands within 250 ms again, it answers at once and each count it takes is owed in the
same way. The directory doors wait every time. Other
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
last second or so of counts, a count whose write took longer than 250 ms or that the KDC took
while the database was not keeping that bound, and up to the last 10 seconds of web starts.

A bind that gets none of the server's four key-stretching slots within 2 seconds, or finds 32
binds already waiting for one, is answered busy (LDAP result 51, HTTP 503) with one failed
`bind` row, `server busy`; it counts as no failure. A name that is no user is remembered as
such for 5 seconds on the server that read it: a user created on another server within those
seconds of a sign-in attempt for its name is answered `unknown user` there until they pass.

With several servers on one database (only with Kerberos disabled), each server counts the
attempts it sees exactly, the servers agree within 30 seconds, and a guesser who spreads the
attempts over N servers gets at most N times the threshold before every server refuses. A
table that cannot be read refuses the attempt (`policy: unreadable`).

## Password length

`password-min-length` (8 to 128, default 8) is the fewest characters a new password may
have. Characters are counted, not bytes: `pässwört` has 8. Only new and changed passwords are
held to it; a password already set is never judged, so a user moved under a higher minimum
keeps signing in with the old password until it changes. A user's value comes from their
OU, by the inheritance above. There is no server-wide setting. A changed minimum applies to the
next password change on every server at once, unlike the sign-in items, which follow within
about 30 seconds: each change reads the user's minimum from the database, a few small reads.

The server holds every password it sees to the user's minimum, and refuses a shorter one with
"the password must be at least N characters", N being that minimum:

| Door | A shorter password |
|---|---|
| GraphQL `setUserPassword` | a GraphQL error |
| LDAP password modify (`ldappasswd`), LDAP Modify replacing `userPassword` | 53 (unwillingToPerform) |
| LDAP Add with `userPassword` | 53, judged by the OU the DN names; nothing is made |
| The web pages and `lldap_set_password`, for a user with `kerberosSync` | 400 at the finish |
| kadmin `cpw` on a directory user's principal | `PASS_Q_TOOSHORT`, which kadmin shows as *Password is too short* |

Each refusal writes one failure row, and the password is not changed.

For a user without `kerberosSync`, the web pages and `lldap_set_password` never show the
server the password (OPAQUE), so the server does not enforce the minimum there. Instead the
register start's answer carries the user's minimum (`password_min_length`, see
[scripting.md](scripting.md)), and the pages and the tool refuse a shorter password before the
finish. The pages say *Invalid password. Min length: N*, and the tool says *New password is
too short, expected at least N characters*. They check the same number for a synced user, so
the server's 400 is seen only by a client that skips the check. A client older than the field
keeps checking 8. The pages and the tool apply the server's rule, so a password with a NUL
character is refused there too, with "the password must not contain a NUL character
(U+0000)". `lldap_set_password --bypass-password-policy` skips the minimum length only, never
the NUL check.

When the user's policy cannot be read, or the stored value is not a whole number, every door
above refuses the change with "the password policy could not be read; try again", never
holding it to 8 instead (a stored number out of range is held to 8 to 128); kadmin `cpw`
answers `PASS_Q_GENERIC`, which kadmin shows as *Unspecified password quality failure*. A
minimum whose read has not answered within 2 seconds (while `ou_policies` or `policies` is
locked, say) is refused the same way at every door, and the database ends that read's own wait.
The register start is refused the same way (400) for every user, and the pages show the
sentence.

The configuration's admin password (`ldap_user_pass`) is checked against 8 only, at the first
start and at a forced reset (`force_ldap_user_pass_reset`). When that password is shorter than
the admin's minimum, the start logs one warning that names the minimum, never the password's
length: *The admin password in ldap_user_pass is shorter than the admin's password-min-length
of 12: the configuration's password is checked against 8 only, and a change of it is held to
12*. When the admin's minimum cannot be read within 2 seconds, the start logs one warning that
says so and goes on. Any other change of the admin's password is held to the minimum.

A synced user's password crosses the web pages and `lldap_set_password` in an envelope of at
most 318 bytes, so there a high minimum cannot be met in letters of several bytes each: 128
characters of 3 bytes are 384 bytes. The pages and the tool refuse such a password with *A
password with Kerberos sync can be at most 318 bytes long*. `setUserPassword` and LDAP have no
such bound.

The create-user page makes the user first and sets the password after. When the password stops
before the finish is sent (the register start refused, or the OU's minimum not met), the user
stays created without a password, and the page says so after the cause. Only the minimum's
cause names N: *Invalid password. Min length: 12. User bob was created without a password; set
one from the user's page*. A refused start reads, for example, *the password policy could not
be read; try again. User bob was created without a password; set one from the user's page*.
When the server refuses the finish itself, the user was created and its password may not have
been set, and the page says that after the cause: *Failed to set new password: … User bob was
created, and its password may not have been set; set one from the user's page*.

## Login hours

`login-hours` says when a user may sign in. A user's value comes from their OU, by the
inheritance above; there is no server-wide setting, and empty (the default) means always.
Nobody is exempt, admins included: hours set on the root, or on the admins' OU, refuse the admins
outside them too.

The value is entries separated by `;`, each `DAY[-DAY] HH:MM-HH:MM`:

- Days are `mon` to `sun`, in any case. One space separates the days from the times; spaces
  around an entry are allowed, others are refused.
- A range runs from its first day to its last and may wrap: `fri-mon` is Friday, Saturday,
  Sunday and Monday; `mon-mon` is Monday alone; `tue-mon` is the whole week.
- Times are two-digit hours and minutes. The start comes before the end, and `24:00` may end
  a window (`mon 23:00-24:00`) but never start one. A night across midnight is two entries:
  `fri 22:00-24:00;sat 00:00-06:00`.

A sign-in is judged at the moment it is made, read on the wall clock of the server's one zone,
`login_hours_timezone`, which is `UTC` unless you set it ([Configuration](#configuration)), and
compared with the windows:

- A window admits from its start up to, not including, its end, to the second: `08:00-18:00`
  admits 08:00:00 to 17:59:59.
- The day is the wall clock's weekday.
- Where the zone changes its clocks, only the wall-clock times that happen count. When the
  clocks go forward the skipped times never happen: in `America/Chicago` on 8 March 2026 the
  clock goes from 01:59:59 to 03:00:00, so `sun 02:00-03:00` admits at no moment that day and
  `sun 02:30-03:30` admits from 03:00:00 to 03:29:59. When the clocks go back the repeated times
  happen twice and a window covering them admits during both: on 1 November 2026 01:00 to 01:59
  comes twice, so `sun 01:00-02:00` admits for two hours.
- In a zone that changes at midnight the weekday follows the wall clock too.
  `America/Santiago` goes back on Saturday 4 April 2026 (03:00 UTC on the 5th) from 23:59:59 to
  23:00:00, so `sat 23:00-24:00` admits for two hours. It goes forward from Saturday 5 September
  2026 23:59:59 to Sunday 6 September 01:00:00 (04:00 UTC on the 6th), so `sun 00:00-01:00`
  admits at no moment that day.

It is judged at every sign-in door: LDAP bind, `/auth/simple/login`, the web login, token
refresh and token use, kinit, renewals and service tickets. At the LDAP bind and
`/auth/simple/login` it is judged after the password and before a code or an enrolment is asked
for (and again with the code), so nobody learns a user's hours there without the user's
password, and a refusal answers byte for byte as a wrong password does: LDAP 49 and
`/auth/simple/login` 401 with the same body. The web login judges it when the sign-in starts,
before a code or an enrolment is asked for, and a refused user's sign-in fails as a wrong
password's does; there too nobody learns a user's hours without the user's password. At the KDC it
is judged before any password, as the lockout is: kinit, a renewal or a service ticket outside the
hours gets error 18 (`CLIENT_REVOKED`), which `kinit` shows as *Client's credentials have been
revoked* for any policy refusal. Anyone can ask the KDC for a user's ticket without a password, so
that answer shows that some rule refuses the user at that moment; it does not say which (a lock
answers the same). Tickets already issued run out by themselves. S4U2Self and S4U2Proxy are not
judged by the hours: a service asking for a user is not the user at a keyboard.

A refusal at a sign-in door is a row of the door's kind with the detail `policy:
login-hours (outside login hours)` ([logging.md](logging.md)); the web login's start and
kinit refuse before any password, so their rows are counted in a flood row pair past a
user's first 8 ([logging.md](logging.md#rows)). A stored value that does not
parse (one written to the database by hand, say) refuses the users it applies to as `policy:
unreadable` at the doors that judge the hours, and the server logs one warning naming the
policy and the item, again only when the value changes.

Sessions and connections:

- A web session is refused at every API request while the rule refuses, and works again when
  it no longer does; nothing is revoked.
- An LDAP connection is judged at its bind only.

What it costs: where no OU sets the item, the doors read nothing for it and the policy cache is
not filled for it; the item is followed with the policies' one read every 30 seconds. When a
linked policy first sets it, the cache is filled before the doors judge with it; until that
fill succeeds the doors that judge the hours refuse every user, whatever their OU, admins
included, token refresh and use among them (`policy: unreadable`, at the KDC `not loaded yet`).
The server tries again every second, and unlinking every OU whose policy sets the item ends it.
A policy change applies at once on the server that made it and within about 30 seconds on the
others.

Locked out by this rule: run `lldap policy-unlink --config-file <config> '<ou>'` as the user the
server runs as, for the OU whose policy sets the hours
([Getting back in from the host](#getting-back-in-from-the-host)).

## Inactivity

`inactivity-days` (0 turns it off, up to 3650) refuses a user who has not signed in for that
many days, at every door: LDAP bind, `/auth/simple/login`, the web login, token refresh, token
use, kinit, renewals and service tickets, and a service asking a ticket for the user (S4U2Self,
S4U2Proxy). Nobody is exempt, admins included.

**What counts as a sign-in:** a success at the LDAP bind, `/auth/simple/login`, the web login's
finish, a token refresh, or a ticket issued by kinit. Any proof of the password that the rules
admit counts, a page's password check (a web login finish with `"session": false`) included.
It is written beside the door's success row, after the last check that could still refuse, so a
refused attempt, a wrong password and a refusal on an admin-only server, whose realm did not
open, write nothing. A
token's use writes nothing (its refresh does), and neither does a renewal or a service ticket:
give a client that only renews its tickets a limit longer than `renew_lifetime`. A service's
request for a user (S4U2Self, S4U2Proxy) is judged but never counts, so a user who comes in only
through such a service is refused once the limit passes; give that OU no limit, or re-enable such
users. Each server
writes at most one sign-in an hour for each user, into the table `user_activity`; the first after
a start always writes. Nothing is written while no OU sets the item.

**The four starting points:** a user's idle time is counted from the latest of

- their last recorded sign-in;
- their creation;
- the moment the item last went from off to on anywhere (`inactivity_recording_since` in
  `system_config`, written by the first server that sees the change; `off` while no OU sets
  it);
- their last re-enable.

So linking `inactivity-days = 90` refuses nobody that day, and a user who never signs in is
refused 90 days after the later of their creation and that moment. Exactly 90 days of idle time
is admitted; 90 days and one second is refused. An item turned off and on again within one
30-second read of the policies can go unseen, and the earlier moment then stands. An OU that
takes the item while it is already on elsewhere judges its users on what has been recorded, so a
user truly idle past the new limit is refused at once; the way back is `reenableUser` or
`lldap reenable`, run on the host as the user the server runs as.

**The answer:** at the LDAP bind and `/auth/simple/login`, the door's ordinary refusal, byte for
byte the answer to a wrong password (LDAP 49 and the HTTP 401 body of a wrong password), and it
comes only after the password was right and before a code or an enrolment is asked for (and
again with the code), so nobody learns a user's state there without their password. The web
login judges it when the sign-in starts, and a refused user's sign-in fails as
a wrong password's does; there too nobody learns a user's state without their password. Kerberos
refuses before the password is checked, with code 18 and no text, as for every policy refusal: kinit
prints "Client's credentials have been revoked", and a request for a user's name shows whether some
directory policy refuses that user ([kerberos.md](kerberos.md#inactivity-and-kinit)). The reason is
in the log row only, `policy: inactivity-days (inactive)`. A value that cannot be read refuses with
`policy: unreadable`, and the server logs one warning naming the policy, until the value changes.

**When it cannot be read:** a sign-in the rule cannot judge is refused with `policy:
unreadable`, at the directory's doors and at Kerberos. That is the sign-in of a user whose OU sets
a value that does not parse, and, while the server cannot read `inactivity_recording_since` or the
table `user_activity` as it starts or as the item is linked, of every user whose OU sets it to
anything but 0. A user whose OU sets 0 or nothing signs in as usual. If the policies themselves
cannot be read as the item is linked, every sign-in is refused (`policy: unreadable`, at Kerberos
`not loaded yet`) until they are. While `inactivity_recording_since` or the sign-ins cannot be
read, the server reads them again about a second later, and every five seconds once ten tries in
a row have failed. When a later refill of the policy cache cannot read the sign-ins, every user it
held keeps what was read, and a user first seen in that refill is refused, if their OU sets a
limit, until a read answers. A re-enable does not help. To take the rule off from the host, run
`lldap policy-unlink` for each OU whose policy sets it ([Getting back in from the
host](#getting-back-in-from-the-host)); a running server sees that within 30 seconds.

**Sessions:** a web session is refused at every API request while the rule refuses, and works
again when it no longer does; nothing is revoked. An LDAP connection is judged at its bind only.
A password reset mail does not let an inactive user in: the page that sets the new password
asks with the mail's token, which is refused as any token's use is.

**Re-enable:** an admin's `reenableUser(userId)` over GraphQL (the **Re-enable after
inactivity** button on the user's page while the user is inactive, [Pages](#pages)), or
`lldap reenable` on the host, run as the user the server runs as, restarts the user's
count now (or when a refill in progress ends). Each writes one `account_reenable` row
in its own transaction. A running server takes a re-enable made elsewhere within 30
seconds.

**Servers:** the sign-ins are kept in the database and shared; another server sees one at its
next read of the policy cache (about every 30 seconds), far inside a limit counted in days. A
ticket's sign-in is written off the KDC's thread within a quarter of a second. A sign-in whose
write does not land within its quarter of a second is kept while this server runs and written
once the database answers: a clean stop tries once more for a second, a restart otherwise loses
it, and at most 65,536 users' sign-ins are kept.

## Allowed networks

`allowed-networks` (comma-separated CIDRs; empty, the default, admits any address) refuses a
sign-in from outside the list, at every door: LDAP bind, `/auth/simple/login`, the web login, token
refresh, token use, kinit, renewals and service tickets. A service asking for the user (S4U2Self,
S4U2Proxy) is not judged by it. Nobody is exempt, admins included. At the LDAP bind and
`/auth/simple/login` it is judged after the password and before a code or an enrolment is asked
for (and again with the code), and the answer is a wrong password's; the web login judges it when
the sign-in starts, and a refused user's sign-in fails as a wrong password's does. Kerberos refuses
before the password is checked, with code 18 and no text, and a request for a user's name shows
whether some directory policy refuses that user. The row says
`policy: allowed-networks (address not allowed)`. A list that cannot be read refuses with
`policy: unreadable`. LDAP and Kerberos judge their socket's peer; HTTP judges its TCP peer, or
behind a proxy listed in `trusted_proxies` the forwarded address. Behind Docker's published ports
the server may see the bridge gateway for every client. A list then admits every client or none.
Behind a reverse proxy that is not in `trusted_proxies`, every web request comes from the proxy's
address, with the same result. GraphQL `clientAddress` shows the address the server judges for
you, and a policy write warns when your own list would refuse you. A ticket-granting ticket
forwarded to a server asks for service tickets from that server's address, so that server must be
inside the user's list. Locked out by this rule: run
`lldap policy-unlink --config-file <config> '<ou>'` as the user the server runs as, for the OU
whose policy sets the list (the warning names it). The matcher, the proxies, the measured
addresses and the sessions are in [allowed-networks.md](allowed-networks.md).

## What is recorded

`policy_change` rows: creating/updating/deleting a policy (target = name; detail
`created` / `updated: {field names}` / `deleted`), attaching or clearing an OU
(target = the OU, or `(root)`; detail `policy set: {name}` / `policy cleared: {name}`, and
`policy cleared: {name} (lldap policy-unlink)` from the host tool),
inheritance toggles, and dropping state when an OU is deleted (`ou removed`). A
no-op inheritance toggle is not logged.

## Getting back in from the host

When a rule refuses everyone who could change it, admins included, the host tool works on the
database directly, with the server running or stopped. Run it as the user the server runs as, so
what it writes keeps the server's owner, and give it the server's configuration: the same file and
the same `LLDAP_` variables (on a host install, those the unit or its drop-in sets; `docker exec`
already has the container's). Without them it stops for want of `jwt_secret`, or opens the
database the file alone names (`users.db` in the directory it runs in, when it names none), which
need not be the server's. In the image, run it as
`docker exec -u <UID> <container> /app/lldap <command> --config-file /data/lldap_config.toml …`,
with the uid the image runs the server as (`UID`, or `LLDAP_UID` when set; 1000 by default).

A `policy: unreadable` row names no item. A value that does not parse is named in the server
log's warning, with its policy and item; a read that failed is logged as a warning with its cause
(*The policy cache was not refilled*, *The users' activity was not read*, for example).

| Locked out | Run |
|---|---|
| by the lockout | `lldap unlock --config-file <config> <user>` |
| by this rule: `inactivity-days` | `lldap reenable --config-file <config> <user>` |
| by `inactivity-days` as `policy: unreadable` (its value, `inactivity_recording_since` or the table `user_activity` cannot be read; a re-enable does not help) | `lldap policy-unlink --config-file <config> '<ou>'` |
| by this rule: any item of an OU's policy | `lldap policy-unlink --config-file <config> '<ou>'` |

`lldap policy-unlink` removes the policy link of one OU. `<ou>` is the OU's key
(`people\labs`); the root is `(root)` or `""`. In a shell, quote the key:
`lldap policy-unlink --config-file <config> 'people\labs'`, `'(root)'` for the root. Unlink the OU
whose policy sets the item, which can be a parent of the user's OU or the root, not always the
user's own. If an OU above it on the user's chain also sets the item, that value applies next, so
unlink each OU on the chain whose policy sets it. It writes one `policy_change` row, `policy
cleared: <name> (lldap policy-unlink)` with the OU as target (`(root)` for the root), in the
same transaction, and prints it. An OU with no link is an error and writes nothing. A running
server sees it within 30 seconds. The policy itself is kept: fix it and link it again from the
page.

`lldap reenable` restarts one user's inactivity count now. It writes one `account_reenable` row,
detail `lldap reenable`, with the user as target, in the same transaction, and prints it. An
unknown user is an error and writes nothing. A running server sees it within 30 seconds.

## Configuration

None. The surface is always on (reads for admins and read-only admins, writes for admins).
The lockout is in force wherever an OU sets a threshold, `password-min-length` wherever an OU
sets it (8 elsewhere), `login-hours` wherever an OU sets it, `inactivity-days` wherever an
OU sets it above 0, `allowed-networks` wherever an OU sets a list, and `enable-mfa` wherever
an OU sets it, unless `enable_mfa` is set server-wide, which overrides it. `lldap_mfa_disabled` is made
at start when `enable_mfa` is set server-wide to `enabled` or `always`; otherwise by
whichever server first reads an OU's `enable-mfa` above `off` (at the change, or at its
30-second read), never while the policies are not read.

`login_hours_timezone` (default `UTC`; `LLDAP_LOGIN_HOURS_TIMEZONE`, `--login-hours-timezone`)
is the zone `login-hours` windows are read in: an IANA name such as `America/Chicago`, read
once at start from the system's zone files (`/usr/share/zoneinfo`, or the directory `TZDIR`
names). `UTC` is built in, and the process's own zone (`TZ`) is never read. Name the zone
itself: a name under `right/` (whose files count leap seconds and would move every window by
about half a minute) or `posix/` is refused, and so are `localtime` and `posixrules`, which
name no zone of their own. An unknown name, or a file that is not a zone
file, refuses the start, naming it. The start's log line names the zone and its file. A
tzdata update takes effect at the next start; a host install needs tzdata. `/settings` gives
the zone's name as `login_hours_timezone`.

`trusted_proxies` (default empty; `LLDAP_TRUSTED_PROXIES`, `--trusted-proxies`) lists, as one
string of comma-separated CIDRs, the reverse proxies whose `X-Forwarded-For` the
`allowed-networks` item believes ([allowed-networks.md](allowed-networks.md#whose-address)). A bad
entry refuses the start, naming it.

## Limitations

- `login-hours` has one zone for the whole server, not one per OU; servers that share a database
  each judge in their own, so give them the same `login_hours_timezone`.
- Some reads of the policies have no 2-second bound: the admin's policies page, the policy cache's
  refresh, and the server's start. While `ou_policies` or `policies` is locked, they wait as long
  as the database lets them.
- On MySQL and MariaDB the 2-second bound is set by a different setting on each, chosen by
  which of `max_statement_time` (MariaDB) and `max_execution_time` (MySQL) the server has; a
  server that has both is bounded by `max_statement_time`. The
  server asks once, at its first bounded read, and keeps the answer until it stops. On a server
  that has neither, every bounded read fails: a sign-in that reads a user the policy cache does
  not hold yet is refused (`policy: unreadable`), a password change is refused ("the password
  policy could not be read; try again"), and a save gives no `allowed-networks` warning.
- A lock's duration runs from the last counted attempt, and a web start counts as one until
  its finish takes it back, so the duration can run from a start that then succeeded.
- Kerberos already tells whether a principal exists (an unknown one gets a different error);
  a lock does not change that.
- Depth is root / primary / secondary with one policy each — no AD multi-link stacking.
- `updatePolicy.items` is a wholesale replace.
- Policy applies per OU, not per object.

## What builds on it

`resolve_effective_items` over an OU's levels is the seam every item's enforcement reads:
per-OU MFA, the lockout, password length, login hours, allowed networks and inactivity. The
levels come from `PolicyBackendHandler::get_policy_levels` for the policy cache and the policies
page, and from the bounded reads (`bounded_policy_entry`, `bounded_activity_entry`,
`bounded_policy_levels`) for a user the cache does not hold and for a password change. A sign-in
item also adds its check to `default_item_checks`.
