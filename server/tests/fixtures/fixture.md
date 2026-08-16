# Stock lldap migration fixture

Genuine artifacts from stock upstream lldap **v0.6.3** (schema **v11**), produced by
`scripts/generate_lldap_fixture.sh` on 2026-08-15 from commit `48a0a8d961f32bd8e3263b202053ce49a6c94781`:
the server booted on a fresh SQLite database, all content was created through its
GraphQL API, and both passwords were registered through the real OPAQUE flows
(admin at first boot, bob via `lldap_set_password`). `lldap_v11.sql` is the
python-`iterdump` of the resulting database. Consumed by
`server/tests/migration_compat.rs`, which adopts it under a fresh key: the stock
passwords are only asserted to be gone.

## Constants (asserted by the test — keep in sync with the script)

| What | Value |
|---|---|
| admin password | `FixtureAdminPass2026!` |
| bob password | `FixtureBobPass2026!` |
| bob email / display / first / last | `bob@example.com` / `Bob Fixture` / `Bincode Bob` / `Fixtureson` |
| bob avatar + `fixturejpeg` (JPEG_PHOTO) | the 649-byte JPEG, base64 in the script; byte-identical after migration |
| `fixturedate` (DATE_TIME) | `2024-05-01T12:00:00Z` (epoch 1714564800 after re-encode) |
| `fixturetags` (STRING list) | `["alpha", "beta"]` |
| `fixturenumber` (INTEGER) | `4242` |
| group | `Fixture Crew`, member: bob, `fixturegroupnote` = `stock group attribute survives` |
| charlie | no password ever registered (bind must fail cleanly) |

UUIDs and creation/modification dates are whatever generation produced — the test
asserts the constants above, not those. Regeneration rewrites both files; diff
before committing.
