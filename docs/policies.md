# Organizational-unit policies

KLLDAP can attach a named policy of **items** to an OU, including the domain root
(`dc=example,dc=com` → the empty key `""`). An object resolves each item by walking its
OU chain. This pass stores and resolves those values; **nothing is enforced at login,
bind, or any other door yet**. Each later pass consumes the same resolution at its seam.

## Resolution

The chain is root-first: `people\labs` walks `""` → `people` → `people\labs`. Closest
wins: the deepest OU that sets an item is the source. An OU may **block inheritance**;
the chain then restarts at that OU (its own policy still applies). The root cannot block.
One policy per OU; a policy may still be linked to many OUs. Server-scope items (none in
v1) always resolve from the root only.

Example: root policy sets `require-mfa=off`, `people\labs` sets `require-mfa=always`. A
user in `people\labs` sees `always` with source `people\labs`. If `people\labs` blocks
inheritance, root's other items no longer apply there.

## Using it

Admin-only GraphQL. Item values are strings: bools `true`/`false`, ints base-10 in range,
enums exact tokens, lists comma-separated. `login-hours` is empty (always) or
`;`-separated `DAY[-DAY] HH:MM-HH:MM` (`mon-fri 08:00-18:00`). `allowed-networks` is
comma-separated CIDR with an explicit prefix.

```graphql
{ policyItemCatalog { key scope defaultValue enforced description } }
mutation { createPolicy(name: "Hours", items: [{key: "require-mfa", value: "always"}]) { id } }
mutation { setOuPolicy(ou: "", policyId: 1) { ok } }
mutation { setOuPolicyInheritance(ou: "people", blocked: true) { ok } }
{ effectivePolicyItems(ou: "people\\labs") { key value enforced sourceOu sourcePolicyName } }
{ ouPolicyStates { ou policyId policyName blockInheritance } }
```

`ou` `""` is the domain root. `linkedOus` on a policy uses the same keys. The web pages
are a later pass.

## What is recorded

`policy_change` rows: creating/updating/deleting a policy (target = name; detail
`created` / `updated: {field names}` / `deleted`), attaching or clearing an OU
(target = the OU, or `(root)`; detail `policy set: {name}` / `policy cleared: {name}`),
inheritance toggles, and dropping state when an OU is deleted (`ou removed`). A
no-op inheritance toggle is not logged.

## Configuration

None. The surface is always on, admin-only, and inert until an enforcement pass.

## Limitations

- Nothing is enforced yet. Catalog and effective items carry `enforced: false` and say so
  in their descriptions; per-item passes follow.
- Depth is root / primary / secondary with one policy each — no AD multi-link stacking.
- `updatePolicy.items` is a wholesale replace.
- Policy applies per OU, not per object.

## What builds on it

`PolicyBackendHandler::get_policy_levels` plus `resolve_effective_items` is the seam
each later enforcement pass consumes (per-OU MFA, lockout, login hours, networks,
inactivity). The UI pass adds the pages and shows the domain root as `EXAMPLE.COM`.
