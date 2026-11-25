# Allowed networks

The OU policy item `allowed-networks` ([policies.md](policies.md)) limits where a user may sign
in from: a comma-separated list of networks in CIDR form, each with an explicit prefix
(`10.0.0.0/8, 2001:db8::/32`). Empty, the default, admits any address. Behind Docker's published
ports the server may see one address, the bridge gateway, for every client, and a list then admits
everyone or no one: check `clientAddress` (shown on the policies page) before you save a list
([Behind Docker's published ports](#behind-dockers-published-ports)).

## The rule

- **Matching:** an address is inside a network when its first *prefix* bits equal the network's.
  The host bits of an entry are ignored, so `10.0.0.1/8` is `10.0.0.0/8`. `/0` is every address
  of its family, `/32` (IPv4) and `/128` (IPv6) one address. An IPv4 network never matches an
  IPv6 address, and the reverse. An IPv4 address seen over IPv6 (`::ffff:192.0.2.7`) is the IPv4
  address `192.0.2.7`. An entry written as an IPv4-mapped IPv6 network (`::ffff:192.0.2.0/120`)
  matches nothing; write the IPv4 network (`192.0.2.0/24`).
- **No address:** under a non-empty list, a request that carries no address is refused.
- **A value that cannot be read** (stored before a validator change, or written to the database
  by hand) refuses with `policy: unreadable`, and the server logs one warning naming the policy
  and the item, until the value changes. When a linked policy first sets a list, the policy cache
  is filled before the doors judge with it; until that fill succeeds the doors that judge the list
  refuse every user, whatever their OU, admins included, token refresh and use among them
  (`policy: unreadable`, at the KDC `not loaded yet`). The server tries again every second, and
  unlinking every OU whose policy sets the item ends it.
- **Doors:** the LDAP bind, `/auth/simple/login`, the web login, token refresh, token use, kinit,
  renewals and service tickets. A service asking a ticket for the user (S4U2Self, S4U2Proxy) is
  not judged by this item: the user is not at a keyboard there and has no address. Nobody is
  exempt, admins included.
- **The answer:** at the LDAP bind and `/auth/simple/login` the check comes after the password,
  and the answer is byte for byte a wrong password's (LDAP 49 and the HTTP 401 body of a wrong
  password). The web login judges it when the sign-in starts, and a refused user's sign-in fails
  as a wrong password's does. For a user with a second factor it also comes before the code is asked
  for. At the bind and `/auth/simple/login` nobody learns a user's list without that user's
  password; a refusal at any door counts nothing toward the lockout. Kerberos refuses before
  the password is checked, with code 18 and no text, as for every policy refusal: kinit prints
  "Client's credentials have been revoked", and a request for a user's name shows whether some
  directory policy refuses that user. The reason is in the log row only: `policy: allowed-networks
  (address not allowed)`.
- **Sessions:** a web session is refused at every API request while the rule refuses, and works
  again when it no longer does; nothing is revoked. An LDAP connection is judged at its bind
  only. A ticket-granting ticket forwarded to a server asks for service tickets from that
  server's address, so that server must be inside the user's list.

## Whose address

| Door | The address judged |
|---|---|
| LDAP | the TCP peer, always |
| Kerberos | the KDC's TCP or UDP peer, always |
| HTTP (`/auth/*`, GraphQL) | the TCP peer; behind a listed proxy, the forwarded address below |

**`trusted_proxies`** (default empty; `LLDAP_TRUSTED_PROXIES`, `--trusted-proxies`) is one string of
comma-separated CIDRs in the item's grammar: the reverse proxies whose `X-Forwarded-For` header the
server believes. As in the item, an entry written as an IPv4-mapped IPv6 network
(`::ffff:10.9.0.1/128`) matches nothing; write the IPv4 network (`10.9.0.1/32`).

- Only when a request's TCP peer is inside one of them is the header read.
- It is read from the right, over every `X-Forwarded-For` line of the request taken as one list in
  order. The first address that is not itself a listed proxy is the client's address.
- If every entry is a listed proxy, the left-most one is taken.
- An entry that is not a bare address (a port, brackets, a name such as `unknown`, an empty
  element, a line that is not text), met before that address is found, leaves the client's address
  unknown: under a non-empty list the request is refused, and `clientAddress` answers null.
- A listed proxy that sends no `X-Forwarded-For` at all is itself the client: that is a request
  made on the proxy's own host.
- With the list empty, the header is never read for a decision.
- A request through a reverse proxy that is not listed is judged at the proxy's address: every
  web request through it comes from that one address, and a list admits all of them or none.
- A bad entry refuses the start, naming it. The start's log line says which proxies are believed.

List only your own proxies: anyone connecting from a listed address can name any client address.
List a proxy in `trusted_proxies` only if it appends the address it saw to `X-Forwarded-For`, as
nginx's `$proxy_add_x_forwarded_for` and HAProxy's `option forwardfor` do: a proxy that passes the
client's own header through lets the client name any address. An allowed list that contains a
proxy's own address admits requests made from that host itself.

The `Forwarded` header (RFC 7239) is not read in 0.8.1. RFC 7239 section 8.1 says of that header
that it "cannot be relied upon to be correct, as it may be modified, whether mistakenly or for
malicious reasons, by every node on the way to the server, including the client making the
request"; the same holds for `X-Forwarded-For`, which is why only the listed proxies are believed.

**LDAP behind a TCP proxy** (HAProxy in TCP mode, an nginx `stream` block, a load balancer) is seen
as the proxy: the PROXY protocol is not read. Under a networks list the proxy's address must then
be in the list, and every client of that proxy is judged as the proxy.

**The log row keeps `peer` and `forwarded_for` as they came** ([logging.md](logging.md#proxies-and-privacy)):
a refusal behind a proxy shows the proxy as `peer`, and the judged address is in `forwarded_for`
when it came from the header.

## Behind Docker's published ports

Behind Docker's published ports the server may see the bridge gateway for every client. Then a
networks list either refuses everyone or admits everyone. Use host networking or a host install,
or for the web a reverse proxy the server can see, listed in `trusted_proxies`. The policies page
shows the address the server sees you as: check it before you save a list.

Measured on one host (Docker bridge network, published ports, the userland proxy on, which is
Docker's default), with a container started in this shape:

```
docker run -d --name klldap-addr-cell --network bridge \
  -p 127.0.0.1:13890:3890 -p 192.168.177.1:13890:3890 \
  -p 127.0.0.1:11717:17170 -p 192.168.177.1:11717:17170 \
  -p 127.0.0.1:10088:1088/tcp -p 192.168.177.1:10088:1088/tcp \
  -p 127.0.0.1:10088:1088/udp -p 192.168.177.1:10088:1088/udp \
  -v klldap-addr-cell-data:/data -v klldap-addr-cell-kdc:/var/kerberos/krb5kdc \
  -e LLDAP_LDAP_BASE_DN=dc=example,dc=com -e LLDAP_VERBOSE=true \
  -e LLDAP_LDAP_USER_PASS -e LLDAP_JWT_SECRET -e LLDAP_KEY_SEED \
  aelieth/klldap:0.8.1
```

The container's address was 172.17.0.3 and its gateway 172.17.0.1. The address is the peer on
the server's own log row:

| from | door | address on the log row | what that address is |
| --- | --- | --- | --- |
| host, published 127.0.0.1 | kerberos | 172.17.0.1 | bridge gateway |
| host, published 127.0.0.1 | ldap | 172.17.0.1 | bridge gateway |
| host, published 127.0.0.1 | http | 172.17.0.1 | bridge gateway |
| guest 192.168.177.30, published 192.168.177.1 | kerberos | 172.17.0.1 | bridge gateway |
| guest 192.168.177.30, published 192.168.177.1 | ldap | 172.17.0.1 | bridge gateway |
| guest 192.168.177.30, published 192.168.177.1 | http | 172.17.0.1 | bridge gateway |
| inside, the container's own listeners | kerberos | 127.0.0.1 | loopback |
| inside, the container's own listeners | ldap | 127.0.0.1 | loopback |
| inside, the container's own listeners | http | 127.0.0.1 | loopback |

None of the nine is the client's address. A client on the same Docker network as the server,
talking to the container's own address, is seen as itself.

The same holds for `mfa_proof_same_address` ([kerberos.md](kerberos.md#a-second-factor-and-kinit)): behind published ports
the directory's sign-in and the kinit both come from the gateway, so the two addresses are then
always equal. With `mfa_proof_same_address` on and a reverse proxy in front, the window's address
is the proxy's.

## What the server sees

Any signed-in user can ask which address the server judges for their own request:

```graphql
{ clientAddress }
```

It answers the address after `trusted_proxies` (for example `"172.17.0.1"` behind published
ports), or `null` when it has none: no address at all, or a listed proxy's `X-Forwarded-For` with
an entry that is not a bare address.

The policies page shows the same answer beside the `allowed-networks` field: *The server sees you
as 172.17.0.1*, or *The server sees you as unknown* for `null`.

**Saving a list:** `updatePolicy`, `setOuPolicy`, `setOuPolicyInheritance`, `clearOuPolicy` and
`deletePolicy` succeed as before and return `warnings`. When, after the write, your own effective
list refuses the address the server sees you as (`unknown` when it has none), it holds one warning,
which names the OU whose policy sets that list:

```
allowed-networks: the list that now applies to you does not contain the address the server sees you as (172.17.0.1). The way back, on the host: lldap policy-unlink --config-file <config> 'people'
```

It is never a refusal: an admin may be setting a rule for others from elsewhere. Your own next
request is refused, though, as any request from outside the list is. A policy that does not reach
you gives none. Other writes give none, moving your own user to another OU included: check
`clientAddress` first. Only this item is checked against you at a save: a `login-hours` value
that applies to you and leaves out the present moment gives no warning, and refuses your next
request.

The policies page shows the warning under the save's success line. When the page's next request is
then refused, it says so in one line, with `lldap policy-unlink` as the way back, instead of an
error.

## Locked out by this rule

When a list refuses everyone who could change it, run on the host, as the user the server runs as,
with the server running or stopped:

```
lldap policy-unlink --config-file <config> '<ou>'
```

`<ou>` is the key of the OU whose policy sets the list (`'people\labs'`), or `'(root)'` for the
root; in a shell, quote it as shown. That OU can be a parent of the user's OU or the root, not
always the user's own: it is the OU a save's warning names. If an OU above it on the user's chain
also sets a list, that list applies next, so unlink each OU on the chain whose policy sets one. It
removes that link and writes one `policy_change` row; a running server sees it within 30 seconds
([policies.md](policies.md#getting-back-in-from-the-host)). Fix the list and link it again.
