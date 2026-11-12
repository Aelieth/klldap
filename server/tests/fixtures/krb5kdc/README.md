# Kerberos migration fixture

`principal.dump` and `.k5.LIVEBOB.TEST` are the dump and the stash of a throwaway realm,
`LIVEBOB.TEST`, made once with the MIT tools of the `aelieth/klldap:0.7.2` image. They hold
test keys only. `server/tests/kerberos.rs` boots on them to check that a 0.7.2 realm migrates.

The realm has one user principal, `livebob`, password `LivebobPass2026!`, pre-authentication
required, renewable for 7 days. It was made in a container of that image whose
`/var/kerberos/krb5kdc` started empty (the third line left pre-authentication off; the fourth
sets it):

    docker exec migfix-live kdb5_util -r LIVEBOB.TEST create -s -P FixtureMaster2026!
    docker exec -e KRB5CCNAME=MEMORY:cc migfix-live kadmin.local -r LIVEBOB.TEST -q "addprinc -pw LivebobPass2026! livebob"
    docker exec -e KRB5CCNAME=MEMORY:cc migfix-live kadmin.local -r LIVEBOB.TEST -q "modprinc -requires_preauth -maxrenewlife 7d livebob"
    docker exec -e KRB5CCNAME=MEMORY:cc migfix-live kadmin.local -r LIVEBOB.TEST -q "modprinc +requires_preauth livebob"

and dumped with the command the upgrade guide gives for a stopped container:

    docker run --rm --entrypoint kdb5_util -v <that krb5kdc directory>:/var/kerberos/krb5kdc aelieth/klldap:0.7.2 -r LIVEBOB.TEST dump /var/kerberos/krb5kdc/principal.dump
