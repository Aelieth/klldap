#!/bin/bash
# The low-spec phase's flood from a client container (the image's own ldapwhoami and kinit):
#   lowspec-client.sh <ldap|kinit> <seconds> <senders> <count, 0 for none> <target> <name>
# ldap:  target is an ldap:// URL, name a bind DN; kinit: target is unused (KRB5_CONFIG names the
# KDC), name a principal. "{n}" in the name becomes a new number each time. Every password is wrong.
# Prints: sent=<n> seconds=<s> senders=<n> answers=<answer>:<count>,...
# An ldap answer is ldapwhoami's exit code (49 invalid credentials, 51 busy, 255 no connection,
# 124 no answer in 20 s); a kinit answer is incorrect, revoked, ticket, timeout or other.

set -u
mode="${1:?mode}" seconds="${2:?seconds}" senders="${3:?senders}" count="${4:?count}"
target="${5:?target}" name="${6:?name}"
dir="${TMPDIR:-/tmp}/lowspec.$$"
mkdir -p "$dir" || exit 1
end=$((SECONDS + seconds))
bound=()
command -v timeout >/dev/null 2>&1 && bound=(timeout 20)

one() {
    local who="${name//\{n\}/$1-$2}" out rc
    case "$mode" in
    ldap)
        "${bound[@]}" ldapwhoami -x -o nettimeout=10 -H "$target" -D "$who" -w "wrong-$1-$2" >/dev/null 2>&1
        echo "$?"
        ;;
    kinit)
        out="$(printf '%s\n' "wrong-$1-$2" | KRB5CCNAME="${KRB5CCNAME:-$dir/cc}.$1" "${bound[@]}" kinit "$who" 2>&1)"
        rc=$?
        case "$rc:$out" in
        0:*) echo ticket ;;
        124:*) echo timeout ;;
        *"Password incorrect"*) echo incorrect ;;
        *revoked*) echo revoked ;;
        *) echo other ;;
        esac
        ;;
    *) echo "unknown-mode" ;;
    esac
}

sender() {
    local n=0 answer key
    local -A seen=()
    while [ "$SECONDS" -lt "$end" ] && { [ "$count" = 0 ] || [ "$n" -lt "$count" ]; }; do
        n=$((n + 1))
        answer="$(one "$1" "$n")"
        seen[$answer]=$((${seen[$answer]:-0} + 1))
    done
    for key in "${!seen[@]}"; do
        printf '%s %s\n' "$key" "${seen[$key]}"
    done >"$dir/$1.tally"
}

i=0
while [ "$i" -lt "$senders" ]; do
    sender "$i" &
    i=$((i + 1))
done
wait

declare -A total=()
sent=0
while read -r key n; do
    total[$key]=$((${total[$key]:-0} + n))
    sent=$((sent + n))
done < <(cat "$dir"/*.tally 2>/dev/null)
answers=""
for key in $(printf '%s\n' "${!total[@]}" | sort); do
    answers+="${answers:+,}$key:${total[$key]}"
done
rm -rf "$dir"
printf 'sent=%s seconds=%s senders=%s answers=%s\n' "$sent" "$SECONDS" "$senders" "${answers:-none}"
