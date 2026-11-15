#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
    cat <<EOF
Docker only, any tag: the script decides from the image itself. Podman installs follow the manual steps in docs/kerberos.md.

usage: $0 [--yes] CONTAINER [BACKUP_DIR]
       $0 --verify CONTAINER BACKUP_DIR

Without --yes, print the plan and change nothing.
--yes stops the 0.7.2 container, backs up both mounts, writes principal.dump
with that container's image, and prints the edits. It does not start 0.8.0.
--verify checks the 0.8.0 container against the backup directory.
EOF
}

yes=0
verify=0
container=""
backup=""
while [ $# -gt 0 ]; do
    case "$1" in
        --help | -h)
            usage
            exit 0
            ;;
        --yes)
            yes=1
            shift
            ;;
        --verify)
            verify=1
            shift
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "unknown option $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            if [ -z "$container" ]; then
                container=$1
            elif [ -z "$backup" ]; then
                backup=$1
            else
                echo "too many arguments" >&2
                usage >&2
                exit 1
            fi
            shift
            ;;
    esac
done

if [ "$verify" -eq 1 ] && [ "$yes" -eq 1 ]; then
    echo "--verify and --yes are different runs" >&2
    exit 1
fi
if [ -z "$container" ]; then
    usage >&2
    exit 1
fi
if [ "$verify" -eq 1 ] && [ -z "$backup" ]; then
    echo "--verify needs the backup directory from the prepare run" >&2
    exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "Docker only, any tag: the script decides from the image itself. This host has no docker. Podman installs follow the manual steps in docs/kerberos.md." >&2
    exit 1
fi

runid="$(date +%Y%m%d-%H%M%S)-$$"
case "$runid" in
    *[!0-9-]*)
        echo "internal run id is not safe" >&2
        exit 1
        ;;
esac

ok=0
stopped=0
began_running=0
wrote_dump=0
backup_begun=0
image_id=""
kdc_spec=""
name=""

# shellcheck disable=SC2329
undo() {
    local moved="none"
    if [ "$backup_begun" -eq 1 ]; then
        echo "backup directory ${backup_abs} is incomplete"
    fi
    if [ "$wrote_dump" -eq 1 ]; then
        moved="$(docker run --rm --entrypoint bash \
            -v "${kdc_spec}:/kdc" \
            "$image_id" \
            -c 'if [ -f /kdc/principal.dump ]; then mv /kdc/principal.dump /kdc/principal.dump.'"$runid"'; printf moved; else printf none; fi')" || moved="none"
        if [ "$moved" = moved ]; then
            echo "moved this run's principal.dump aside to principal.dump.${runid}"
        else
            echo "this run left no principal.dump"
        fi
    else
        echo "this run wrote no principal.dump"
    fi
    if [ "$began_running" -eq 1 ]; then
        if docker start "$name" >/dev/null; then
            echo "started ${name} again"
        else
            echo "could not start ${name} again. Start it with: docker start ${name}" >&2
        fi
    else
        echo "${name} was not running at the start, so it was left stopped"
    fi
}

# shellcheck disable=SC2329
on_exit() {
    rc=$?
    trap - EXIT
    if [ "$ok" -eq 1 ] || [ "$stopped" -eq 0 ]; then
        exit "$rc"
    fi
    undo || true
    exit "$rc"
}
trap on_exit EXIT

image_is_072() {
    docker run --rm --entrypoint bash "$1" -c '[ -x /usr/sbin/kdb5_util ] || [ -x /usr/bin/kdb5_util ] && [ -x /app/kerberos_manager ]'
}

mount_fields() {
    docker inspect -f '{{range .Mounts}}{{.Type}}{{"\u0000"}}{{.Name}}{{"\u0000"}}{{.Source}}{{"\u0000"}}{{.Destination}}{{"\u0000"}}{{end}}' "$1"
}

realm_ok() {
    case "$1" in
        "" | *[!A-Za-z0-9.-]*)
            return 1
            ;;
    esac
    return 0
}

read_realm() {
    local env_text toml kdc_text line value
    env_text="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$name")"
    realm=""
    while IFS= read -r line; do
        case "$line" in
            LLDAP_KERB_REALM_NAME=)
                ;;
            LLDAP_KERB_REALM_NAME=*)
                realm="${line#LLDAP_KERB_REALM_NAME=}"
                ;;
            LLDAP_KEYCLOAK_ADMIN_PASS=*)
                keycloak_set=yes
                ;;
        esac
    done <<<"$env_text"
    if realm_ok "$realm"; then
        return 0
    fi
    realm=""
    toml="$(docker run --rm --entrypoint bash \
        -v "${data_spec}:/data:ro" \
        "$image_id" \
        -c 'if [ -f /data/kerberos_config.toml ]; then cat /data/kerberos_config.toml; fi')"
    while IFS= read -r line; do
        case "$line" in
            realm_name*)
                value="${line#*=}"
                value="${value#"${value%%[![:space:]]*}"}"
                value="${value%\"}"
                value="${value#\"}"
                if realm_ok "$value"; then
                    realm=$value
                fi
                ;;
        esac
    done <<<"$toml"
    if realm_ok "$realm"; then
        return 0
    fi
    realm=""
    kdc_text="$(docker run --rm --entrypoint bash \
        -v "${kdc_spec}:/kdc:ro" \
        "$image_id" \
        -c 'if [ -f /kdc/kdc.conf ]; then cat /kdc/kdc.conf; fi')"
    while IFS= read -r line; do
        line="${line#"${line%%[![:space:]]*}"}"
        case "$line" in
            *=*\{*)
                value="${line%%=*}"
                value="${value%"${value##*[![:space:]]}"}"
                if realm_ok "$value"; then
                    realm=$value
                fi
                ;;
        esac
    done <<<"$kdc_text"
}

mount_size() {
    docker run --rm --entrypoint du \
        -v "$1:/src:ro" \
        "$image_id" \
        -sb /src | awk '{print $1}'
}

file_there() {
    docker run --rm --entrypoint bash \
        -v "$1:/mnt:ro" \
        "$image_id" \
        -c 'test -f "/mnt/$1"' _ "$2"
}

start_080() {
    return 0
}

compose_of() {
    local value
    value="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$name" 2>/dev/null || true)"
    case "$value" in
        "" | "<no value>") compose_project="" ;;
        *) compose_project=$value ;;
    esac
    value="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$name" 2>/dev/null || true)"
    case "$value" in
        "" | "<no value>") compose_service="" ;;
        *) compose_service=$value ;;
    esac
}

binding_text() {
    local ip="$1" hport="$2" cport="$3" proto="$4" force="$5"
    if [ -n "$ip" ]; then
        case "$ip" in
            *:*) printf '[%s]:%s:%s/%s' "$ip" "$hport" "$cport" "$proto" ;;
            *) printf '%s:%s:%s/%s' "$ip" "$hport" "$cport" "$proto" ;;
        esac
        return 0
    fi
    if [ -z "$hport" ]; then
        if [ "$force" = yes ] || [ "$proto" != tcp ]; then
            printf '%s/%s' "$cport" "$proto"
        else
            printf '%s' "$cport"
        fi
        return 0
    fi
    if [ "$force" = yes ] || [ "$proto" != tcp ]; then
        printf '%s:%s/%s' "$hport" "$cport" "$proto"
    else
        printf '%s:%s' "$hport" "$cport"
    fi
}

read_ports() {
    local rec key rest ip hport cport proto force
    port_kind=()
    port_old=()
    port_new=()
    kerberos_ports=0
    while IFS= read -r rec || [ -n "$rec" ]; do
        [ -n "$rec" ] || continue
        key=${rec%%|*}
        rest=${rec#*|}
        ip=${rest%%|*}
        hport=${rest#*|}
        case "$ip" in
            "" | 0.0.0.0) ip="" ;;
        esac
        cport=${key%%/*}
        proto=${key#*/}
        force=no
        case "$cport" in
            88 | 749) force=yes ;;
        esac
        case "$cport" in
            88)
                kerberos_ports=$((kerberos_ports + 1))
                port_kind+=(replace)
                port_old+=("$(binding_text "$ip" "$hport" 88 "$proto" "$force")")
                port_new+=("$(binding_text "$ip" "$hport" 1088 "$proto" "$force")")
                ;;
            749)
                port_kind+=(delete)
                port_old+=("$(binding_text "$ip" "$hport" 749 "$proto" "$force")")
                port_new+=("")
                ;;
            *)
                port_kind+=(leave)
                port_old+=("$(binding_text "$ip" "$hport" "$cport" "$proto" "$force")")
                port_new+=("")
                ;;
        esac
    done < <(docker inspect -f '{{range $p, $conf := .HostConfig.PortBindings}}{{range $conf}}{{$p}}|{{.HostIp}}|{{.HostPort}}
{{end}}{{end}}' "$name" 2>/dev/null || true)
}

print_port_actions() {
    local style="$1" i=0 n lead bt='`'
    n=${#port_kind[@]}
    if [ "$n" -eq 0 ]; then
        echo "ports:        this container publishes no Kerberos port"
        echo "              the KDC's port in the container moved from 88 to 1088; clients that reach the container directly must use 1088"
        return 0
    fi
    while [ "$i" -lt "$n" ]; do
        if [ "$i" -eq 0 ]; then
            lead="ports:        "
        else
            lead="              "
        fi
        case "${port_kind[$i]}" in
            replace)
                if [ "$style" = quote ]; then
                    printf '%sreplace "%s" with "%s"\n' "$lead" "${port_old[$i]}" "${port_new[$i]}"
                else
                    printf '%sreplace %s-p %s%s with %s-p %s%s\n' "$lead" "$bt" "${port_old[$i]}" "$bt" "$bt" "${port_new[$i]}" "$bt"
                fi
                ;;
            delete)
                if [ "$style" = quote ]; then
                    printf '%sdelete "%s"\n' "$lead" "${port_old[$i]}"
                else
                    printf '%sdelete %s-p %s%s\n' "$lead" "$bt" "${port_old[$i]}" "$bt"
                fi
                ;;
            leave)
                if [ "$style" = quote ]; then
                    printf '%sleave "%s" unchanged\n' "$lead" "${port_old[$i]}"
                else
                    printf '%sleave %s-p %s%s unchanged\n' "$lead" "$bt" "${port_old[$i]}" "$bt"
                fi
                ;;
        esac
        i=$((i + 1))
    done
    if [ "$kerberos_ports" -eq 0 ]; then
        echo "              this container publishes no Kerberos port"
        echo "              the KDC's port in the container moved from 88 to 1088; clients that reach the container directly must use 1088"
    fi
}

print_env_actions() {
    local style="$1"
    if [ -n "$realm" ]; then
        if [ "$style" = run ]; then
            printf 'environment:  add -e LLDAP_KERBEROS_OPTIONS__REALM=%s\n' "$realm"
        else
            printf 'environment:  add LLDAP_KERBEROS_OPTIONS__REALM=%s\n' "$realm"
        fi
        echo "              delete LLDAP_KERB_REALM_NAME (0.8.0 ignores it)"
    else
        echo "environment:  delete LLDAP_KERB_REALM_NAME (0.8.0 ignores it)"
    fi
    if [ "$keycloak_set" = yes ]; then
        echo "              rename LLDAP_KEYCLOAK_ADMIN_PASS to LLDAP_KEYCLOAK_OPTIONS__ADMIN_PASS (keep its value)"
    else
        echo "              LLDAP_KEYCLOAK_ADMIN_PASS was not set"
    fi
}

quote_arg() {
    local spec="$1"
    case "$spec" in
        *[!A-Za-z0-9_./-]*)
            printf '%q' "$spec"
            ;;
        *)
            printf '%s' "$spec"
            ;;
    esac
}

mount_text() {
    local spec="$1" dest="$2"
    case "$spec" in
        *[!A-Za-z0-9_./-]*)
            printf -- '-v %q:%s' "$spec" "$dest"
            ;;
        *)
            printf -- '-v %s:%s' "$spec" "$dest"
            ;;
    esac
}

print_compose_block() {
    echo "edits_for_compose"
    if [ -n "$compose_project" ]; then
        echo "install looks like compose project ${compose_project} service ${compose_service}"
    fi
    if [ -n "$compose_service" ]; then
        echo "In the compose file, service ${compose_service}:"
    else
        echo "In the compose file:"
    fi
    echo "image:        change to aelieth/klldap:0.8.0"
    print_port_actions quote
    print_env_actions compose
    echo "a configuration that does not set kerberos_options.enabled now starts a realm; set enabled = false to stay without one"
    echo "then run:     docker compose up -d"
    echo "the service name does not change, so the container name stays ${name}"
    printf 'then run:     %s --verify %s %s\n' "$self" "$name" "$(quote_arg "$backup_abs")"
    echo "edits_for_compose_end"
}

print_run_block() {
    echo "edits_for_docker_run"
    echo "For docker run:"
    echo "the old container must be renamed or removed before a new one takes its name; this script never removes it"
    echo "docker rename ${name} ${name}-0.7.2"
    echo "image:        change to aelieth/klldap:0.8.0"
    print_port_actions tick
    print_env_actions run
    echo "a configuration that does not set kerberos_options.enabled now starts a realm; set enabled = false to stay without one"
    printf 'volumes:      %s\n' "$(mount_text "$data_spec" /data)"
    printf '              %s\n' "$(mount_text "$kdc_spec" /var/kerberos/krb5kdc)"
    echo "name:         --name ${name}"
    printf 'then run:     %s --verify %s %s\n' "$self" "$name" "$(quote_arg "$backup_abs")"
    echo "edits_for_docker_run_end"
}

print_edits() {
    compose_of
    read_ports
    echo "0.7.2 is stopped. Apply one of the two blocks, then start 0.8.0 yourself."
    if [ -n "$compose_project" ]; then
        print_compose_block
        print_run_block
    else
        print_run_block
        print_compose_block
    fi
}

write_copy() {
    local label="$1" spec="$2" hex restore
    docker run --rm --entrypoint bash \
        -v "${spec}:/src:ro" \
        -v "${backup_abs}:/backup" \
        "$image_id" \
        -c 'mkdir -p /backup/'"$label"' && cp -a /src/. /backup/'"$label"'/'
    docker run --rm --entrypoint bash \
        -v "${backup_abs}/${label}:/tree:ro" \
        "$image_id" \
        -c 'shopt -s nullglob dotglob
walk() {
  local d="$1" e name hash
  for e in "$d"/*; do
    name=${e##*/}
    case "$name" in .|..) continue ;; esac
    if [ -L "$e" ]; then
      printf "link %s link %s\n" "$(stat -c "%a %u %g %s" "$e")" "${e#/tree/}"
    elif [ -d "$e" ]; then
      printf "dir %s dir %s\n" "$(stat -c "%a %u %g %s" "$e")" "${e#/tree/}"
      walk "$e"
    elif [ -f "$e" ]; then
      hash=$(sha256sum "$e" | awk "{print \$1}")
      printf "file %s %s %s\n" "$(stat -c "%a %u %g %s" "$e")" "$hash" "${e#/tree/}"
    fi
  done
}
walk /tree' | LC_ALL=C sort >"${backup_abs}/${label}.list"
    hex="$(sha256sum "${backup_abs}/${label}.list" | awk '{print $1}')"
    restore="$(printf 'docker run --rm --entrypoint bash -v %q:/backup:ro -v <new-empty-volume>:/dest %q -c %q' \
        "$backup_abs" "$image_id" "cp -a /backup/${label}/. /dest/")"
    printf '%s  %s.list\nRestore into an empty volume. This script never empties or deletes a volume.\n%s\n' \
        "$hex" "$label" "$restore" | tee "${backup_abs}/${label}.list.sha256"
}

db_outside() {
    local line url class
    url=""
    db_external=no
    db_file=no
    while IFS= read -r line; do
        case "$line" in
            LLDAP_DATABASE_URL_FILE=) ;;
            LLDAP_DATABASE_URL_FILE=*)
                db_file=yes
                ;;
            LLDAP_DATABASE_URL=) ;;
            LLDAP_DATABASE_URL=*)
                url="${line#LLDAP_DATABASE_URL=}"
                ;;
        esac
    done <<<"$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$name")"
    if [ -n "$url" ]; then
        case "$url" in
            sqlite:*) db_external=no ;;
            *) db_external=yes ;;
        esac
        return 0
    fi
    class="$(docker run --rm --entrypoint bash \
        -v "${data_spec}:/data:ro" \
        "$image_id" \
        -c 'url=""
if [ -f /data/lldap_config.toml ]; then
  while IFS= read -r line; do
    case "$line" in
      \#*) ;;
      database_url*)
        url=${line#*=}
        url=${url#"${url%%[![:space:]]*}"}
        url=${url%\"}
        url=${url#\"}
        ;;
    esac
  done < /data/lldap_config.toml
fi
case "$url" in
  ""|sqlite:*) printf internal ;;
  *) printf external ;;
esac')"
    if [ "$class" = external ]; then
        db_external=yes
    fi
}

check_dump() {
    local count
    count="$(docker run --rm --entrypoint bash \
        -v "${kdc_spec}:/kdc:ro" \
        "$image_id" \
        -c 'IFS= read -r line < /kdc/principal.dump || exit 2
case "$line" in
"kdb5_util load_dump version "*) ;;
*) exit 3 ;;
esac
n=0
tab=$(printf "\t")
while IFS= read -r line; do
  case "$line" in
    princ*)
      rest=${line#princ}
      if [ "${rest#"$tab"}" != "$rest" ]; then n=$((n + 1)); fi
      ;;
  esac
done < /kdc/principal.dump
if [ "$n" -lt 1 ]; then exit 4; fi
printf "%s\n" "$n"')"
    printf '%s\n' "$count" >"${backup_abs}/dump_count"
    printf '%s\n' "$realm" >"${backup_abs}/realm"
    echo "dump_count ${count}"
}

do_verify() {
    local vrunning realm count logs loaded migrated listed mode
    if ! docker inspect "$container" >/dev/null 2>&1; then
        echo "no such container ${container}. Pass the 0.8.0 container name and the backup directory." >&2
        exit 1
    fi
    vrunning="$(docker inspect -f '{{.State.Running}}' "$container")"
    if [ "$vrunning" != true ]; then
        echo "${container} is not running. Start 0.8.0, then run --verify again. Nothing was changed." >&2
        exit 1
    fi
    if [ ! -f "${backup}/dump_count" ] || [ ! -f "${backup}/realm" ]; then
        echo "${backup} has no dump_count from a prepare that wrote a dump. Nothing was changed." >&2
        exit 1
    fi
    count="$(tr -d '[:space:]' <"${backup}/dump_count")"
    realm="$(tr -d '[:space:]' <"${backup}/realm")"
    case "$count" in
        '' | *[!0-9]*)
            echo "dump_count in ${backup} is not a number. Nothing was changed." >&2
            exit 1
            ;;
    esac
    if ! realm_ok "$realm"; then
        echo "realm in ${backup} is not a realm name. Nothing was changed." >&2
        exit 1
    fi
    logs="$(docker logs "$container" 2>&1 || true)"
    loaded=missing
    migrated=no
    while IFS= read -r line; do
        case "$line" in
            *"Loaded "*" Kerberos principals"*)
                loaded="${line#*Loaded }"
                loaded="${loaded%% Kerberos*}"
                loaded="${loaded%% *}"
                ;;
            *"Migrated the MIT realm; its files are kept in"*)
                migrated=yes
                ;;
        esac
    done <<<"$logs"
    if [ "$loaded" != missing ] && [ "$loaded" != "$count" ]; then
        echo "the start log Loaded count is ${loaded} and the dump count is ${count}. Names are not printed." >&2
        exit 1
    fi
    listed="$(docker exec "$container" bash -c 'n=0
while IFS= read -r line; do
  case "$line" in
    *[!A-Za-z0-9_./@-]*) ;;
    *@*) n=$((n + 1)) ;;
  esac
done < <(kadmin -k -t /data/kadm5.keytab -p "admin/admin@'"$realm"'" -q listprincs 2>/dev/null)
printf "%s\n" "$n"')"
    if [ "$listed" != "$count" ]; then
        echo "listprincs count is ${listed} and the dump count is ${count}. Names are not printed." >&2
        exit 1
    fi
    if ! docker exec "$container" kinit -kt /data/kadm5.keytab "admin/admin@${realm}" >/dev/null 2>&1; then
        echo "kinit with the admin keytab failed. Nothing was deleted." >&2
        exit 1
    fi
    if ! docker exec "$container" bash -c 'test -d /var/kerberos/krb5kdc/mit-db2.bak'; then
        echo "mit-db2.bak is not a directory in the KDC directory. Leave any backup where it is." >&2
        exit 1
    fi
    mode="$(docker exec "$container" stat -c %a /var/kerberos/krb5kdc/mit-db2.bak)"
    if [ "$mode" != 700 ]; then
        echo "mit-db2.bak mode is ${mode}, not 700. Leave it until the realm works." >&2
        exit 1
    fi
    if docker exec "$container" bash -c 'test -e /var/kerberos/krb5kdc/principal'; then
        echo "principal is still in the KDC directory. The migration did not finish. Leave mit-db2.bak alone." >&2
        exit 1
    fi
    echo "verify_ok"
    if [ "$loaded" = missing ] && [ "$migrated" = no ]; then
        echo "start log was not found; the container may have been recreated since the migration"
    fi
    echo "When the realm works, remove mit-db2.bak/."
    ok=1
}

if [ "$verify" -eq 1 ]; then
    echo "Docker only, any tag: the script decides from the image itself. Podman installs follow the manual steps in docs/kerberos.md."
    do_verify
    exit 0
fi

name=$container
self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
if ! docker inspect "$name" >/dev/null 2>&1; then
    echo "no such container ${name}. Pass the 0.7.2 container name. Nothing was changed." >&2
    exit 1
fi
image_id="$(docker inspect -f '{{.Image}}' "$name")"
image_ref="$(docker inspect -f '{{.Config.Image}}' "$name")"
if ! docker image inspect "$image_id" >/dev/null 2>&1; then
    echo "image ${image_id} is not local. Nothing was changed. This script does not pull." >&2
    exit 1
fi
if ! image_is_072 "$image_id"; then
    echo "${name} (ref ${image_ref}) is not a 0.7.2 image: ${image_id} has no kdb5_util or no /app/kerberos_manager. A 0.8.0 image has neither. Nothing was changed. This script does not pull. Podman follows the manual steps in docs/kerberos.md." >&2
    exit 1
fi

data_spec=""
kdc_spec=""
data_source=""
kdc_source=""
extra=0
while IFS= read -r -d '' mtype && IFS= read -r -d '' mname && IFS= read -r -d '' msource && IFS= read -r -d '' mdest; do
    [ -n "$mdest" ] || continue
    case "$mdest" in
        /data)
            if [ -n "$data_spec" ]; then
                echo "${name} has more than one mount at /data. Nothing was changed." >&2
                exit 1
            fi
            data_source=$msource
            if [ "$mtype" = volume ]; then
                data_spec=$mname
            else
                data_spec=$msource
            fi
            ;;
        /var/kerberos/krb5kdc)
            if [ -n "$kdc_spec" ]; then
                echo "${name} has more than one mount at /var/kerberos/krb5kdc. Nothing was changed." >&2
                exit 1
            fi
            kdc_source=$msource
            if [ "$mtype" = volume ]; then
                kdc_spec=$mname
            else
                kdc_spec=$msource
            fi
            ;;
        *)
            extra=$((extra + 1))
            echo "extra mount ${mdest}"
            ;;
    esac
done < <(mount_fields "$name")

if [ -z "$data_spec" ] || [ -z "$kdc_spec" ]; then
    echo "${name} needs mounts at /data and /var/kerberos/krb5kdc. Nothing was changed. See docs/kerberos.md." >&2
    exit 1
fi

others=""
while IFS= read -r other; do
    [ -n "$other" ] || continue
    [ "$other" = "$name" ] && continue
    while IFS= read -r -d '' _otype && IFS= read -r -d '' oname && IFS= read -r -d '' osource && IFS= read -r -d '' _odest; do
        [ -n "$osource" ] || [ -n "$oname" ] || continue
        if [ -n "$oname" ] && { [ "$oname" = "$data_spec" ] || [ "$oname" = "$kdc_spec" ]; }; then
            others="$other"
        fi
        if [ "$osource" = "$data_source" ] || [ "$osource" = "$kdc_source" ]; then
            others="$other"
        fi
    done < <(mount_fields "$other")
done < <(docker ps -a --format '{{.Names}}')
if [ -n "$others" ]; then
    echo "${others} also mounts this data or KDC path. Nothing was changed. This script does not stop or remove that container." >&2
    exit 1
fi

if file_there "$kdc_spec" principal.dump; then
    echo "principal.dump is already in the KDC directory. Nothing was changed. Move that file aside yourself and run again, or if 0.8.0 is already up run --verify. This script does not delete it." >&2
    exit 1
fi

keycloak_set=no
realm=""
read_realm
has_principal=no
if file_there "$kdc_spec" principal; then
    has_principal=yes
fi
if [ "$has_principal" = yes ] && ! realm_ok "$realm"; then
    echo "the KDC has a principal file but no realm in LLDAP_KERB_REALM_NAME, kerberos_config.toml, or kdc.conf. Nothing was changed. Set LLDAP_KERB_REALM_NAME and run again." >&2
    exit 1
fi

if [ -n "$backup" ]; then
    backup_dir=$backup
else
    backup_dir="./klldap-upgrade-${name}-$(date +%Y%m%d-%H%M%S)"
fi
parent="$(dirname "$backup_dir")"
if [ ! -d "$parent" ]; then
    echo "backup parent ${parent} does not exist. Create it, or omit BACKUP_DIR. Nothing was changed." >&2
    exit 1
fi
parent_abs="$(cd "$parent" && pwd)"
backup_abs="${parent_abs}/$(basename "$backup_dir")"
case "$backup_abs" in
    "$data_source" | "$data_source"/* | "$kdc_source" | "$kdc_source"/*)
        echo "backup directory ${backup_abs} is inside a volume this script reads. Pick another directory. Nothing was changed." >&2
        exit 1
        ;;
esac
if [ -e "$backup_abs" ]; then
    echo "backup directory ${backup_abs} already exists. Pick another. This script does not delete a backup." >&2
    exit 1
fi

data_bytes="$(mount_size "$data_spec")"
kdc_bytes="$(mount_size "$kdc_spec")"
need=$((data_bytes + kdc_bytes))
free="$(df -B1 --output=avail "$parent_abs" | awk 'NR==2 {print $1}')"
if [ "$free" -lt "$need" ]; then
    echo "backup needs ${need} bytes and ${parent_abs} has ${free} bytes free. Nothing was changed. Free space, or pass a BACKUP_DIR on a larger filesystem." >&2
    exit 1
fi

db_outside
echo "Docker only, any tag: the script decides from the image itself. Podman installs follow the manual steps in docs/kerberos.md."
echo "container ${name}"
echo "image_ref ${image_ref}"
echo "image_id ${image_id}"
echo "data ${data_spec}"
echo "kdc ${kdc_spec}"
echo "extra_mounts ${extra}"
if [ -n "$realm" ]; then
    echo "realm ${realm}"
else
    echo "realm none"
fi
echo "principal ${has_principal}"
echo "principal_dump no"
echo "backup_need ${need}"
echo "backup_free ${free}"
echo "backup_dir ${backup_abs}"
if [ "$db_external" = yes ]; then
    echo "the database is outside these volumes; back it up yourself before the first 0.8.0 start; on MySQL and MariaDB schema changes are not transactional"
fi
if [ "$db_file" = yes ]; then
    echo "the database URL comes from a file this script does not read; if it is not SQLite, back it up yourself before the first 0.8.0 start; on MySQL and MariaDB schema changes are not transactional"
fi

if [ "$yes" -eq 0 ]; then
    echo "plan_only changes_nothing"
    ok=1
    exit 0
fi

running="$(docker inspect -f '{{.State.Running}}' "$name")"
if [ "$running" = true ]; then
    docker stop "$name" >/dev/null
    began_running=1
fi
stopped=1
mkdir "$backup_abs"
chmod 0700 "$backup_abs"
backup_begun=1

write_copy data "$data_spec"
write_copy kdc "$kdc_spec"
backup_begun=0

if [ "$has_principal" = no ]; then
    echo "no principal file in the KDC directory; nothing to dump."
    echo "0.8.0 starts a realm unless kerberos_options.enabled = false."
    echo "no_realm nothing_to_dump"
    print_edits
    ok=1
    exit 0
fi

wrote_dump=1
set +e
docker run --rm --entrypoint kdb5_util \
    -v "${kdc_spec}:/var/kerberos/krb5kdc" \
    "$image_id" \
    -r "$realm" dump /var/kerberos/krb5kdc/principal.dump
dump_rc=$?
set -e
if [ "$dump_rc" -ne 0 ]; then
    echo "kdb5_util dump exited ${dump_rc}. The next lines say what was put back." >&2
    exit 1
fi
check_dump
start_080
print_edits
echo "prepare_done"
ok=1
exit 0
