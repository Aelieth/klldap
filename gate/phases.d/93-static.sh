# shellcheck shell=bash
# Phase: static files. The expectations are what actix-files 0.6.10 answered.
# Range and precondition rows keep those answers.

D="$(phase_dir)"
base="$(http_url)"

static_fetch() {
    local name="$1"
    shift
    : >"$D/${name}.hdr"
    : >"$D/${name}.body"
    t curl -sS -D "$D/${name}.hdr" -o "$D/${name}.body" "$@" || true
}

static_status() {
    awk 'NR==1 { print $2; exit }' "$1"
}

static_header() {
    local file="$1" name="$2"
    awk -v name="$name" 'BEGIN { want = tolower(name) }
        {
            line = $0
            sub(/\r$/, "", line)
            colon = index(line, ":")
            if (colon < 2) next
            key = tolower(substr(line, 1, colon - 1))
            if (key == want) {
                val = substr(line, colon + 1)
                sub(/^[[:space:]]+/, "", val)
                print val
                exit
            }
        }
    ' "$file"
}

static_sha() {
    sha256sum "$1" | awk '{ print $1 }'
}

static_is() {
    local name="$1" want="$2" label="$3" got
    got="$(static_status "$D/${name}.hdr")"
    if [ "$got" = "$want" ]; then
        p_ok "$label is $want"
    else
        p_bad "$label is '${got:-none}' (expected $want)"
    fi
}

static_hdr_is() {
    local name="$1" key="$2" want="$3" label="$4" got
    got="$(static_header "$D/${name}.hdr" "$key")"
    if [ "$got" = "$want" ]; then
        p_ok "$label"
    else
        p_bad "$label: got '${got:-absent}'"
    fi
}

static_hdr_absent() {
    local name="$1" key="$2" label="$3" got
    got="$(static_header "$D/${name}.hdr" "$key")"
    if [ -z "$got" ]; then
        p_ok "$label"
    else
        p_bad "$label: got '$got'"
    fi
}

static_hdr_present() {
    local name="$1" key="$2" label="$3" got
    got="$(static_header "$D/${name}.hdr" "$key")"
    if [ -n "$got" ]; then
        p_ok "$label"
    else
        p_bad "$label: absent"
    fi
}

static_bytes() {
    wc -c <"$D/${1}.body" | tr -d ' '
}

static_len_is() {
    local name="$1" want="$2" label="$3" got
    got="$(static_bytes "$name")"
    if [ "$got" = "$want" ]; then
        p_ok "$label is $want bytes"
    else
        p_bad "$label is $got bytes (expected $want)"
    fi
}

static_same() {
    local name="$1" other="$2" label="$3" sum other_sum
    sum="$(static_sha "$D/${name}.body")"
    other_sum="$(static_sha "$D/${other}.body")"
    if [ "$sum" = "$other_sum" ]; then
        p_ok "$label matches $other"
    else
        p_bad "$label does not match $other"
    fi
}

static_differs() {
    local name="$1" other="$2" label="$3" sum other_sum
    sum="$(static_sha "$D/${name}.body")"
    other_sum="$(static_sha "$D/${other}.body")"
    if [ "$sum" != "$other_sum" ]; then
        p_ok "$label is not $other"
    else
        p_bad "$label is $other"
    fi
}

static_fetch root "$base/"
static_fetch root_head -I "$base/"
static_fetch css "$base/static/fonts.css"
static_fetch css_head -I "$base/static/fonts.css"
static_fetch wasm "$base/pkg/lldap_app_bg.wasm"
static_fetch wasm_head -I "$base/pkg/lldap_app_bg.wasm"
static_fetch gz "$base/pkg/lldap_app_bg.wasm.gz"
static_fetch gz_head -I "$base/pkg/lldap_app_bg.wasm.gz"
static_fetch font "$base/static/fonts/fonts.txt"
static_fetch font_head -I "$base/static/fonts/fonts.txt"

wasm_len="$(static_header "$D/wasm.hdr" content-length)"
wasm_etag="$(static_header "$D/wasm.hdr" etag)"
wasm_modified="$(static_header "$D/wasm.hdr" last-modified)"
gz_len="$(static_header "$D/gz.hdr" content-length)"
css_len="$(static_header "$D/css.hdr" content-length)"
font_len="$(static_header "$D/font.hdr" content-length)"

static_fetch wasm_range -H 'Range: bytes=0-99' "$base/pkg/lldap_app_bg.wasm"
static_fetch wasm_range_bad -H 'Range: bytes=999999999-999999999' "$base/pkg/lldap_app_bg.wasm"
static_fetch wasm_inm -H "If-None-Match: $wasm_etag" "$base/pkg/lldap_app_bg.wasm"
static_fetch wasm_inm_other -H 'If-None-Match: "not-the-etag"' "$base/pkg/lldap_app_bg.wasm"
static_fetch wasm_ims -H "If-Modified-Since: $wasm_modified" "$base/pkg/lldap_app_bg.wasm"
static_fetch miss_pkg "$base/pkg/no-such-file"
static_fetch miss_static "$base/static/no-such-file"
static_fetch dir_pkg "$base/pkg/"
static_fetch dir_static "$base/static/"
static_fetch trav_toml --path-as-is "$base/pkg/../lldap_config.toml"
static_fetch trav_db --path-as-is "$base/static/..%2f..%2fdata/users.db"
static_fetch trav_passwd --path-as-is "$base/pkg/%2e%2e/%2e%2e/etc/passwd"
static_fetch trav_hidden --path-as-is "$base/static/.hidden"

static_is root 200 "GET /"
static_hdr_is root content-type "text/html; charset=utf-8" "GET / is text/html"
static_hdr_absent root content-encoding "GET / has no Content-Encoding"
static_hdr_absent root etag "GET / has no ETag"
static_hdr_absent root last-modified "GET / has no Last-Modified"
static_hdr_absent root accept-ranges "GET / has no Accept-Ranges"

static_is root_head 200 "HEAD /"
static_hdr_is root_head content-type "text/html; charset=utf-8" "HEAD / is text/html"
static_hdr_absent root_head content-encoding "HEAD / has no Content-Encoding"
static_hdr_absent root_head etag "HEAD / has no ETag"
static_hdr_absent root_head accept-ranges "HEAD / has no Accept-Ranges"

static_is css 200 "GET /static/fonts.css"
static_hdr_is css content-type "text/css; charset=utf-8" "GET fonts.css is text/css"
static_hdr_absent css content-encoding "GET fonts.css has no Content-Encoding"
static_hdr_present css etag "GET fonts.css has an ETag"
static_hdr_present css last-modified "GET fonts.css has Last-Modified"
static_hdr_is css accept-ranges bytes "GET fonts.css accepts ranges"
static_len_is css "$css_len" "GET fonts.css body matches Content-Length"

static_is css_head 200 "HEAD /static/fonts.css"
static_hdr_is css_head content-type "text/css; charset=utf-8" "HEAD fonts.css is text/css"
static_hdr_absent css_head content-encoding "HEAD fonts.css has no Content-Encoding"
static_hdr_is css_head accept-ranges bytes "HEAD fonts.css accepts ranges"
static_hdr_is css_head content-length "$css_len" "HEAD fonts.css length matches GET"

static_is wasm 200 "GET /pkg/lldap_app_bg.wasm"
static_hdr_is wasm content-type "application/wasm" "GET wasm is application/wasm"
static_hdr_absent wasm content-encoding "GET wasm has no Content-Encoding"
static_hdr_present wasm etag "GET wasm has an ETag"
static_hdr_present wasm last-modified "GET wasm has Last-Modified"
static_hdr_is wasm accept-ranges bytes "GET wasm accepts ranges"
static_len_is wasm "$wasm_len" "GET wasm body matches Content-Length"

static_is wasm_head 200 "HEAD /pkg/lldap_app_bg.wasm"
static_hdr_is wasm_head content-type "application/wasm" "HEAD wasm is application/wasm"
static_hdr_absent wasm_head content-encoding "HEAD wasm has no Content-Encoding"
static_hdr_is wasm_head accept-ranges bytes "HEAD wasm accepts ranges"
static_hdr_is wasm_head content-length "$wasm_len" "HEAD wasm length matches GET"

static_is gz 200 "GET /pkg/lldap_app_bg.wasm.gz"
static_hdr_is gz content-type "application/wasm" "GET wasm.gz is application/wasm"
static_hdr_is gz content-encoding gzip "GET wasm.gz is gzip"
static_hdr_present gz etag "GET wasm.gz has an ETag"
static_hdr_present gz last-modified "GET wasm.gz has Last-Modified"
static_hdr_is gz accept-ranges bytes "GET wasm.gz accepts ranges"
static_len_is gz "$gz_len" "GET wasm.gz body matches Content-Length"

static_is gz_head 200 "HEAD /pkg/lldap_app_bg.wasm.gz"
static_hdr_is gz_head content-type "application/wasm" "HEAD wasm.gz is application/wasm"
static_hdr_is gz_head content-encoding gzip "HEAD wasm.gz is gzip"
static_hdr_is gz_head accept-ranges bytes "HEAD wasm.gz accepts ranges"
static_hdr_is gz_head content-length "$gz_len" "HEAD wasm.gz length matches GET"

static_is font 200 "GET /static/fonts/fonts.txt"
static_hdr_is font content-type "text/plain; charset=utf-8" "GET fonts.txt is text/plain"
static_hdr_absent font content-encoding "GET fonts.txt has no Content-Encoding"
static_hdr_present font etag "GET fonts.txt has an ETag"
static_hdr_present font last-modified "GET fonts.txt has Last-Modified"
static_hdr_is font accept-ranges bytes "GET fonts.txt accepts ranges"
static_len_is font "$font_len" "GET fonts.txt body matches Content-Length"

static_is font_head 200 "HEAD /static/fonts/fonts.txt"
static_hdr_is font_head content-type "text/plain; charset=utf-8" "HEAD fonts.txt is text/plain"
static_hdr_is font_head accept-ranges bytes "HEAD fonts.txt accepts ranges"
static_hdr_is font_head content-length "$font_len" "HEAD fonts.txt length matches GET"

static_is wasm_range 206 "GET wasm Range bytes=0-99"
static_hdr_is wasm_range content-length 100 "Range bytes=0-99 is 100 bytes"
static_hdr_is wasm_range content-range "bytes 0-99/${wasm_len}" "Range bytes=0-99 is the first 100 bytes"
static_hdr_is wasm_range content-type "application/wasm" "Range bytes=0-99 is application/wasm"
static_len_is wasm_range 100 "Range bytes=0-99 body"

static_is wasm_range_bad 416 "GET wasm unsatisfiable Range"
static_hdr_is wasm_range_bad content-range "bytes */${wasm_len}" "unsatisfiable Range reports the size"
static_hdr_is wasm_range_bad content-length 0 "unsatisfiable Range is empty"
static_len_is wasm_range_bad 0 "unsatisfiable Range body"

static_is wasm_inm 304 "GET wasm If-None-Match own ETag"
static_len_is wasm_inm 0 "If-None-Match own ETag body"

static_is wasm_inm_other 200 "GET wasm If-None-Match other"
static_same wasm_inm_other wasm "If-None-Match other"

static_is wasm_ims 304 "GET wasm If-Modified-Since own Last-Modified"
static_len_is wasm_ims 0 "If-Modified-Since own Last-Modified body"

static_is miss_pkg 200 "GET /pkg/no-such-file"
static_hdr_is miss_pkg content-type "text/html; charset=utf-8" "GET /pkg/no-such-file is text/html"
static_same miss_pkg root "GET /pkg/no-such-file"

static_is miss_static 200 "GET /static/no-such-file"
static_hdr_is miss_static content-type "text/html; charset=utf-8" "GET /static/no-such-file is text/html"
static_same miss_static root "GET /static/no-such-file"

static_is dir_pkg 404 "GET /pkg/"
static_hdr_is dir_pkg content-type "text/plain; charset=utf-8" "GET /pkg/ is text/plain"
static_differs dir_pkg root "GET /pkg/"

static_is dir_static 404 "GET /static/"
static_hdr_is dir_static content-type "text/plain; charset=utf-8" "GET /static/ is text/plain"
static_differs dir_static root "GET /static/"

static_is trav_toml 200 "GET /pkg/../lldap_config.toml"
static_same trav_toml root "GET /pkg/../lldap_config.toml"

static_is trav_db 400 "GET /static/..%2f..%2fdata/users.db"
static_differs trav_db root "GET traversal to users.db"

static_is trav_passwd 200 "GET /pkg/%2e%2e/%2e%2e/etc/passwd"
static_same trav_passwd root "GET /pkg/%2e%2e/%2e%2e/etc/passwd"

static_is trav_hidden 400 "GET /static/.hidden"
static_hdr_is trav_hidden content-type "text/plain; charset=utf-8" "GET /static/.hidden is text/plain"
static_differs trav_hidden root "GET /static/.hidden"

{
    printf '%s %s\n' "GET /pkg/" "$(static_header "$D/dir_pkg.hdr" content-length)"
    printf '%s %s\n' "GET /static/" "$(static_header "$D/dir_static.hdr" content-length)"
    printf '%s %s\n' "GET /static/..%2f..%2fdata/users.db" "$(static_header "$D/trav_db.hdr" content-length)"
    printf '%s %s\n' "GET /static/.hidden" "$(static_header "$D/trav_hidden.hdr" content-length)"
} >"$D/error-lengths.txt"
