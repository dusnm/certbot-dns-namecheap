#!/bin/sh
# Translates CERTBOT_* / NAMECHEAP_* environment variables into certbot runs.
#
#   no arguments  -> issue missing/changed certificates, then renew on a loop
#   any arguments -> passed straight to certbot (e.g. `certificates`, `renew --dry-run`)
set -eu
set -f  # no globbing: certificate names contain "*"

if [ "$#" -gt 0 ]; then
    exec certbot "$@"
fi

log() { echo "[entrypoint] $*"; }
die() { echo "[entrypoint] ERROR: $*" >&2; exit 1; }

is_true() {
    case "$(echo "${1:-}" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on) return 0 ;;
        ""|0|false|no|off) return 1 ;;
        *) die "expected true/false, got '$1'" ;;
    esac
}

: "${CERTBOT_EMAIL:?CERTBOT_EMAIL is required}"
: "${CERTBOT_CERTS:?CERTBOT_CERTS is required (e.g. example.com,*.example.com;example.net,*.example.net)}"
: "${NAMECHEAP_API_USER:?NAMECHEAP_API_USER is required}"
: "${NAMECHEAP_API_KEY:?NAMECHEAP_API_KEY is required}"
: "${NAMECHEAP_CLIENT_IP:?NAMECHEAP_CLIENT_IP is required}"

PROPAGATION="${NAMECHEAP_PROPAGATION_SECONDS:-120}"
KEY_TYPE="${CERTBOT_KEY_TYPE:-ecdsa}"
RENEW_INTERVAL="${CERTBOT_RENEW_INTERVAL:-12h}"
DEPLOY_HOOK="${CERTBOT_DEPLOY_HOOK:-}"

case "$PROPAGATION" in ''|*[!0-9]*) die "NAMECHEAP_PROPAGATION_SECONDS must be an integer" ;; esac
case "$KEY_TYPE" in ecdsa|rsa) ;; *) die "CERTBOT_KEY_TYPE must be ecdsa or rsa" ;; esac

# Arguments shared by certonly and renew.
set -- --non-interactive \
       --authenticator dns-namecheap \
       --dns-namecheap-propagation-seconds "$PROPAGATION"
if is_true "${CERTBOT_STAGING:-false}"; then
    log "Using Let's Encrypt STAGING"
    set -- "$@" --test-cert
fi
if [ -n "$DEPLOY_HOOK" ]; then
    set -- "$@" --deploy-hook "$DEPLOY_HOOK"
fi

issue_all() {
    old_ifs=$IFS
    IFS=';'
    for group in $CERTBOT_CERTS; do
        IFS=$old_ifs
        group=$(echo "$group" | tr -d '[:space:]')
        [ -n "$group" ] || continue

        first=${group%%,*}
        cert_name=${first#\*.}

        domain_args=""
        IFS=','
        for name in $group; do
            [ -n "$name" ] && domain_args="$domain_args -d $name"
        done
        IFS=$old_ifs

        log "Ensuring certificate '$cert_name': $group"
        # shellcheck disable=SC2086  # domain_args is intentionally split; globbing is off
        certbot certonly "$@" \
            --agree-tos --email "$CERTBOT_EMAIL" \
            --key-type "$KEY_TYPE" \
            --keep-until-expiring --expand \
            --cert-name "$cert_name" $domain_args \
            || log "WARNING: issuing '$cert_name' failed, will retry on next start"
        IFS=';'
    done
    IFS=$old_ifs
}

trap 'log "Stopping"; exit 0' TERM INT

issue_all "$@"

while :; do
    log "Next renewal check in $RENEW_INTERVAL"
    sleep "$RENEW_INTERVAL" &
    wait $!
    log "Running certbot renew"
    certbot renew "$@" || log "WARNING: renew failed"
done
