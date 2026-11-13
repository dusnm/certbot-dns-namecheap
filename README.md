# certbot-dns-namecheap

Certbot DNS-01 authenticator for Namecheap, packaged as a Docker image
(`dusnm1/certbot-namecheap-dns-plugin:latest`) so it can issue wildcard certificates.

> Status: in production since 2026-11-13 (apex + wildcard for one domain), after a staging run
> that left the zone (incl. Custom MX and a 410-char DKIM TXT) unchanged.
>
> Certificates live in the host's `/etc/letsencrypt` (read by host nginx). Files there and in
> `lib/` and `logs/` are created by the container as root; use `sudo` or
> `docker-compose exec certbot ...` to read them. `deploy/systemd/` has a path unit that
> reloads host nginx when the certificate changes.

## Quick start

1. Enable API access in Namecheap (Profile → Tools → API Access) and whitelist this host's IP.
2. `cp .env.example .env` and put the API key in it.
3. Edit the `environment:` section of `docker-compose.yml`.
4. `docker-compose up -d --build`

Run one-off certbot commands through the same image:

    docker-compose run --rm certbot certificates

## Configuration (environment)

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `NAMECHEAP_API_USER` | yes | | API user |
| `NAMECHEAP_API_KEY` | yes | | API key |
| `NAMECHEAP_USERNAME` | no | `NAMECHEAP_API_USER` | Account the API acts on |
| `NAMECHEAP_CLIENT_IP` | yes | | Whitelisted static IPv4 |
| `NAMECHEAP_SANDBOX` | no | `false` | Use the Namecheap sandbox API |
| `NAMECHEAP_PROPAGATION_SECONDS` | no | `120` | Wait after writing DNS |
| `CERTBOT_EMAIL` | yes | | ACME account email |
| `CERTBOT_CERTS` | yes | | `;` between certificates, `,` between names |
| `CERTBOT_STAGING` | no | `false` | Use Let's Encrypt staging |
| `CERTBOT_KEY_TYPE` | no | `ecdsa` | `ecdsa` or `rsa` |
| `CERTBOT_RENEW_INTERVAL` | no | `12h` | Interval between `certbot renew` runs |
| `CERTBOT_DEPLOY_HOOK` | no | | Command run (inside the container) after renewal |

The certificate name is the first name of each group without a leading `*.`,
so `example.com,*.example.com` lands in `letsencrypt/live/example.com/`.

## How it changes your DNS

Namecheap's API can only replace a domain's **entire** record set (`setHosts`), so for
each zone the plugin:

1. reads all records (`getHosts`) and stops if the domain is not on Namecheap DNS
   or any record comes back incomplete;
2. adds (or, on cleanup, removes) only the `_acme-challenge` TXT records for this run,
   all challenges for a zone in a single write (apex + wildcard need two values at the same name);
3. refuses to write if anything other than those TXT records would change;
4. saves a JSON backup of the zone to `lib/namecheap-backups/` (last 50 per zone kept);
5. writes the zone back with `EmailType`, MX priorities and TTLs preserved, then
   reads it again to confirm the TXT records are there.

If cleanup fails, the run still finishes and the log names the records to remove by hand.
To restore a zone, use the backup JSON (records + `email_type`) as the reference.
