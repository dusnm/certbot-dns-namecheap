FROM certbot/certbot:v5.9.0

COPY pyproject.toml README.md /src/
COPY certbot_dns_namecheap /src/certbot_dns_namecheap
RUN pip install --no-cache-dir /src && rm -rf /src

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

VOLUME ["/etc/letsencrypt", "/var/lib/letsencrypt"]
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
