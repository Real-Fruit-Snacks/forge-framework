FROM debian:bookworm-slim

# Samba AD Domain Controller — Active Directory lab for enum modules.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       samba-ad-dc samba-ad-provision krb5-kdc \
    && rm -rf /var/lib/apt/lists/*

# Provision happens at RUNTIME (entrypoint.sh), fresh on every start:
# NT ACLs need security.NTACL xattrs — blocked at build time on overlayfs,
# allowed at runtime with CAP_SYS_ADMIN (see compose.yml). Labs are
# throwaway, so no volume: a clean domain every boot.
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 53 88 135 139 389 445 464 636 3268 3269
ENTRYPOINT ["/entrypoint.sh"]
