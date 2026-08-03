FROM debian:bookworm-slim

# Samba with a guest share and an authenticated share — an impacket-class
# protocol target (smbclient/rpcdump/samrdump/lookupsid style modules).
RUN apt-get update \
    && apt-get install -y --no-install-recommends samba \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /shares/public /shares/labuser \
    && echo 'flag{smb_labs_are_fun}' > /shares/public/flag.txt \
    && echo 'private notes for labuser' > /shares/labuser/notes.txt \
    && echo '<configuration><appSettings><add key="cs" value="x"/></appSettings></configuration>' > /shares/public/web.config \
    && echo 'root:toor # planted spider fixture' > /shares/public/credentials.txt \
    && useradd -M labuser && echo 'labuser:labpass' | chpasswd \
    && (echo 'labpass'; echo 'labpass') | smbpasswd -a -s labuser \
    && chown labuser:labuser /shares/labuser

COPY smb.conf /etc/samba/smb.conf

EXPOSE 139 445
CMD ["smbd", "--foreground", "--debug-stdout", "--no-process-group"]
