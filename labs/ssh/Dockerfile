FROM debian:bookworm-slim

# OpenSSH with deliberately weak users — a brute-force practice target.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /run/sshd \
    && useradd -m admin && echo 'admin:admin' | chpasswd \
    && useradd -m user && echo 'user:password' | chpasswd \
    && echo 'root:toor' | chpasswd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
