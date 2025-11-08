# image for Bugbouty
FROM debian:latest

# Essentials
RUN apt update && apt install -y curl git wget zsh tar p7zip-full unzip zip tmux build-essential gcc python3-pip python3-venv libmariadb-dev libcurl4-openssl-dev libssl-dev ldap-utils libpq-dev ike-scan unzip default-jdk libsqlite3-dev libsqlcipher-dev  

COPY src/ /root/
RUN chmod +x /root/install.sh && /root/install.sh && rm -rf /root/install.sh

WORKDIR /workspace
ENTRYPOINT [ "/bin/zsh" ]
