# image for Bugbouty
FROM debian:latest

# Essentials
RUN apt update && apt install -y curl git wget zsh tar p7zip-full unzip zip tmux build-essential gcc python3-pip python3-venv libmariadb-dev libcurl4-openssl-dev libssl-dev ldap-utils libpq-dev ike-scan unzip default-jdk libsqlite3-dev libsqlcipher-dev libpng16-16 libpng-dev pkg-config autoconf libtool build-essential nasm libx11-dev libxkbfile-dev man git gh glab subversion lsb-release pciutils gcc clang libclang-dev musl-tools gcc-mingw-w64-x86-64 libsqlite3-dev libsqlcipher-dev bsdmainutils sdcc binutils openvpn libxmlsec1 libxmlsec1-dev dirb prips swaks swig git ca-certificates build-essential fzf

COPY src/ /root/
RUN chmod +x /root/install.sh && /root/install.sh && rm -rf /root/install.sh

WORKDIR /workspace
ENTRYPOINT [ "/bin/zsh" ]
