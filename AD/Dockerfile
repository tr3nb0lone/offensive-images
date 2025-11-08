# image for Red-Teaming
FROM debian:latest

# Essentials
RUN apt update && apt install -y curl git wget zsh tar p7zip-full unzip zip tmux build-essential gcc python3-pip python3-venv samdump2 smbclient onesixtyone nbtscan ldap-utils krb5-user gcc-mingw-w64-x86-64 mingw-w64-tools mingw-w64-common g++-mingw-w64 gcc-mingw-w64 osslsigncode libreadline8 libreadline-dev libpcap-dev libxml2-dev libxslt-dev swig libkrb5-dev krb5-config gcc clang libclang-dev libgssapi-krb5-2 libkrb5-dev libsasl2-modules-gssapi-mit musl-tools gcc-mingw-w64-x86-64 libmagic-dev openvpn neovim tree

 

COPY src/ /root/
RUN chmod +x /root/install.sh && /root/install.sh && rm -rf /root/install.sh

WORKDIR /workspace
ENTRYPOINT [ "/bin/zsh" ]
