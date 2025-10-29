#!/bin/bash
# Inspired by the works of Exegol - please check them out!

function setup_dirs() {
	# make landing DIR(s) for some tools:
	mkdir -p /opt/tools/ /opt/tools/bin/
}

function install_go() {
    echo "[INFO] Installing Golang: "
    wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz -O /tmp/go1.23.0.linux-amd64.tar.gz
    mkdir -p /usr/local/go/
    tar -C /usr/local/ -xzf /tmp/go1.23.0.linux-amd64.tar.gz

}

function install_ohmyzsh() {
    echo "[INFO] Installing oh-my-zsh: "
    if [[ -d "/root/.oh-my-zsh" ]]; then
        return
    fi
    # splitting wget and sh to avoid having additional logs put in curl output being executed because of catch_and_retry
    wget -O /tmp/ohmyzsh.sh https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh
    sh /tmp/ohmyzsh.sh

    git -C ~/.oh-my-zsh/custom/plugins/ clone --depth 1 https://github.com/zsh-users/zsh-autosuggestions
    git -C ~/.oh-my-zsh/custom/plugins/ clone --depth 1 https://github.com/zsh-users/zsh-syntax-highlighting
    git -C ~/.oh-my-zsh/custom/plugins/ clone --depth 1 https://github.com/zsh-users/zsh-completions

}

# install all ProjectDiscovery tools:
function install_pdtm() {
    # get the latest release:
    wget https://github.com/projectdiscovery/pdtm/releases/download/v0.1.3/pdtm_0.1.3_linux_amd64.zip -O /tmp/pdtm.zip
    cd /tmp && unzip /tmp/pdtm.zip
    ./pdtm -install-all 

    # Nuclei templates:
    ~/.pdtm/go/bin/nuclei # just enough to install the templates
}

function install_ffuf() {
    echo "[INFO] Installing ffuf: "
    if [[ $(uname -m) = 'x86_64' ]]
    then
        local arch="amd64"
    fi
    local ffuf_url
    ffuf_url=$(curl --location --silent "https://api.github.com/repos/ffuf/ffuf/releases/latest" | grep 'browser_download_url.*ffuf.*linux_'"$arch"'.tar.gz"' | grep -o 'https://[^"]*')
    curl --location -o /tmp/ffuf.tar.gz "$ffuf_url"
    tar -xf /tmp/ffuf.tar.gz --directory /opt/tools/bin/

}

function install_git-dumper() {
    echo "[INFO] Installing git-dumper: "
    pipx install --system-site-packages git-dumper

}

function install_pipx() {
    echo "[INFO] Installing Pipx: "
    pip3 install pipx --break-system-packages
    pipx ensurepath
}

function install_feroxbuster() {
    echo "[INFO] Installing Feroxbuster: "
    mkdir /opt/tools/feroxbuster
    cd /opt/tools/feroxbuster || exit

    # splitting curl | bash to avoid having additional logs put in curl output being executed
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh -o /tmp/install-feroxbuster.sh
    bash /tmp/install-feroxbuster.sh
    ln -v -s /opt/tools/feroxbuster/feroxbuster /opt/tools/bin/feroxbuster

}

function install_dirsearch() {
    echo "[INFO] Installing Dirsearch: "
    pipx install --system-site-packages git+https://github.com/maurosoria/dirsearch
}

function main() {
	# warming up:
	setup_dirs
	
	# TODO: Find the ACTUAL use for go
	# install_go
	install_pipx
	install_ffuf
	install_dirsearch
	install_git-dumper
	install_feroxbuster
	install_pdtm

	# shells/aliases/paths:
	install_ohmyzsh
        chsh -s /bin/zsh

}


main "$@"
