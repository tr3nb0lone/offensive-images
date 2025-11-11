#!/bin/bash
# Install script for tools related to bugbounty.
# Inspired by the works of Exegol - please check them out!

function setup_dirs() {
	# make landing DIR(s) for some tools:
	mkdir -p /opt/tools/ /opt/tools/bin/ /opt/lists/
}

function install_go() {
    echo "[INFO] Installing Golang: "
    wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz -O /tmp/go1.23.0.linux-amd64.tar.gz
    mkdir -p /usr/local/go/
    tar -C /usr/local/ -xzf /tmp/go1.23.0.linux-amd64.tar.gz

}

# INFO: Installs most of the tools!
function install_pipx_uv() {
    echo "[INFO] Installing Pipx: "
    pip3 install pipx --break-system-packages
    pipx ensurepath

    # UV:
    pipx install uv
    source ~/.bashrc # makes uv available immediately!
}
function install_ohmyzsh() {
    echo "[INFO] Installing oh-my-zsh: "
    # splitting wget and sh to avoid having additional logs put in curl output being executed because of catch_and_retry
    wget -O /tmp/ohmyzsh.sh https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh
    sh /tmp/ohmyzsh.sh

    git -C ~/.oh-my-zsh/custom/plugins/ clone --depth 1 https://github.com/zsh-users/zsh-autosuggestions
    git -C ~/.oh-my-zsh/custom/plugins/ clone --depth 1 https://github.com/zsh-users/zsh-syntax-highlighting
    git -C ~/.oh-my-zsh/custom/plugins/ clone --depth 1 https://github.com/zsh-users/zsh-completions

}
# wordlists:
function install_seclists() {
    echo "[INFO] Installing seclists: "
    git -C /opt/lists clone --single-branch --branch master --depth 1 https://github.com/danielmiessler/SecLists.git seclists
    cd /opt/lists/seclists || exit
    rm -r LICENSE .git* CONTRIBUT* .bin
    tar -xvf /opt/lists/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz -C /opt/lists/
    # helping people to find wordlists in common places
    ln -v -s /opt/lists/seclists /usr/share/seclists
    mkdir -p /usr/share/wordlists
    ln -v -s /opt/lists/seclists /usr/share/wordlists/seclists
    ln -v -s /opt/lists/rockyou.txt /usr/share/wordlists/rockyou.txt
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

function install_ssrfmap() {
    echo "[INFO] Installing SSRFmap"
    git -C /opt/tools/ clone --depth 1 https://github.com/swisskyrepo/SSRFmap
    cd /opt/tools/SSRFmap || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
}

function install_xsstrike() {
    echo "[INFO] Installing XSStrike"
    git -C /opt/tools/ clone --depth 1 https://github.com/s0md3v/XSStrike.git
    cd /opt/tools/XSStrike || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
}

function install_xsser() {
    echo "[INFO] Installing xsser"
    git -C /opt/tools clone --depth 1 https://github.com/epsylon/xsser.git
    cd /opt/tools/xsser || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install pycurl bs4 pygeoip gobject cairocffi selenium
    deactivate
}

function install_xsrfprobe() {
    echo "[INFO] Installing XSRFProbe"
    uv tool install git+https://github.com/0xInfection/XSRFProbe
}

function install_patator() {
    echo "[INFO] Installing patator"
    git -C /opt/tools clone --depth 1 https://github.com/lanjelot/patator.git
    cd /opt/tools/patator || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
}

function install_droopescan() {
    echo "[INFO] Installing droopescan"
    uv tool install git+https://github.com/droope/droopescan.git
}

function install_cmsmap() {
    echo "[INFO] Installing CMSmap"
    uv tool install git+https://github.com/Dionach/CMSmap.git
}

function install_moodlescan() {
    echo "[INFO] Installing moodlescan"
    git -C /opt/tools/ clone --depth 1 https://github.com/inc0d3/moodlescan.git
    cd /opt/tools/moodlescan || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
    cd /opt/tools/moodlescan || exit
}

function install_cloudfail() {
    echo "[INFO] Installing CloudFail"
    git -C /opt/tools/ clone --depth 1 https://github.com/m0rtem/CloudFail
    cd /opt/tools/CloudFail || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
}

function install_corscanner() {
    echo "[INFO] Installing CORScanner"
    git -C /opt/tools/ clone --depth 1 https://github.com/chenjj/CORScanner.git
    cd /opt/tools/CORScanner || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
}


function install_linkfinder() {
    echo "[INFO] Installing LinkFinder"
    git -C /opt/tools/ clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git
    cd /opt/tools/LinkFinder || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
}

function install_jwt_tool() {
    echo "[INFO] Installing JWT tool"
    git -C /opt/tools/ clone --depth 1 https://github.com/ticarpi/jwt_tool
    cd /opt/tools/jwt_tool || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    # Running the tool to create the initial configuration and force it to returns 0
    python3 jwt_tool.py || :
    deactivate
    
    # Configuration
    sed -i 's/^proxy = 127.0.0.1:8080/#proxy = 127.0.0.1:8080/' /root/.jwt_tool/jwtconf.ini
    sed -i 's|^wordlist = jwt-common.txt|wordlist = /opt/tools/jwt_tool/jwt-common.txt|' /root/.jwt_tool/jwtconf.ini
    sed -i 's|^commonHeaders = common-headers.txt|commonHeaders = /opt/tools/jwt_tool/common-headers.txt|' /root/.jwt_tool/jwtconf.ini
    sed -i 's|^commonPayloads = common-payloads.txt|commonPayloads = /opt/tools/jwt_tool/common-payloads.txt|' /root/.jwt_tool/jwtconf.ini
}

function install_gittools() {
    echo "[INFO] Installing GitTools"
    git -C /opt/tools/ clone --depth 1 https://github.com/internetwache/GitTools.git
    cd /opt/tools/GitTools/Finder || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
}

function install_phpggc() {
    echo "[INFO] Installing phpggc"
    git -C /opt/tools clone --depth 1 https://github.com/ambionics/phpggc.git
}

function install_httpmethods() {
    echo "[INFO] Installing httpmethods"
    git -C /opt/tools/ clone --depth 1 https://github.com/ShutdownRepo/httpmethods
    cd /opt/tools/httpmethods || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
}

function install_h2csmuggler() {
    echo "[INFO] Installing h2csmuggler"
    git -C /opt/tools/ clone --depth 1 https://github.com/BishopFox/h2csmuggler
    cd /opt/tools/h2csmuggler || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install h2
    deactivate
}

function install_arjun() {
    echo "[INFO] Installing arjun"
    uv tool install arjun
}

function install_gau() {
    echo "[INFO] Installing gau"
    go install github.com/lc/gau/v2/cmd/gau@latest
    asdf reshim golang
}

function install_httprobe() {
    echo "[INFO] Installing httprobe"
    go install -v github.com/tomnomnom/httprobe@latest
    asdf reshim golang
}

function install_anew() {
    echo "[INFO] Installing anew"
    go install -v github.com/tomnomnom/anew@latest
    asdf reshim golang
}

function install_robotstester() {
    echo "[INFO] Installing Robotstester"
    uv tool install git+https://github.com/p0dalirius/robotstester
}

function install_php_filter_chain_generator() {
    echo "[INFO] Installing PHP_Filter_Chain_Generator"
    git -C /opt/tools/ clone --depth 1 https://github.com/synacktiv/php_filter_chain_generator.git
}

function install_sqlmap() {
    echo "[INFO] Installing sqlmap"
    git -C /opt/tools/ clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
    ln -s "/opt/tools/sqlmap/sqlmap.py" /opt/tools/bin/sqlmap
}

function install_sslscan() {
    echo "[INFO] Installing sslscan"
    git -C /tmp clone --depth 1 https://github.com/rbsec/sslscan.git
    cd /tmp/sslscan || exit
    make static
    mv /tmp/sslscan/sslscan /opt/tools/bin/sslscan
}

function install_jsluice() {
    echo "[INFO] Installing jsluice"
    go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest
    asdf reshim golang
}

function install_wpprobe() {
    echo "[INFO] Installing wpprobe"
    go install -v github.com/Chocapikk/wpprobe@latest
    asdf reshim golang
}

function install_token_exploiter() {
    echo "[INFO] Installing Token Exploiter"
    uv tool install git+https://github.com/psyray/token-exploiter
}

function install_bbot() {
    echo "[INFO] Installing BBOT"
    uv tool install bbot
}


# post-install:
function post_install() {
    echo "[INFO] Adding /opt/tools/bin to PATH"
    # this could be stupid, but IDC!
    echo -e "export PATH=\"/opt/tools/bin:\$PATH\"\n" >> ~/.bashrc
    echo -e "export PATH=\"/root/.pdtm/go/bin:\$PATH\"\n" >> ~/.bashrc
    echo -e "source ~/.bashrc\n" >> ~/.zshrc
    chsh -s /bin/zsh

}

function main() {
	local start_time
	local end_time
	start_time=$(date +%s)
	
	# warming up:
	setup_dirs
	install_ohmyzsh
	install_pipx_uv
	
	install_pdtm
	install_seclists
	install_feroxbuster
	install_gobuster                # Web fuzzer (pretty good for several extensions)
	install_ffuf                    # Web fuzzer (little favorites)
	install_dirsearch               # Web fuzzer
	install_ssrfmap                 # SSRF scanner
	install_xsstrike                # XSS scanner
	install_xsser                   # XSS scanner
	install_xsrfprobe               # CSRF scanner
	install_patator                 # Login scanner
	install_droopescan              # Drupal scanner
	install_cmsmap                  # CMS scanner (Joomla, Wordpress, Drupal)
	install_moodlescan              # Moodle scanner
	install_cloudfail               # Cloudflare misconfiguration detector
	install_corscanner              # CORS misconfiguration detector
	install_linkfinder              # Discovers endpoint JS files
	install_jwt_tool                # Toolkit for validating, forging, scanning and tampering JWTs
	install_git-dumper              # Dump a git repository from a website
	install_gittools                # Dump a git repository from a website
	install_phpggc                  # php deserialization payloads
	install_httpmethods             # Tool for HTTP methods enum & verb tampering
	install_h2csmuggler             # Tool for HTTP2 smuggling
	install_gau                     # fetches known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, Common Crawl, and URLScan
	install_httprobe                # Probe http
	install_uncover                 # Quickly discover exposed hosts on the internet using multiple search engines.
	install_anew                    # A tool for adding new lines to files, skipping duplicates
	install_robotstester            # Robots.txt scanner
	install_php_filter_chain_generator # A CLI to generate PHP filters chain and get your RCE
	install_sqlmap                  # SQL injection scanner
	install_sslscan                 # SSL/TLS scanner
	install_jsluice                 # Extract URLs, paths, secrets, and other interesting data from JavaScript source code
	install_wpprobe                 # WPProbe - Tool for detecting WordPress plugins using misconfigured REST API endpoints
	install_token_exploiter         # Github personal token Analyzer
	install_bbot                    # Recursive Scanner
	post_install


	post_install
	end_time=$(date +%s)
	local elapsed_time=$((end_time - start_time))
	echo "[INFO] Installation completed in $elapsed_time seconds." >> /root/.time_wasted

}


main "$@"
