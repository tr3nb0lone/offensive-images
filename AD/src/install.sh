#!/bin/bash
## Install script for the AD image:

# Setup dest. Dir(s)
function setup_dirs() {
	mkdir -p /opt/tools/ /opt/tools/bin/
}

# TODO:
# prereqs: Go, rust, pipx, uv, 
function install_pipx_uv() {
    echo "[INFO] Installing Pipx: "
    pip3 install pipx --break-system-packages
    pipx ensurepath

    # UV:
    pipx install uv
    source ~/.bashrc # makes uv available immediately!
}

# env:
function set_bin_path() {
    echo "[INFO] Adding /opt/tools/bin to PATH"
    export PATH="/opt/tools/bin:$PATH"
}

# Tools:
function install_asrepcatcher() {
    echo "[INFO] Installing Asrepcatcher: "
    uv tool install git+https://github.com/Yaxxine7/ASRepCatcher
}

# BUG: doesn't work!
function install_responder() {
    echo "[INFO] Installing Responder: "
    git -C /opt/tools/ clone --depth 1 https://github.com/lgandx/Responder
    cd /opt/tools/Responder || exit
    uv venv ./venv
    source ./venv/bin/activate
    pip3 install -r requirements.txt
    # following requirements needed by MultiRelay.py
    uv pip install pycryptodomex six
    deactivate
    sed -i 's/ Random/ 1122334455667788/g' /opt/tools/Responder/Responder.conf
    sed -i 's/files\/AccessDenied.html/\/opt\/tools\/Responder\/files\/AccessDenied.html/g' /opt/tools/Responder/Responder.conf
    sed -i 's/files\/BindShell.exe/\/opt\/tools\/Responder\/files\/BindShell.exe/g' /opt/tools/Responder/Responder.conf
    sed -i 's/certs\/responder.crt/\/opt\/tools\/Responder\/certs\/responder.crt/g' /opt/tools/Responder/Responder.conf
    sed -i 's/certs\/responder.key/\/opt\/tools\/Responder\/certs\/responder.key/g' /opt/tools/Responder/Responder.conf
    x86_64-w64-mingw32-gcc /opt/tools/Responder/tools/MultiRelay/bin/Runas.c -o /opt/tools/Responder/tools/MultiRelay/bin/Runas.exe -municode -lwtsapi32 -luserenv
    x86_64-w64-mingw32-gcc /opt/tools/Responder/tools/MultiRelay/bin/Syssvc.c -o /opt/tools/Responder/tools/MultiRelay/bin/Syssvc.exe -municode
    /opt/tools/Responder/certs/gen-self-signed-cert.sh
}


function install_sprayhound() {
    echo "[INFO] Installing Sprayhound: "
    uv tool install --with setuptools==80 git+https://github.com/Hackndo/sprayhound
}

function install_smartbrute() {
    echo "[INFO] Installing Smartbrute: "
    uv tool install git+https://github.com/ShutdownRepo/smartbrute
}


function install_ldapdomaindump() {
    echo "[INFO] Installing Ldapdomaindump: "
    uv tool install git+https://github.com/dirkjanm/ldapdomaindump
}

function install_bloodhound-py() {
    echo "[INFO] Installing Bloodhound-py: "
    uv tool install git+https://github.com/fox-it/BloodHound.py
}


function install_bloodhound-ce-py() {
    echo "[INFO] Installing Bloodhound-ce-py: "
    git -C /opt/tools/ clone --branch bloodhound-ce --depth 1 https://github.com/dirkjanm/BloodHound.py BloodHound-CE.py
    cd /opt/tools/BloodHound-CE.py || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install .
    deactivate
    # where to put the ingestor?
    ln -v -s /opt/tools/BloodHound-CE.py/venv/bin/bloodhound-ce-python /opt/tools/bin/bloodhound-ce.py
}

function install_mitm6() {
    echo "[INFO] Installing mim6: "
    uv tool install mitm6
}

function install_aclpwn() {
    echo "[INFO] Installing Aclpwn: "
    uv tool install git+https://github.com/aas-n/aclpwn.py
}

function install_impacket() {
   echo "[INFO] Installing Impacket: "
   # avoid the nasty setuptoools error
   uv tool install --with setuptools==80 git+https://github.com/fortra/impacket
}

function install_lsassy() {
    echo "[INFO] Installing Lsassy: "
    uv tool install lsassy
}


function install_privexchange() {
    echo "[INFO] Installing Privexchange: "
    git -C /opt/tools/ clone --depth 1 https://github.com/dirkjanm/PrivExchange
    cd /opt/tools/PrivExchange || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install impacket
    deactivate
}

function install_upx() {
    echo "[INFO] Installing Upx: "
    local arch="amd64"
    local upx_url
    upx_url=$(curl --location --silent "https://api.github.com/repos/upx/upx/releases/latest" | grep 'browser_download_url.*upx.*'"$arch"'.*tar.xz"' | grep -o 'https://[^"]*')
    curl --location -o /tmp/upx.tar.xz "$upx_url"
    tar -xf /tmp/upx.tar.xz --directory /tmp
    rm /tmp/upx.tar.xz
    mv /tmp/upx* /opt/tools/upx

    ln -v -s /opt/tools/upx/upx /opt/tools/bin/upx
    ln -v -s upx /opt/tools/bin/upx-ucl
}

function install_darkarmour() {
    echo "[INFO] Installing Darkarmor: "
    install_upx
    git -C /opt/tools/ clone --depth 1 https://github.com/bats3c/darkarmour
}


function install_powershell() {
    echo "[INFO] Installing Powershell: "
    curl -L -o /tmp/powershell.tar.gz https://github.com/PowerShell/PowerShell/releases/download/v7.3.4/powershell-7.3.4-linux-x64.tar.gz

   # where to put powershell?
   mkdir -v -p /opt/tools/powershell/7
   tar xvfz /tmp/powershell.tar.gz -C /opt/tools/powershell/7
   chmod -v +x /opt/tools/powershell/7/pwsh
   rm -v /tmp/powershell.tar.gz

   ln -v -s /opt/tools/powershell/7/pwsh /opt/tools/bin/pwsh
   ln -v -s /opt/tools/powershell/7/pwsh /opt/tools/bin/powershell
}

# BUG: the stinky setuptools error
function install_krbrelayx() {
    echo "[INFO] Installing Kerbrelayx: "
    git -C /opt/tools/ clone --depth 1 https://github.com/dirkjanm/krbrelayx
    cd /opt/tools/krbrelayx || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install dnspython ldap3 impacket dsinternals
    deactivate
    cp -v /root/sources/assets/grc/conf.krbrelayx /usr/share/grc/conf.krbrelayx
}

function install_pypykatz() {
    echo "[INFO] Installing Pypykatz: "
      git -C /opt/tools/ clone --depth 1 https://github.com/skelsec/pypykatz
      cd /opt/tools/pypykatz || exit
      uv venv ./venv
      source ./venv/bin/activate
      uv pip install .
      uv pip install --force-reinstall oscrypto@git+https://github.com/wbond/oscrypto.git

      ln -v -s /opt/tools/pypykatz/venv/bin/pypykatz /opt/tools/bin/pypykatz
      deactivate
}


function install_krbjack() {
    echo "[INFO] Installing Krbjack: "
    uv tool install krbjack
}


function install_enyx() {
    echo "[INFO] Installing Enyx: "
    git -C /opt/tools/ clone --depth 1 https://github.com/trickster0/Enyx
}


function install_enum4linux-ng() {
    echo "[INFO] Installing Enum4Linux-ng: "
    uv tool install git+https://github.com/cddmp/enum4linux-ng
}

function install_zerologon() {
    echo "[INFO] Pulling CVE-2020-1472 exploit and scan scripts"
    mkdir /opt/tools/zerologon
    cd /opt/tools/zerologon || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install impacket
    deactivate
    # other scripts
    git -C /opt/tools/zerologon clone --depth 1 https://github.com/SecuraBV/CVE-2020-1472 zerologon-scan
    git -C /opt/tools/zerologon clone --depth 1 https://github.com/dirkjanm/CVE-2020-1472 zerologon-exploit
}


function install_libmspack() {
    echo "[INFO] Installing Libmspack: "
    git -C /opt/tools/ clone --depth 1 https://github.com/kyz/libmspack.git
    cd /opt/tools/libmspack/libmspack || exit
    ./rebuild.sh
    ./configure
    make
}

function install_polenum() {
    echo "[INFO] Installing Polenum: "
    git -C /opt/tools/ clone --depth 1 https://github.com/Wh1t3Fox/polenum
    cd /opt/tools/polenum || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install impacket
    deactivate
}

function install_smbmap() {
    echo "[INFO] Installing SMBmap: "
    git -C /opt/tools clone --depth 1 https://github.com/ShawnDEvans/smbmap
    cd /opt/tools/smbmap || exit
    uv tool install .
}

function install_pth-tools() {
    echo "[INFO] Installing PTH-tools: "
    git -C /opt/tools clone --depth 1 https://github.com/byt3bl33d3r/pth-toolkit
    ln -s /usr/lib/x86_64-linux-gnu/libreadline.so /opt/tools/pth-toolkit/lib/libreadline.so.6
}


function install_smtp-user-enum() {
    echo "[INFO] Installing Smtp-user-enum: "
    uv tool install smtp-user-enum
}

function install_gpp-decrypt() {
    echo "[INFO] Installing gpp-decrypt: "
    git -C /opt/tools/ clone --depth 1 https://github.com/t0thkr1s/gpp-decrypt
    cd /opt/tools/gpp-decrypt || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install pycryptodome colorama
    deactivate
}

function install_ntlmv1-multi() {
    echo "[INFO] Installing NTLM-multi: "
    git -C /opt/tools clone --depth 1 https://github.com/evilmog/ntlmv1-multi
    cd /opt/tools/ntlmv1-multi || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install pycryptodome
    deactivate
}

function install_adidnsdump() {
    echo "[INFO] Installing AD-DNSdump: "
    uv tool install git+https://github.com/dirkjanm/adidnsdump
}

function install_pygpoabuse() {
    echo "[INFO] Installing pyGPOAbuse: "
    git -C /opt/tools/ clone --depth 1 https://github.com/Hackndo/pyGPOAbuse
    cd /opt/tools/pyGPOAbuse || exit
    uv add --script pygpoabuse.py -r requirements.txt
    # run with uv run /path/to/pygpoabuse.py
}


function install_bloodhound-import() {
    echo "[INFO] Installing Bloodhound-import: "
    uv tool install bloodhound-import
}


function install_bloodhound-quickwin() {
    echo "[INFO] Installing Bloodhound-quickwin: "
    git -C /opt/tools/ clone --depth 1 https://github.com/kaluche/bloodhound-quickwin
    cd /opt/tools/bloodhound-quickwin || exit
    uv add --script bhqc.py -r requirements.txt
    # run with uv run bhqc.py
}


function install_ldapsearch-ad() {
    echo "[INFO] Installing LDAPsearch-ad "
    git -C /opt/tools/ clone --depth 1 https://github.com/yaap7/ldapsearch-ad
    cd /opt/tools/ldapsearch-ad || exit
    uv add --script ldapsearch-ad.py -r requirements.txt
    # run with uv run ldapsearch-ad.py
}

function install_petitpotam() {
    echo "[INFO] Installing Petitpotam "
    git -C /opt/tools/ clone --depth 1 https://github.com/ly4k/PetitPotam
    cd /opt/tools/PetitPotam || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install impacket
    deactivate

    mv /opt/tools/PetitPotam /opt/tools/PetitPotam_alt
    git -C /opt/tools/ clone --depth 1 https://github.com/topotam/PetitPotam
    cd /opt/tools/PetitPotam || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install impacket
    deactivate
}

function install_dfscoerce() {
    echo "[INFO] Installing Dfscoerce: "
    git -C /opt/tools/ clone --depth 1 https://github.com/Wh04m1001/DFSCoerce
    cd /opt/tools/DFSCoerce || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install impacket
    deactivate
}

function install_coercer() {
    echo "[INFO] Installing Coercer: "
    uv tool install git+https://github.com/p0dalirius/Coercer
}


function install_pkinittools() {
    echo "[INFO] Installing PKINIT-tools: "
    git -C /opt/tools/ clone --depth 1 https://github.com/dirkjanm/PKINITtools
    cd /opt/tools/PKINITtools || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install minikerberos impacket
    # without following fix, tool raises "oscrypto.errors.LibraryNotFoundError: Error detecting the version of libcrypto"
    # see https://github.com/wbond/oscrypto/issues/78 and https://github.com/wbond/oscrypto/issues/75
    uv pip install --force-reinstall oscrypto@git+https://github.com/wbond/oscrypto.git
    deactivate
}


function install_pywhisker() {
    echo "[INFO] Installing Pywhisker: "
    uv tool install --with setuptools==80 git+https://github.com/ShutdownRepo/pywhisker
}

# BUG: ImportError: failed to find libmagic.
function install_manspider() {
    echo "[INFO] Installing Manspider: "
    uv tool install --with setuptools==80 git+https://github.com/blacklanternsecurity/MANSPIDER
}


function install_targetedKerberoast() {
    echo "[INFO] Installing TargeteedKerberoast: "
    git -C /opt/tools/ clone --depth 1 https://github.com/ShutdownRepo/targetedKerberoast
    cd /opt/tools/targetedKerberoast || exit
    uv add --script targetedKerberoast.py -r requirements.txt
    # run with uv run targeterKerberoast.py
}


function install_pcredz() {
    echo "[INFO] Installing Pcredz: "
    git -C /opt/tools/ clone --depth 1 https://github.com/lgandx/PCredz
    cd /opt/tools/PCredz || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install Cython python-libpcap
    deactivate
}

# BUG: gcc error
function install_pywsus() {
    echo "[INFO] Installing PyWSUS: "
    git -C /opt/tools/ clone --depth 1 https://github.com/GoSecure/pywsus
    cd /opt/tools/pywsus || exit

    # https://github.com/GoSecure/pywsus/pull/12
    echo -e "beautifulsoup4==4.9.1\nlxml==4.9.1\nsoupsieve==2.0.1" > requirements.txt
    uv add --script pywsus.py -r requirements.txt
    # run with uv run /path/pywsus.py
}

function install_donpapi() {
    echo "[INFO] Installing DonPAPI: "
    uv tool install git+https://github.com/login-securite/DonPAPI
}

function install_webclientservicescanner() {
    echo "[INFO] Installing Webclientservicescanner: "
    uv tool install git+https://github.com/Hackndo/WebclientServiceScanner
}

function install_certipy() {
    echo "[INFO] Installing Certipy: "
    uv tool install --with setuptools==80 git+https://github.com/ly4k/Certipy
}


function install_shadowcoerce() {
    echo "[INFO] Installing ShadowCoerce: "
    git -C /opt/tools/ clone --depth 1 https://github.com/ShutdownRepo/ShadowCoerce
    cd /opt/tools/ShadowCoerce || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install impacket
    deactivate
}


function install_gmsadumper() {
    echo "[INFO] Installing GMSADumper: "
    git -C /opt/tools/ clone --depth 1 https://github.com/micahvandeusen/gMSADumper
    cd /opt/tools/gMSADumper || exit
    uv add --script gMSADumper.py -r requirements.txt
    # run with uv run gMSADumper.py
}


function install_pylaps() {
    echo "[INFO] Installing PyLAPS: "
    git -C /opt/tools/ clone --depth 1 https://github.com/p0dalirius/pyLAPS
    cd /opt/tools/pyLAPS || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install impacket
    deactivate
}

function install_ldaprelayscan() {
    echo "[INFO] Installing LDAPRelayScan: "
    git -C /opt/tools/ clone --depth 1 https://github.com/zyn3rgy/LdapRelayScan
    cd /opt/tools/LdapRelayScan || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    uv pip install --force-reinstall oscrypto@git+https://github.com/wbond/oscrypto.git
    deactivate
}

function install_goldencopy() {
    echo "[INFO] Installing Goldencopy: "
    git -C /opt/tools/ clone --depth 1 https://github.com/Dramelac/GoldenCopy
    cd /opt/tools/GoldenCopy || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install .
    deactivate
    ln -v -s /opt/tools/GoldenCopy/venv/bin/goldencopy /opt/tools/bin/goldencopy
}


function install_crackhound() {
    echo "[INFO] Installing CrackHound: "
    git -C /opt/tools/ clone --depth 1 https://github.com/trustedsec/CrackHound
    cd /opt/tools/CrackHound || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
}

function install_ldeep() {
    echo "[INFO] Installing Ldeep: "
    uv tool install ldeep
}

function install_certsync() {
    echo "[INFO] Installing certSync: "
    uv tool install git+https://github.com/zblurx/certsync
}

# BUG: ImportError: failed to find libmagic.
function install_keepwn() {
    echo "[INFO] Installing Keepwn: "
    uv tool install git+https://github.com/Orange-Cyberdefense/KeePwn
}

function install_pre2k() {
    echo "[INFO] Installing Pre2k: "
    uv tool install git+https://github.com/garrettfoster13/pre2k
}

function install_msprobe() {
    echo "[INFO] Installing MSProbe: "
    uv tool install --with setuptools==80 git+https://github.com/puzzlepeaches/msprobe
}

function install_masky() {
    echo "[INFO] Installing Masky: "
    uv tool install git+https://github.com/Z4kSec/Masky
}

function install_roastinthemiddle() {
    echo "[INFO] Installing roastingInTheMiddle: "
    uv tool install git+https://github.com/Tw1sm/RITM
}

function install_PassTheCert() {
    echo "[INFO] Installing PassTheCert: "
    git -C /opt/tools/ clone --depth 1 https://github.com/AlmondOffSec/PassTheCert
    cd /opt/tools/PassTheCert/Python/ || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install impacket
    deactivate
}

# BUG: ModuleNotFoundError: No module named 'pkg_resources'
function install_noPac() {
    echo "[INFO] Installing noPac: "
    git -C /opt/tools/ clone --depth 1 https://github.com/Ridter/noPac
    cd /opt/tools/noPac || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
}

function install_roadrecon() {
    echo "[INFO] Installing roadRecon: "
    uv tool install roadrecon
}

function install_roadtx() {
    echo "[INFO] Installing Roadtx: "
    uv tool install --with setuptools==80 roadtx
}

function install_teamsphisher() {
    echo "[INFO] Installing TeamPhisher: "
    git -C /opt/tools clone --depth 1 https://github.com/Octoberfest7/TeamsPhisher
    cd /opt/tools/TeamsPhisher || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install msal colorama requests
    deactivate
}

function install_GPOddity() {
    echo "[INFO] Installing GPOdditty: "
    uv tool install git+https://github.com/synacktiv/GPOddity
}

function install_netexec() {
    echo "[INFO] Installing NetExec: "
    uv tool install -p 3.11 --with setuptools==80 git+https://github.com/Pennyw0rth/NetExec
    register-python-argcomplete nxc >> ~/.zshrc
}

function install_extractbitlockerkeys() {
    echo "[INFO] Installing extractBitLockerKeys: "
    git -C /opt/tools/ clone --depth 1 https://github.com/p0dalirius/ExtractBitlockerKeys
    cd /opt/tools/ExtractBitlockerKeys || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
}

function install_pywerview() {
    echo "[INFO] Installing Pywerview: "
    uv tool install git+https://github.com/the-useless-one/pywerview
}

function install_ntlm_theft() {
    echo "[INFO] Installing NTLM-Theft: "
    git -C /opt/tools/ clone --depth 1 https://github.com/Greenwolf/ntlm_theft
    cd /opt/tools/ntlm_theft || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install xlsxwriter
    deactivate
}

function install_abuseACL() {
    echo "[INFO] Installing AbuseACL: "
    uv tool install git+https://github.com/AetherBlack/abuseACL
}

function install_bloodyAD() {
    echo "[INFO] Installing BloodyAD: "
    uv tool install -p 3.11 --with setuptools==80 git+https://github.com/CravateRouge/bloodyAD
}

function install_autobloody() {
    echo "[INFO] Installing Autobloody: "
    uv tool install git+https://github.com/CravateRouge/autobloody
}

function install_dploot() {
    echo "[INFO] Installing Dploot: "
    uv tool install git+https://github.com/zblurx/dploot
}

function install_PXEThief() {
    echo "[INFO] Installing PXEThief: "
    git -C /opt/tools/ clone --depth 1 https://github.com/blurbdust/PXEThief.git
    cd /opt/tools/PXEThief || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
}

function install_sccmhunter() {
    echo "[INFO] Installing SCCMHunter: "
    git -C /opt/tools/ clone --depth 1 https://github.com/garrettfoster13/sccmhunter
    cd /opt/tools/sccmhunter || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
}


function install_sccmsecrets() {
    echo "[INFO] Installing SCCMHsecrets: "
    git -C /opt/tools/ clone --depth 1 https://github.com/synacktiv/SCCMSecrets
    cd /opt/tools/SCCMSecrets || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
}

# BUG: does the tool even work?
function install_sccmwtf() {
    echo "[INFO] Installing SCCMH-wtf: "
    git -C /opt/tools/ clone --depth 1 https://github.com/xpn/sccmwtf
    cd /opt/tools/sccmwtf || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
}

function install_cmloot() {
    echo "[INFO] Installing cmloot: "
    git -C /opt/tools/ clone --depth 1 https://github.com/shelltrail/cmloot.git
    cd /opt/tools/cmloot || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install --requirements requirements.txt
    deactivate
}

function install_smbclientng() {
    echo "[INFO] Installing Smbclient-NG: "
    uv tool install git+https://github.com/p0dalirius/smbclient-ng
}

function install_conpass() {
    echo "[INFO] Installing Conpass: "
    uv tool install git+https://github.com/login-securite/conpass
    # https://github.com/login-securite/conpass/pull/5
}

function install_adminer() {
    echo "[INFO] Installing AD-Miner: "
    uv tool install git+https://github.com/Mazars-Tech/AD_Miner
}

function install_remotemonologue() {
    echo "[INFO] Installing RemoteMonologue: "
    git -C /opt/tools/ clone --depth 1 https://github.com/3lp4tr0n/RemoteMonologue
    cd /opt/tools/RemoteMonologue || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install impacket
    deactivate
}


function install_powerview() {
    echo "[INFO] Installing PowerView: "
    uv tool install git+https://github.com/aniqfakhrul/powerview.py
}

function install_pysnaffler(){
    echo "[INFO] Installing PySnaffler: "
    git -C /opt/tools/ clone --depth 1 https://github.com/skelsec/pysnaffler
    cd /opt/tools/pysnaffler || exit
    uv venv ./venv
    source ./venv/bin/activate
    uv pip install .
    deactivate
}

function install_evil-winrm-py() {
    echo "[INFO] Installing evil-winrm-py: "
    uv tool install 'evil-winrm-py[kerberos]@git+https://github.com/adityatelange/evil-winrm-py'
}


function main() {
    setup_dirs
    set_bin_path
    local start_time
    local end_time
    start_time=$(date +%s)
    install_pipx_uv                 # Install both pipx and UV
    install_asrepcatcher            # Active Directory ASREP roasting tool that catches ASREP for users in the same VLAN whether they require pre-authentication or not
    install_responder               # LLMNR, NBT-NS and MDNS poisoner
    install_ldapdomaindump
    install_sprayhound              # Password spraying tool
    install_smartbrute              # Password spraying tool
    install_bloodhound-py           # ingestor for legacy BloodHound
    install_bloodhound-ce-py        # ingestor for legacy BloodHound
    install_cypheroth               # Bloodhound dependency
    install_mitm6_pip               # DNS server misconfiguration exploiter
    install_aclpwn                  # ACL exploiter
    install_impacket                # Network protocols scripts
    install_lsassy                  # Credentials extracter
    install_privexchange            # Exchange exploiter
    install_ruler                   # Exchange exploiter
    install_darkarmour              # Windows AV evasion
    install_amber                   # AV evasion
    install_powershell              # Windows Powershell for Linux
    install_krbrelayx               # Kerberos unconstrained delegation abuse toolkit
    install_evilwinrm               # WinRM shell
    install_pypykatz                # Mimikatz implementation in pure Python
    install_krbjack                 # KrbJack
    install_enyx                    # Hosts discovery
    install_enum4linux-ng           # Hosts enumeration
    install_zerologon               # Exploit for zerologon cve-2020-1472
    install_libmspack               # Library for some loosely related Microsoft compression format
    install_oaburl                  # Send request to the MS Exchange Autodiscover service
    install_lnkup
    install_polenum
    install_smbmap                  # Allows users to enumerate samba share drives across an entire domain
    install_pth-tools               # Pass the hash attack
    install_smtp-user-enum          # SMTP user enumeration via VRFY, EXPN and RCPT
    install_gpp-decrypt             # Decrypt a given GPP encrypted string
    install_ntlmv1-multi            # NTLMv1 multi tools: modifies NTLMv1/NTLMv1-ESS/MSCHAPv2
    install_hashonymize             # Anonymize NTDS, ASREProast, Kerberoast hashes for remote cracking
    install_adidnsdump              # enumerate DNS records in Domain or Forest DNS zones
    install_pygpoabuse
    install_bloodhound-import
    install_bloodhound-quickwin     # Python script to find quickwins from BH data in a neo4j db
    install_ldapsearch-ad           # Python script to find quickwins from basic ldap enum
    install_petitpotam              # Python script to coerce auth through MS-EFSR abuse
    install_dfscoerce               # Python script to coerce auth through NetrDfsRemoveStdRoot and NetrDfsAddStdRoot abuse
    install_coercer                 # Python script to coerce auth through multiple methods
    install_pkinittools             # Python scripts to use kerberos PKINIT to obtain TGT
    install_pywhisker               # Python script to manipulate msDS-KeyCredentialLink
    install_manspider               # Snaffler-like in Python
    install_targetedKerberoast
    install_pcredz
    install_pywsus
    install_donpapi
    install_webclientservicescanner
    install_certipy
    install_shadowcoerce
    install_gmsadumper
    install_pylaps
    install_ldaprelayscan
    install_goldencopy
    install_crackhound
    install_ldeep
    # TODO: install_rusthound
    # TODO: install_godap                  # A complete terminal user interface (TUI) for LDAP
    # TODO:install_goexec                 # Go version of *exec (smb,dcom...) from impacket with stronger OPSEC
    # TODO: install_kerbrute                # Tool to enumerate and bruteforce AD accounts through kerberos pre-authentication
    # TODO: install_gosecretsdump           # secretsdump in Go for heavy files
    # TODO: install_windapsearch-go         # Active Directory Domain enumeration through LDAP queries
    # TODO: install_rusthound-ce
    install_certsync
    install_keepwn
    install_pre2k
    install_msprobe
    install_masky
    install_roastinthemiddle
    install_PassTheCert
    install_bqm                    # Deduplicate custom BloudHound queries from different datasets and merge them in one customqueries.json file.
    install_noPac
    install_roadrecon              # Rogue Office 365 and Azure (active) Directory tools
    install_roadtx                 # ROADtools Token eXchange
    install_teamsphisher           # TeamsPhisher is a Python3 program that facilitates the delivery of phishing messages and attachments to Microsoft Teams users whose organizations allow external communications.
    install_GPOddity
    install_netexec                # Crackmapexec repo
    install_extractbitlockerkeys   # Extract Bitlocker recovery keys from all the computers of the domain
    install_pywerview
    install_bloodhound-ce          # AD (Community Edition) security tool for reconnaissance and attacking AD environments
    install_ntlm_theft
    install_abuseACL
    install_bloodyAD               # Active Directory privilege escalation swiss army knife.
    install_autobloody             # Automatically exploit Active Directory privilege escalation paths.
    install_dploot                 # Python rewrite of SharpDPAPI written un C#.
    install_PXEThief
    install_sccmhunter             # SCCMHunter is a post-ex tool built to streamline identifying, profiling, and attacking SCCM related assets in an Active Directory domain.
    install_sccmsecrets
    install_sccmwtf                # This code is designed for exploring SCCM in a lab.
    install_cmloot
    install_smbclientng
    install_conpass                # Python tool for continuous password spraying taking into account the password policy.
    install_adminer
    install_remotemonologue        # A tool to coerce NTLM authentications via DCOM
    install_powerview              # Powerview Python implementation 
    install_pysnaffler             # Snaffler, but in Python
    install_evil-winrm-py          # Evil-Winrm, but in Python
    install_adidnsdump
    post_install
    
    end_time=$(date +%s)
    local elapsed_time=$((end_time - start_time))
    echo "[INFO] Installation completed in $elapsed_time seconds."
}


main "$@"
