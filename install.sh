#!/bin/bash

red=$(tput setaf 1)
green=$(tput setaf 2)
reset=$(tput sgr0)

configPath='/usr/local/etc/xray/config.json'
nginxPath='/etc/nginx/conf.d/xray.conf'

isRoot() {
    if [[ "$EUID" -ne '0' ]]; then
        echo "${red}error: You must run this script as root!${reset}"
        exit 1
    fi
}

isNumber() {
    arg="$1"
    if [[ "$arg" =~ ^[0-9]+$ ]]; then
        return 1
    else
        return 0
    fi
}

identifyOS() {
    if [[ "$(uname)" != 'Linux' ]]; then
        echo "error: This operating system is not supported."
        exit 1
    fi
    if [[ "$(type -P apt)" ]]; then
        PACKAGE_MANAGEMENT_INSTALL='apt -y --no-install-recommends install'
        PACKAGE_MANAGEMENT_REMOVE='apt purge -y'
        PACKAGE_MANAGEMENT_UPDATE='apt update'
        package_provide_tput='ncurses-bin'
    elif [[ "$(type -P dnf)" ]]; then
        PACKAGE_MANAGEMENT_INSTALL='dnf -y install'
        PACKAGE_MANAGEMENT_REMOVE='dnf remove -y'
        PACKAGE_MANAGEMENT_UPDATE='dnf update'
        package_provide_tput='ncurses'
    elif [[ "$(type -P yum)" ]]; then
        PACKAGE_MANAGEMENT_INSTALL='yum -y install'
        PACKAGE_MANAGEMENT_REMOVE='yum remove -y'
        PACKAGE_MANAGEMENT_UPDATE='yum update'
        package_provide_tput='ncurses'
        ${PACKAGE_MANAGEMENT_INSTALL} 'epel-release' &>/dev/null
    else
        echo "error: The script does not support the package manager in this operating system."
        exit 1
    fi
}

isCommandExists() {
    local command_name="$1"
    if command -v "$command_name" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

installPackage() {
    local package_name="$1"

    if ${PACKAGE_MANAGEMENT_INSTALL} "$package_name" &>/dev/null; then
        echo "info: $package_name is installed."
    else
        echo "${red}error: Installation of $package_name failed, please check your network.${reset}"
        exit 1
    fi
}

uninstallPackage() {
    local package_name="$1"
    if ${PACKAGE_MANAGEMENT_REMOVE} "$package_name" &>/dev/null; then
        echo "info: $package_name is uninstalled."
    else
        echo "${red}error: Uninstallation of $package_name failed, please try to uninstall it manually.${reset}"
        exit 1
    fi
}

installXray() {
    echo "info: install Xray."
    isCommandExists 'xray' && return
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
}

installWarp() {
    echo "info: install WARP."
    isCommandExists 'warp-cli' && return
    if isCommandExists 'apt'; then
        curl https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list
    elif isCommandExists 'yum'; then
        curl -fsSl https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo | tee /etc/yum.repos.d/cloudflare-warp.repo
    else
        echo "${red}Your system doesn't support WARP!${reset}"
        exit
    fi
    ${PACKAGE_MANAGEMENT_UPDATE}
    installPackage "cloudflare-warp"
}

configWarp() {
    warp-cli --accept-tos register
    warp-cli set-mode proxy
    warp-cli connect
    sleep 3
    curl -x 'socks5://127.0.0.1:40000' 'https://www.cloudflare.com/cdn-cgi/trace/'
}

writeXrayConfig() {
    cat >$configPath <<EOF
{
    "log": {
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log",
        "loglevel": "warning",
        "dnsLog": false
    },
    "inbounds": [
        {
            "port": $(($1)),
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$(cat /proc/sys/kernel/random/uuid)"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "path": "/th1nk"
                }
            }
        }
    ],
    "outbounds": [
        {
            "tag": "free",
            "protocol": "freedom",
            "settings": {}
        },
        {
            "tag": "warp",
            "protocol": "socks",
            "settings": {
                "servers": [
                    {
                        "address": "127.0.0.1",
                        "port": 40000
                    }
                ]
            }
        }
    ],
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "domain": [
                    "domain:openai.com"
                ],
                "outboundTag": "warp"
            },
            {
                "type": "field",
                "port": "0-65535",
                "outboundTag": "free"
            }
        ]
    }
}
EOF
}

getConfigInfo() {
    xray_uuid=$(jq -r ".inbounds[0].settings.clients[0].id" $configPath)
    xray_addr=$(curl -s 'ip.sb')
    xray_streamPath=$(jq -r ".inbounds[0].streamSettings.wsSettings.path" $configPath)
    xray_userDomain=$(grep -m 1 -oP "server_name\s+\K\S+" $nginxPath | tr -d ';')
}

writeNginxConfig() {
    xrayPort=$(($1))
    domain="$2"
    proxyUrl="$3"
    [ -f '/etc/nginx/sites-enabled/default' ] && rm '/etc/nginx/sites-enabled/default'
    setNginxCert
    cat >/etc/nginx/conf.d/default.conf <<EOF
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    ssl_certificate        /etc/nginx/cert/default.crt;
    ssl_certificate_key    /etc/nginx/cert/default.key;
    server_name _;
    return 444;
}
EOF
    cat >$nginxPath <<EOF
server {
    listen 443 ssl;
    listen [::]:443 ssl;

    ssl_certificate       /etc/nginx/cert/cert.pem;
    ssl_certificate_key   /etc/nginx/cert/cert.key;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;
    ssl_session_tickets off;

    ssl_protocols         TLSv1.2 TLSv1.3;
    ssl_ciphers           ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    server_name           $domain;
    location /th1nk {
    if (\$http_upgrade != "websocket") {
        return 404;
    }
    proxy_redirect off;
    proxy_pass http://127.0.0.1:$xrayPort;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    # Show real IP in xray access.log
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
}
    location / {
        proxy_ssl_server_name on;
        proxy_pass $proxyUrl;
    }
}
server{
        listen 80;
        server_name _;
        return 500;
}
# 80 redirect to 443
server {
    listen 80;
    server_name $domain;
    rewrite ^(.*)$ https://\${server_name}\$1 permanent;
}
EOF
}

inputXrayPort() {
    read -rp "${green}Please input Xray port(16500 default):${reset}" xrayPort
    if [ -z "$xrayPort" ]; then
        xrayPort=16500
        ss -tuln | grep -q ":$xrayPort\b" && echo "${red}The port $xrayPort has been occupied.${reset}" && inputXrayPort
        return
    fi
    isNumber $xrayPort
    if [ $? -ne 1 ]; then
        echo "${red}the port should be a number.${reset}"
        inputXrayPort
    fi

    if [ "$xrayPort" -gt 65535 ] || [ "$xrayPort" -lt 1 ]; then
        echo "${red}the port should be 1-65535.${reset}"
        inputXrayPort
    fi
    ss -tuln | grep -q ":$xrayPort\b" && echo "${red}The port $xrayPort has been occupied.${reset}" && inputXrayPort

}

setNginxCert() {
    [ ! -d '/etc/nginx/cert' ] && mkdir '/etc/nginx/cert'
    cp 'cert.key' '/etc/nginx/cert/cert.key'
    cp 'cert.pem' '/etc/nginx/cert/cert.pem'
    cat >/etc/nginx/cert/default.crt <<EOF
-----BEGIN CERTIFICATE-----
MIIDUTCCAjmgAwIBAgIQAK9pm0FrtLk7umWBQEDszzANBgkqhkiG9w0BAQsFADAU
MRIwEAYDVQQDDAlhLmIuYy5jb20wHhcNMjIwOTAzMDI0NTMwWhcNMzIwODMxMDI0
NTMwWjAUMRIwEAYDVQQDDAlhLmIuYy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCQ7jJmeYkk1e+r3/UcEN4VkXH92NyW9Tfp0NA5VJlViCwhmtFo
6vuRVwCXpOUvPUWbpVQZYLyMWBD3xAb2W6LXfKBOR459OGGf4JlExnZWZ+qKoNfQ
T7GZkG9/IQl87A00bOuw34mc0RaStuE7GMR1ZYybphQSkkiFkDP+JSKAnjtNI211
FsFXVy5u6N6avY48QXZnZnKM5WJCxBAI2z5Dg/1uowFWioHJRSxBN5cLXFz2434p
YZFl1Hr/Y4l0Ia1FncATyjKX0H4ycGB/6BYtuHkKNMINwMnecCVtdyYBpHhRN67p
TVtNFEyG9XG40F3ZT3QeBTh3bF5Aqn2yArLHAgMBAAGjgZ4wgZswHQYDVR0OBBYE
FIUhosaI4tZItyUNeb2Ka/UaTSxLMA4GA1UdDwEB/wQEAwIEsDAMBgNVHRMBAf8E
AjAAMDsGA1UdJQQ0MDIGCCsGAQUFBwMCBggrBgEFBQcDAQYIKwYBBQUHAwMGCCsG
AQUFBwMEBggrBgEFBQcDCDAfBgNVHSMEGDAWgBSFIaLGiOLWSLclDXm9imv1Gk0s
SzANBgkqhkiG9w0BAQsFAAOCAQEAbyEDAzPza6x54p/3YdxiXGfZWpxdWvm7VUNn
Yvn61YrDCo3h0b26JOTSM3Oz8QRh4qV/hXbWMHgpkVo63aDvRrH+xITxijQbfEyE
+yCqWHv/mv/plLM2DoPwtXmvs6gBADaZfBCB6Q+zxE+sUT3vw6JMZ9cuBlSvIWt6
Lryb0o1m21JoXdB6naqTnzMfQRecZYpqrRgkDQ/izV9RkQlaan06f9VYz9W9CIJo
fEM/UFW0kjkr0ETtZr0mzcLDAu+M0AbNgguFSg3ONcgQkxghQ648qiiI08axZPkU
BQ/Bp0CbJjnXDb/++x/oLmK+KGxGaQjYntZv8BNK9CkOeitv2w==
-----END CERTIFICATE-----
EOF
    cat >/etc/nginx/cert/default.key <<EOF
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCQ7jJmeYkk1e+r
3/UcEN4VkXH92NyW9Tfp0NA5VJlViCwhmtFo6vuRVwCXpOUvPUWbpVQZYLyMWBD3
xAb2W6LXfKBOR459OGGf4JlExnZWZ+qKoNfQT7GZkG9/IQl87A00bOuw34mc0RaS
tuE7GMR1ZYybphQSkkiFkDP+JSKAnjtNI211FsFXVy5u6N6avY48QXZnZnKM5WJC
xBAI2z5Dg/1uowFWioHJRSxBN5cLXFz2434pYZFl1Hr/Y4l0Ia1FncATyjKX0H4y
cGB/6BYtuHkKNMINwMnecCVtdyYBpHhRN67pTVtNFEyG9XG40F3ZT3QeBTh3bF5A
qn2yArLHAgMBAAECggEAHJm0/n37b3Z8fpmKoEg/21fBfAvAtFWd/BlGDhpAzB08
QEFyE9dTX8IgjsxuodzgkK+Wog9yBewXJR3dFd7NiuLAK9J5LwLiWQ+Uj3ruvWxy
X3sQO76OWLSlHBxj5/AZRwA7nsLuQDEO2FMYrXXcxyIMFmc2zNdrUlg7umqPnXvQ
R+sDQbg3ngq8g6P5wZ7sXWF2Iu6heCis6p4cZiSwG1x0uNkS9GMwXuJC8dtWQBDk
Xrax1xFoKn2B9aIe4KzsDfIyifJe/oNJy4z+TKLjuR5CezZ4+XJbnLaYYY+6xZko
s6EKN3BMsnvFC+Q2sYKkWu2zd+dXIIoK95U/qqa0MQKBgQDBIlIOTm9S33A+V9Mc
SWzdY+Vv4lRfPi3LXwc4Foq7V/BK6+ewxHLW0eg1ATZkANlKMsGSLwZTUhsYZv/I
OLkpIgq+g7NjTxAuwObvl4DNJLX2aSbMaJpOA9/Nzi9cmuRIIvYcNrCqOK8ynqhs
bSorhBYvtHWS9/qv7wkmBIe4CQKBgQDAGx16NxLthePCfxMeWXT+btHProZHquqO
7S3UR5EiimpORCVle/CULnpS/o8fYJg+nk3k0S3oqqR+Q9OkWy6fhGIf01ULUppq
+whOS313tcZnIB1+kGY4acB67qI4a9bYxezlXn7rGeN1KnzpT9G1CxfEcypHdRaY
45bdyUOoTwKBgFkr8nz+g/HcjmOKg0OVNzmE7SNaeaA8AkLbDmc8KTPUp3LANwpr
uaYr5q3KcIV9ytWyV6OaKK6Bw1bh/4k/f2ZZfGJ4RnQ8xfkAQeAvsF2HbKhn5m0M
guowab4JS97S+UHBOqbOLYV6hJG3pYXiZU0QQHooNPz1l/5xPGUcRFmZAoGAW/3g
DMFIwBMocN/XMOZXnutEb3Y8eR9AeTbchlXLC0ZLB7WcTs+d8eebzhh2QulHnlzC
IjuFB3CHmqsyMvczCVIkhub1R5nDtk0FujBuIaAbJRD87rmJKaSCdpvFdM03MdD9
0wyALGbWRCoXbMY7Pr3UIM+hRFyueIIroYMacgMCgYEAgYFMKXVuxRvAKLV4oFKO
Guimh8e52h69/gLl49M4Fz8+6cbvTXEdWE/nkKRV3ahWw9WNQFao2YPm3pHAaocz
IEBbcWgHe9q2csnJsoF1Mx3lLuLQF/ZSJuc7+wRS6m+hPH8Y6y5ozMFJ+GJuOUNZ
T6W2nlU9KS6Mpsr8cNJn63g=
-----END PRIVATE KEY-----
EOF
}

inputDomain() {
    read -rp "${green}Please input your domain(DO NOT start with 'http/https'):${reset}" userDomain

    [[ ! $userDomain =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]] && echo "${red}The content you input is not a legal domain!${reset}" && inputDomain

}

inputProxyUrl() {
    read -rp "${green}Please input the proxy url(default https://httpbin.org/):${reset}" proxyUrl
    [ -z "$proxyUrl" ] && proxyUrl='https://httpbin.org/'
    local regex="^https?://[^[:space:]]+$"
    [[ ! $proxyUrl =~ $regex ]] && echo "${red}The content you input is not a legal url!${reset}" && inputProxyUrl
}

getShareUrl() {
    getConfigInfo
    local shareUrl
    shareUrl='vless://'$xray_uuid'@'$xray_addr':443?encryption=none&security=tls&type=ws&host='$xray_userDomain'&path=%2F'${xray_streamPath:1}'#th1nk-Xray'
    echo "$shareUrl"
}

getQrCode() {
    isCommandExists 'qrencode'
    [ $? -eq 1 ] && installPackage "qrencode"
    local url
    url=$(getShareUrl)
    qrencode -t ANSI "${url}"
    echo "${green}$url${reset}"
}

prepareSoftware() {
    installPackage "$package_provide_tput"
    installPackage "gpg"
    installPackage "unzip"
    installPackage "nginx"
    installPackage "nginx-extras"
    installPackage "jq"
    installXray
    installWarp
}

install() {
    ! [ -e "cert.key" ] || ! [ -e "cert.pem" ] && echo "${red}Please ensure 'cert.key' and 'cert.pem' exist in the current directory.${reset}" && exit 1

    isRoot
    identifyOS
    prepareSoftware
    inputXrayPort
    inputDomain
    inputProxyUrl
    writeXrayConfig $xrayPort
    writeNginxConfig $xrayPort "$userDomain" $proxyUrl
    configWarp

    systemctl restart xray nginx
    systemctl enable nginx xray

    getQrCode
}

modifyXrayUUID() {
    jq ".inbounds[0].settings.clients[0].id = \"$(cat /proc/sys/kernel/random/uuid)\"" $configPath >'config.tmp' && mv 'config.tmp' $configPath
    echo "${green}$(jq ".inbounds[0].settings.clients[0].id" $configPath)${reset}"
    echo 'info: restart Xray.'
    systemctl restart xray
}

modifyXrayPort() {
    local oldPort
    oldPort=$(jq ".inbounds[0].port" $configPath)
    echo "info: old port $oldPort"

    inputXrayPort
    jq ".inbounds[0].port = ${xrayPort}" $configPath >'config.tmp' && mv 'config.tmp' $configPath
    sed -i "s/127.0.0.1:${oldPort}/127.0.0.1:${xrayPort}/" $nginxPath
    echo "${green}$(jq ".inbounds[0].port" $configPath)${reset}"

    echo 'info: restart Xray.'
    systemctl restart xray
    echo 'info: restart Nginx.'
    systemctl restart nginx
}

modifyWsPath() {
    local oldPath
    oldPath=$(grep -Eo 'location (/[a-zA-Z0-9]+)' $nginxPath | grep -Eo '/[a-zA-Z0-9]+')
    echo "info: old websocket path $oldPath"

    read -rp "${green}Please input the new websocket path(${red}START WITH /${green}):${reset}" wsPath
    [[ ! $wsPath =~ ^/[a-zA-Z0-9]+$ ]] && modifyWsPath

    sed -i "s@location /[a-zA-Z0-9]\+@location ${wsPath}@" $nginxPath
    jq ".inbounds[0].streamSettings.wsSettings.path = \"$wsPath\"" $configPath >'config.tmp' && mv 'config.tmp' $configPath

    echo 'info: restart Xray.'
    systemctl restart xray
    echo 'info: restart Nginx.'
    systemctl restart nginx
}

modifyProxyPassUrl() {
    local oldProxyPassUrl
    oldProxyPassUrl=$(grep "proxy_pass" $nginxPath | grep -Eo 'https?://[^[:space:]]+' | awk 'NR == 2 {sub(/;$/, "", $0); print}')
    echo "info: old proxy pass url $oldProxyPassUrl"
    inputProxyUrl
    sed -i "s@$oldProxyPassUrl@$proxyUrl@" $nginxPath
    echo 'info: restart Nginx.'
    systemctl restart nginx
}

addDomainToWarpProxy() {
    read -rp "${green}Please input the domain to add to WARP Proxy List(${red}DO NOT START WITH http(s)${green}):${reset}" _proxyUrl
    [[ ! $_proxyUrl =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]] && addDomainToWarpProxy

    jq ".routing.rules[0].domain += [\"domain:$_proxyUrl\"]" $configPath >'config.tmp' && mv 'config.tmp' $configPath

    jq '.routing.rules[0].domain' $configPath
    unset _proxyUrl
}

deleteDomainFromWarpProxy() {
    local _domainList
    _domainList=$(jq '.routing.rules[0].domain[]' $configPath)
    local _domainListLength
    _domainListLength=$(jq '.routing.rules[0].domain | length' $configPath)

    [ "$_domainListLength" -eq 0 ] && echo "${red}The WARP Proxy List is empty!${reset}" && return

    local i=0
    for _domain in $_domainList; do
        echo -e "\t[$i]${green}$_domain${reset}"
        i=$((i + 1))
    done

    read -rp "${green}Please input the id of domain you want to delete:${reset}" _domainID
    ! isNumber _domainID && deleteDomainFromWarpProxy
    { [ "$_domainID" -gt $((_domainListLength - 1)) ] || [ "$_domainID" -lt 0 ]; } && deleteDomainFromWarpProxy

    local _deleteDomain
    _deleteDomain=$(echo "$_domainList" | awk "{print \$$((_domainID + 1))}")
    jq ".routing.rules[0].domain -= [$_deleteDomain]" $configPath >'config.tmp' && mv 'config.tmp' $configPath

    echo "${red}WARP Proxy List:${reset}"
    jq '.routing.rules[0].domain' $configPath
    unset _domainID

    echo 'info: restart Xray.'
    systemctl restart xray
}

menu() {
    echo -e "\t\t${red}Xray management${reset}"
    echo -e "\t\t[[author: th1nk]]"
    echo -e "\t—————————————— install ——————————————"
    echo -e "\t${green}0.${reset}  install Xray(VLESS + WebSocket + TLS + Nginx + WARP)"
    echo -e "\t—————————————— modify ——————————————"
    echo -e "\t${green}11.${reset}  modify Xray UUID"
    echo -e "\t${green}12.${reset}  modify Xray port"
    echo -e "\t${green}13.${reset}  modify websocket path"
    echo -e "\t${green}14.${reset}  modify proxy pass url"
    echo -e "\t${green}15.${reset}  add domain to WARP proxy"
    echo -e "\t${green}16.${reset}  remove domain from WARP proxy list"
    echo -e "\t—————————————— info ——————————————"
    echo -e "\t${green}21.${reset}  View Xray access log"
    echo -e "\t${green}22.${reset}  View Xray error log"
    echo -e "\t${green}23.${reset}  View nginx access log"
    echo -e "\t${green}24.${reset}  View nginx error log"
    echo -e "\t${green}25.${reset}  Generate Xray configuration url and qrcode"
    echo -e "\t${green}26.${reset}  Show WARP proxy domain list"
    echo -e "\t—————————————— other ——————————————"
    echo -e "\t${green}31.${reset} update Xray-core"
    echo -e "\t${green}32.${reset} uninstall all components"
    echo -e "\t${green}33.${reset} restart Xray and nginx"
    echo -e "\t—————————————— exit ——————————————"
    echo -e "\t${green}100.${reset} exit"
    read -rp "Please input number:" num
    case $num in
    0)
        install
        ;;
    11)
        modifyXrayUUID
        ;;
    12)
        modifyXrayPort
        ;;
    13)
        modifyWsPath
        ;;
    14)
        modifyProxyPassUrl
        ;;
    15)
        addDomainToWarpProxy
        ;;
    16)
        deleteDomainFromWarpProxy
        ;;
    21)
        tail -f '/var/log/xray/access.log'
        ;;
    22)
        tail -f '/var/log/xray/error.log'
        ;;
    23)
        tail -f '/var/log/nginx/access.log'
        ;;
    24)
        tail -f '/var/log/nginx/error.log'
        ;;
    25)
        getQrCode
        ;;
    26)
        jq '.routing.rules[0].domain' $configPath
        ;;
    31)
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
        ;;
    32)
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove
        systemctl stop nginx xray
        warp-cli disconnect
        uninstallPackage 'nginx*'
        uninstallPackage 'cloudflare-warp'
        ;;
    33)
        echo 'info: restart Xray.'
        systemctl restart xray
        echo 'info: restart Nginx.'
        systemctl restart nginx
        ;;
    100)
        exit 0
        ;;
    *)
        echo "${red}please input the correct number${reset}"
        menu
        ;;
    esac
    unset num
}

menu "$@"
