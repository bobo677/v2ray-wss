#!/bin/sh

if [[ $EUID -ne 0 ]]; then
    clear
    echo "Error: This script must be run as root!" 1>&2
    exit 1
fi

timedatectl set-timezone Asia/Shanghai
v2path=$(cat /dev/urandom | head -1 | md5sum | head -c 6)
v2uuid=$(cat /proc/sys/kernel/random/uuid)
sub_vmess=$v2path"vmess98"
sub_clash=$v2path"clash98"

install_precheck(){
    echo "====输入已经DNS解析好的域名===="
    read domain
    
    if [ -f "/usr/bin/apt-get" ]; then
        apt-get update -y
        apt-get install -y net-tools curl
    else
        yum update -y
        yum install -y epel-release
        yum install -y net-tools curl
    fi

    sleep 3
    isPort=`netstat -ntlp| grep -E ':80 |:443 '`
    if [ "$isPort" != "" ];then
        clear
        echo " ================================================== "
        echo " 80或443端口被占用，请先释放端口再运行此脚本"
        echo
        echo " 端口占用信息如下："
        echo $isPort
        echo " ================================================== "
        exit 1
    fi
}

install_nginx(){
    if [ -f "/usr/bin/apt-get" ];then
        apt-get install -y nginx
    else
        yum install -y nginx
    fi

cat >/etc/nginx/nginx.conf<<EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
	worker_connections 768;
	# multi_accept on;
}

http {

	##
	# Basic Settings
	##

	sendfile on;
	tcp_nopush on;
	types_hash_max_size 2048;
	# server_tokens off;

	# server_names_hash_bucket_size 64;
	# server_name_in_redirect off;

	include /etc/nginx/mime.types;
	#default_type application/octet-stream;
	default_type text/plain;

	##
	# SSL Settings
	##

	ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
	ssl_prefer_server_ciphers on;

	##
	# Logging Settings
	##

	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;

	##
	# Gzip Settings
	##

	gzip on;

	# gzip_vary on;
	# gzip_proxied any;
	# gzip_comp_level 6;
	# gzip_buffers 16 8k;
	# gzip_http_version 1.1;
	# gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

	##
	# Virtual Host Configs
	##

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}
#mail {
#	# See sample authentication script at:
#	# http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
#
#	# auth_http localhost/auth.php;
#	# pop3_capabilities "TOP" "USER";
#	# imap_capabilities "IMAP4rev1" "UIDPLUS";
#
#	server {
#		listen     localhost:110;
#		protocol   pop3;
#		proxy      on;
#	}
#
#	server {
#		listen     localhost:143;
#		protocol   imap;
#		proxy      on;
#	}
#}
EOF

cat >/etc/nginx/conf.d/$domain.conf<<EOF
server {
    listen 80 proxy_protocol;
    listen [::]:80 proxy_protocol;
    listen 81 http2 proxy_protocol;
    server_name $domain;
    #root /usr/share/nginx/html;
    location / {
        proxy_ssl_server_name on;
        proxy_pass https://www.wallpaperstock.net;
        proxy_set_header Accept-Encoding '';
        sub_filter "www.wallpaperstock.net" "gh.emodmge.ml";
        sub_filter_once off;
    }
    location /config/sub {
	    alias /usr/local/etc/xray/vmess.txt;

    }
        location = /robots.txt {}

        
}
EOF

}

acme_ssl(){    
    apt-get -y install cron socat || yum -y install cronie socat
    curl https://get.acme.sh | sh -s email=my@example.com
    mkdir -p /etc/letsencrypt/live/$domain
    ~/.acme.sh/acme.sh --issue -d $domain --standalone --keylength ec-256 --pre-hook "systemctl stop nginx" --post-hook "~/.acme.sh/acme.sh --installcert -d $domain --ecc --fullchain-file /etc/letsencrypt/live/$domain/fullchain.pem --key-file /etc/letsencrypt/live/$domain/privkey.pem --reloadcmd \"systemctl restart nginx\""
}

install_v2ray(){
        
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    cp /etc/letsencrypt/live/$domain/fullchain.pem /usr/local/etc/xray/fullchain.pem
    cp /etc/letsencrypt/live/$domain/privkey.pem /usr/local/etc/xray/privkey.pem

cat >/usr/local/etc/xray/config.json<<EOF
{
    "stats": {},
    "api": {
        "tag": "api",
        "services": [
            "StatsService"
        ]
    },
    "policy": {
        "levels": {
            "0": {
                "handshake": 4,
                "connIdle": 300,
                "uplinkOnly": 2,
                "downlinkOnly": 5,
                "statsUserUplink": true,
                "statsUserDownlink": true,
                "bufferSize": 4
            }
        },
        "system": {
            "statsInboundUplink": true,
            "statsInboundDownlink": true,
            "statsOutboundUplink": true,
            "statsOutboundDownlink": true
        }
    },
    "reverse": {
        "portals": [
            {
                "tag": "portal",
                "domain": "pc4.localhost"
            }
        ]
    },
    "inbounds": [
        {
            "tag": "tunnel",
            "port": 443,
            "protocol": "vless",
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ],
                "metadataOnly": false,
                "domainsExcluded": [
                    "emodmge.ml"
                ]
            },
            "settings": {
                "clients": [
                    {
                        "id": "${v2uuid}",
                        "flow": "xtls-rprx-direct",
                        "level": 0
                    }
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "alpn": "http/1.1",
                        "dest": 80,
                        "xver": 1
                    },
                    {
                        "alpn": "h2",
                        "dest": 81,
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                    "serverName": "${domain}",
                    "alpn": [
                        "http/1.1",
                        "h2"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "/usr/local/etc/xray/fullchain.pem",
                            "keyFile": "/usr/local/etc/xray/privkey.pem"
                        }
                    ]
                }
            }
        },
        {
            "listen": "127.0.0.1",
            "port": 10085,
            "protocol": "dokodemo-door",
            "settings": {
                "address": "127.0.0.1"
            },
            "tag": "api"
        }
    ],
    "outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {}
        },
        {
            "tag": "block",
            "protocol": "blackhole",
            "settings": {}
        }
    ],
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "domainMatcher": "mph",
        "rules": [
            {
                "inboundTag": [
                    "api"
                ],
                "outboundTag": "api",
                "type": "field"
            },
            {
                "type": "field",
                "inboundTag": [
                    "tunnel"
                ],
                "domain": [
                    "byr.pt",
                    "geosite:category-anticensorship",
                    "geosite:google",
                    "geosite:youtube",
                    "geosite:telegram",
                    "geosite:category-media",
                    "geosite:geolocation-!cn"
                ],
                "outboundTag": "direct"
            },
            {
                "type": "field",
                "inboundTag": [
                    "interconn"
                ],
                "outboundTag": "portal"
            },
            {
                "type": "field",
                "inboundTag": [
                    "tunnel"
                ],
                "domain": [
                    "emodmge.ml",
                    "geosite:bilibili",
                    "geosite:cn",
                    "domain:icloud.com",
                    "domain:icloud-content.com",
                    "domain:cdn-apple.com",
                    "geosite:private"
                ],
                "outboundTag": "portal"
            },
            {
                "type": "field",
                "inboundTag": [
                    "tunnel"
                ],
                "ip": [
                    "geoip:cn"
                ],
                "outboundTag": "portal"
            },
            {
                "type": "field",
                "protocol": [
                    "bittorrent"
                ],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "domain": [
                    "geosite:category-ads-all"
                ],
                "outboundTag": "block"
            }
        ]
    }
}
EOF

    systemctl enable xay.service && systemctl restart xray.service
    rm -f tcp-wss.sh install-release.sh

cat >/usr/local/etc/xray/client.json<<EOF
{
	"v": "2",
	"ps": "${domain}",
	"add": "${domain}",
	"port": "443",
	"id": "${v2uuid}",
	"aid": "o",
	"scy": "auto",
	"net": "ws",
	"type": "none",
	"host": "${domain}",
	"path": "${v2path}?ed=2048",
	"tls": "tls"
}
EOF

cat > /usr/local/etc/xray/clash.yaml <<EOF
proxies:
  - name: ${domain}
    type: vmess
    server: ${domain}
    port: 443
    uuid: ${v2uuid}
    alterId: 0
    cipher: auto
    tls: true
    udp: true
    network: ws
    ws-opts:
      path: ${v2path}?ed=2048
      headers: 
      	Host: ${domain}
EOF

    clear
}

sub_vmesslink(){
    vmess="vmess://"$(base64 -w 0 /usr/local/etc/xray/client.json)
    echo $vmess | base64 -w 0 > vmess.txt
    systemctl restart nginx.service
}

install_sslibev(){
    if [ -f "/usr/bin/apt-get" ];then
        apt-get update -y
        apt-get install -y --no-install-recommends \
            autoconf automake debhelper pkg-config asciidoc xmlto libpcre3-dev apg pwgen rng-tools \
            libev-dev libc-ares-dev dh-autoreconf libsodium-dev libmbedtls-dev git
    else
        yum update -y
        yum install epel-release -y
        yum install gcc gettext autoconf libtool automake make pcre-devel asciidoc xmlto c-ares-devel libev-devel libsodium-devel mbedtls-devel git -y  
    fi

    git clone https://github.com/shadowsocks/shadowsocks-libev.git
    cd shadowsocks-libev
    git submodule update --init --recursive
    ./autogen.sh && ./configure --prefix=/usr && make
    make install
    mkdir -p /etc/shadowsocks-libev

cat >/etc/shadowsocks-libev/config.json<<EOF
{
    "server":["[::0]","0.0.0.0"],
    "server_port":10240,
    "password":"$v2uuid",
    "timeout":600,
    "method":"chacha20-ietf-poly1305"
}
EOF

cat >/etc/systemd/system/shadowsocks.service<<EOF
[Unit]
Description=Shadowsocks Server
After=network.target
[Service]
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks-libev/config.json
Restart=on-abort
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload && systemctl enable shadowsocks.service && systemctl restart shadowsocks.service
    cd ..
    rm -rf shadowsocks-libev tcp-wss.sh
    clear
}

client_v2ray(){
    echo
    echo "安装已经完成"
    echo
    echo "Vmess: https://${domain}/$sub_vmess
    echo "clash: https://${domain}/$sub_clash
    echo
    echo "===========v2ray配置参数============"
    echo "地址：${domain}"
    echo "端口：443/8080"
    echo "UUID：${v2uuid}"
    echo "加密方式：aes-128-gcm"
    echo "传输协议：ws"
    echo "路径：/${v2path}"
    echo "底层传输：tls"
    echo "注意：8080是免流端口不需要打开tls"
    echo
}

client_sslibev(){
    echo
    echo "安装已经完成"
    echo
    echo "===========Shadowsocks配置参数============"
    echo "地址：0.0.0.0"
    echo "端口：10240"
    echo "密码：${v2uuid}"
    echo "加密方式：chacha20-ietf-poly1305"
    echo "传输协议：tcp"
    echo
}

start_menu(){
    clear
    echo
    echo " 1. 安装Shadowsocks-libev"
    echo " 2. 安装v2ray+ws+tls"
    echo " 3. 同时安装上述两种代理"
    echo " 0. 退出脚本"
    echo
    read -p "请输入数字:" num
    case "$num" in
    1)
    install_sslibev
    client_sslibev
    ;;
    2)
    install_precheck
    install_nginx
    acme_ssl
    install_v2ray
    client_v2ray
    ;;
    3)
    install_precheck
    install_nginx
    acme_ssl
    install_v2ray
    install_sslibev
    client_v2ray
    client_sslibev
    ;;
    0)
    exit 1
    ;;
    *)
    clear
    echo "请输入正确数字"
    sleep 2s
    start_menu
    ;;
    esac
}

start_menu
