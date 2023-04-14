#!/usr/bin/env bash
#Detection area
# -------------------------------------------------------------
#Check the system
export LANG=en_US.UTF-8

echoContent() {
	case $1 in
	#Red
	"red")
		# shellcheck disable=SC2154
		${echoType} "\033[31m${printN}$2 \033[0m"
		;;
		#Sky Blue
	"skyBlue")
		${echoType} "\033[1;36m${printN}$2 \033[0m"
		;;
		#Green
	"green")
		${echoType} "\033[32m${printN}$2 \033[0m"
		;;
		#White
	"white")
		${echoType} "\033[37m${printN}$2 \033[0m"
		;;
	"magenta")
		${echoType} "\033[31m${printN}$2 \033[0m"
		;;
		#Yellow
	"yellow")
		${echoType} "\033[33m${printN}$2 \033[0m"
		;;
	esac
}
checkSystem() {
	if [[ -n $(find /etc -name "redhat-release") ]] || grep </proc/version -q -i "centos"; then
		mkdir -p /etc/yum.repos.d

		if [[ -f "/etc/centos-release" ]]; then
			centosVersion=$(rpm -q centos-release | awk -F "[-]" '{print $3}' | awk -F "[.]" '{print $1}')

			if [[ -z "${centosVersion}" ]] && grep </etc/centos-release -q -i "release 8"; then 			centosVersion=8
			fi
		fi

		release="centos"
		installType='yum -y install'
		removeType='yum -y remove'
		upgrade="yum update -y --skip-broken"

	elif grep </etc/issue -q -i "debian" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "debian" && [[ -f "/proc/version" ]]; then 	release="debian"
		installType='apt -y install'
		upgrade="apt update"
		updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
		removeType='apt -y autoremove'

	elif grep </etc/issue -q -i "ubuntu" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "ubuntu" && [[ -f "/proc/version" ]]; then 	release="ubuntu"
		installType='apt -y install'
		upgrade="apt update"
		updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
		removeType='apt -y autoremove'
		if grep </etc/issue -q -i "16."; then
			release=
		fi
	fi

	if [[ -z ${release} ]]; then 	echoContent red "\nThis script does not support this system, please send the following log feedback to the developer\n"
		echoContent yellow "$(cat /etc/issue)"
		echoContent yellow "$(cat /proc/version)"
		exit 0
	fi
}

#Check CPU provider
checkCPUVendor() {
	if [[ -n $(which uname) ]]; then
		if [[ "$(uname)" == "Linux" ]]; then 		case "$(uname -m)" in
			'amd64' | 'x86_64')
				xrayCoreCPUVendor="Xray-linux-64"
				v2rayCoreCPUVendor="v2ray-linux-64"
				hysteriaCoreCPUVendor="hysteria-linux-amd64"
				;;
			'armv8' | 'aarch64')
				xrayCoreCPUVendor="Xray-linux-arm64-v8a"
				v2rayCoreCPUVendor="v2ray-linux-arm64-v8a"
				hysteriaCoreCPUVendor="hysteria-linux-arm64"
				;;
			*)
				echo "  This CPU architecture is not supported--->"
				exit 1
				;;
			esac
		fi
	else
		echoContent red "  This CPU architecture is not recognized. Default is amd64, x86_64--->"
		xrayCoreCPUVendor="Xray-linux-64"
		v2rayCoreCPUVendor="v2ray-linux-64"
	fi
}

#Initialize global variables
initVar() {
	installType='yum -y install'
	removeType='yum -y remove'
	upgrade="yum -y update"
	echoType='echo -e'

	#CPU versions supported by the core
	xrayCoreCPUVendor=""
	v2rayCoreCPUVendor=""
	hysteriaCoreCPUVendor=""

	#Domain name
	domain=

	#Address of CDN node
	add=

	#Overall installation progress
	totalProgress=1

	#1. xray core installation
	#2. v2ray core installation
	#3. Installation of xray core preview version
	coreInstallType=

	#Core installation path
	# coreInstallPath=

	# v2ctl Path
	ctlPath=
	#1. Install All
	#2. Personalized installation
	# v2rayAgentInstallType=

	#Current personalized installation method 01234
	currentInstallProtocolType=

	#The order of the current Alpn
	currentAlpn=

	#Pre type
	frontingType=

	#Selected personalized installation method
	selectCustomInstallType=

	#Path to v2ray core and xray core configuration files
	configPath=

	#Path to the Hysteria configuration file
	hysteriaConfigPath=

	#Path of configuration file
	currentPath=

	#Host of configuration file
	currentHost=

	#Core type selected during installation
	selectCoreType=

	#Default Core Version
	v2rayCoreVersion=

	#Random Path
	customPath=

	# centos version
	centosVersion=

	# UUID
	currentUUID=

	# previousClients
	previousClients=

	localIP=

	#Integration update certificate logic no longer uses a separate script - RenewTLS
	renewTLS=$1

	#Number of attempts after failed tls installation
	installTLSCount=

	#BTPanel status
	#	BTPanelStatus=

	#Nginx configuration file path
	nginxConfigPath=/etc/nginx/conf.d/

	#Is it a preview version
	prereleaseStatus=false

	#Does xtls use vision
	xtlsRprxVision=

	#SSL type
	sslType=

	#SSL email
	sslEmail=

	#Inspection days
	sslRenewalDays=90

	#DNS SSL status
	dnsSSLStatus=

	# dns tls domain
	dnsTLSDomain=

	#Does this domain name install wildcard certificates through DNS
	installDNSACMEStatus=

	#Custom Port
	customPort=

	#Hysteria Port
	hysteriaPort=

	#Hysteria protocol
	hysteriaProtocol=

	#Hysteria delay
	hysteriaLag=

	#Hysteria downstream speed
	hysteriaClientDownloadSpeed=

	#Hysteria uplink speed
	hysteriaClientUploadSpeed=

}

#Read tls certificate details
readAcmeTLS() {
	if [[ -n "${currentHost}" ]]; then
		dnsTLSDomain=$(echo "${currentHost}" | awk -F "[.]" '{print $(NF-1)"."$NF}')
	fi
	if [[ -d "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc" && -f "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc/*.${dnsTLSDomain}.key" && -f "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc/*.${dnsTLSDomain}.cer" ]]; then
		installDNSACMEStatus=true
	fi
}
#Read default custom port
readCustomPort() {
	if [[ -n "${configPath}" ]]; then 	local port=
		port=$(jq -r .inbounds[0].port "${configPath}${frontingType}.json")
		if [[ "${port}" != "443" ]]; then 		customPort=${port}
		fi
	fi
}
#Detection and installation method
readInstallType() {
	coreInstallType=
	configPath=
	hysteriaConfigPath=

	#1. Detect installation directory
	if [[ -d "/etc/v2ray-agent" ]]; then
		#Detect installation method v2ray core
		if [[ -d "/etc/v2ray-agent/v2ray" && -f "/etc/v2ray-agent/v2ray/v2ray" && -f "/etc/v2ray-agent/v2ray/v2ctl" ]]; then
			if [[ -d "/etc/v2ray-agent/v2ray/conf" && -f "/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json" ]]; then 			configPath=/etc/v2ray-agent/v2ray/conf/
				if grep </etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json -q '"security": "tls"'; then
					#V2ray core without XTLS
					coreInstallType=2
					ctlPath=/etc/v2ray-agent/v2ray/v2ctl
				fi
			fi
		fi
    fi
	
	if [[ -d "/etc/v2ray-agent/xray" && -f "/etc/v2ray-agent/xray/xray" ]]; then
		#Detect xray core here
		if [[ -d "/etc/v2ray-agent/xray/conf" ]] && [[ -f "/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json" || -f "/etc/v2ray-agent/xray/conf/02_trojan_TCP_inbounds.json" ]]; then
			# xray-core
			configPath=/etc/v2ray-agent/xray/conf/
			ctlPath=/etc/v2ray-agent/xray/xray
			if grep </etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json -q '"security": "xtls"'; then 			coreInstallType=1
		    elif grep </etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json -q '"security": "tls"'; then 			coreInstallType=3
			fi
		fi
	fi

	if [[ -d "/etc/v2ray-agent/hysteria" && -f "/etc/v2ray-agent/hysteria/hysteria" ]]; then
		#Detect hysteria here
		if [[ -d "/etc/v2ray-agent/hysteria/conf" ]] && [[ -f "/etc/v2ray-agent/hysteria/conf/config.json" ]] && [[ -f "/etc/v2ray-agent/hysteria/conf/client_network.json" ]]; then 		hysteriaConfigPath=/etc/v2ray-agent/hysteria/conf/
		fi
	fi
}

#Read Protocol Type
readInstallProtocolType() {
	currentInstallProtocolType=

	while read -r row; do
		if echo "${row}" | grep -q 02_trojan_TCP_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'trojan'
			frontingType=02_trojan_TCP_inbounds
		fi
		if echo "${row}" | grep -q VLESS_TCP_inbounds; then 		currentInstallProtocolType=${currentInstallProtocolType}'0'
			frontingType=02_VLESS_TCP_inbounds
		fi
		if echo "${row}" | grep -q VLESS_WS_inbounds; then 		currentInstallProtocolType=${currentInstallProtocolType}'1'
		fi
		if echo "${row}" | grep -q trojan_gRPC_inbounds; then 		currentInstallProtocolType=${currentInstallProtocolType}'2'
		fi
		if echo "${row}" | grep -q VMess_WS_inbounds; then 		currentInstallProtocolType=${currentInstallProtocolType}'3'
		fi
		if echo "${row}" | grep -q 04_trojan_TCP_inbounds; then 		currentInstallProtocolType=${currentInstallProtocolType}'4'
		fi
		if echo "${row}" | grep -q VLESS_gRPC_inbounds; then 		currentInstallProtocolType=${currentInstallProtocolType}'5'
		fi
	done < <(find ${configPath} -name "*inbounds.json" | awk -F "[.]" '{print $1}')

	if [[ -n "${hysteriaConfigPath}" ]]; then
		currentInstallProtocolType=${currentInstallProtocolType}'6'
	fi
}

#Check if the pagoda is installed
checkBTPanel() {
	if pgrep -f "BT-Panel"; then
		nginxConfigPath=/www/server/panel/vhost/nginx/
		#		BTPanelStatus=true
	fi
}
#Read the order of the current Alpn
readInstallAlpn() {
	if [[ -n ${currentInstallProtocolType} ]]; then 	local alpn
		if [[ "${coreInstallType}" == "1" ]]; then
			alpn=$(jq -r .inbounds[0].streamSettings.xtlsSettings.alpn[0] ${configPath}${frontingType}.json)
		else
			alpn=$(jq -r .inbounds[0].streamSettings.tlsSettings.alpn[0] ${configPath}${frontingType}.json)
		fi
		if [[ -n ${alpn} ]]; then 		currentAlpn=${alpn}
		fi
	fi
}

#Check firewall
allowPort() {
	#If the firewall is activated, add the corresponding open port
	if systemctl status netfilter-persistent 2>/dev/null | grep -q "active (exited)"; then
		local updateFirewalldStatus=
		if ! iptables -L | grep -q "$1(mack-a)"; then
			updateFirewalldStatus=true
			iptables -I INPUT -p tcp --dport "$1" -m comment --comment "allow $1(mack-a)" -j ACCEPT
		fi

		if echo "${updateFirewalldStatus}" | grep -q "true"; then
			netfilter-persistent save
		fi
	elif systemctl status ufw 2>/dev/null | grep -q "active (exited)"; then
		if ufw status | grep -q "Status: active"; then
			if ! ufw status | grep -q "$1"; then
				sudo ufw allow "$1"
				checkUFWAllowPort "$1"
			fi
		fi

	elif
		systemctl status firewalld 2>/dev/null | grep -q "active (running)"
	then
		local updateFirewalldStatus=
		if ! firewall-cmd --list-ports --permanent | grep -qw "$1/tcp"; then
			updateFirewalldStatus=true
			firewall-cmd --zone=public --add-port="$1/tcp" --permanent
			checkFirewalldAllowPort "$1"
		fi

		if echo "${updateFirewalldStatus}" | grep -q "true"; then 		firewall-cmd --reload
		fi
	fi
}

#Check the occupancy of ports 80 and 443
checkPortUsedStatus() {
	if lsof -i tcp:80 | grep -q LISTEN; then
		echoContent red "\n ---> Port 80 is occupied. Manually close the port and install it\n"
		lsof -i tcp:80 | grep LISTEN
		exit 0
	fi

	if lsof -i tcp:443 | grep -q LISTEN; then
		echoContent red "\n ---> Port 443 is occupied. Manually shut down the port and install it\n"
		lsof -i tcp:80 | grep LISTEN
		exit 0
	fi
}

#Output ufw port open state
checkUFWAllowPort() {
	if ufw status | grep -q "$1"; then
		echoContent green " --->  Port $1 is successfully opened. Procedure"
	else
		echoContent red " --->  Port $1 opening failed"
		exit 0
	fi
}

#Output firewall-cmd port open status
checkFirewalldAllowPort() {
	if firewall-cmd --list-ports --permanent | grep -q "$1"; then 	echoContent green " ---> Port $1 opening succeeds"
	else
		echoContent red " ---> Port $1 opening failed"
		exit 0
	fi
}

#Reading the Hysteria Network Environment
readHysteriaConfig() {
	if [[ -n "${hysteriaConfigPath}" ]]; then 	hysteriaLag=$(jq -r .hysteriaLag <"${hysteriaConfigPath}client_network.json")
		hysteriaClientDownloadSpeed=$(jq -r .hysteriaClientDownloadSpeed <"${hysteriaConfigPath}client_network.json")
		hysteriaClientUploadSpeed=$(jq -r .hysteriaClientUploadSpeed <"${hysteriaConfigPath}client_network.json")
		hysteriaPort=$(jq -r .listen <"${hysteriaConfigPath}config.json" | awk -F "[:]" '{print $2}')
		hysteriaProtocol=$(jq -r .protocol <"${hysteriaConfigPath}config.json")
	fi
}
#Check the file directory and path path
readConfigHostPathUUID() {
	currentPath=
	currentDefaultPort=
	currentUUID=
	currentHost=
	currentPort=
	currentAdd=
	#Read path
	if [[ -n "${configPath}" ]]; then 	local fallback
		fallback=$(jq -r -c '.inbounds[0].settings.fallbacks[]|select(.path)' ${configPath}${frontingType}.json | head -1)

		local path
		path=$(echo "${fallback}" | jq -r .path | awk -F "[/]" '{print $2}')

		if [[ $(echo "${fallback}" | jq -r .dest) ==31297 ]]; then 		currentPath=$(echo "${path}" | awk -F "[w][s]" '{print $1}')
		elif [[ $(echo "${fallback}" | jq -r .dest) ==31298 ]]; then 		currentPath=$(echo "${path}" | awk -F "[t][c][p]" '{print $1}')
		elif [[ $(echo "${fallback}" | jq -r .dest) ==31299 ]]; then 		currentPath=$(echo "${path}" | awk -F "[v][w][s]" '{print $1}')
		fi
		#Attempt to read alpn h2 Path

		if [[ -z "${currentPath}" ]]; then
			dest=$(jq -r -c '.inbounds[0].settings.fallbacks[]|select(.alpn)|.dest' ${configPath}${frontingType}.json | head -1)
			if [[ "${dest}" == "31302" || "${dest}" == "31304" ]]; then

				if grep -q "trojangrpc {" <${nginxConfigPath}alone.conf; then 				currentPath=$(grep "trojangrpc {" <${nginxConfigPath}alone.conf | awk -F "[/]" '{print $2}' | awk -F "[t][r][o][j][a][n]" '{print $1}')
				elif grep -q "grpc {" <${nginxConfigPath}alone.conf; then 				currentPath=$(grep "grpc {" <${nginxConfigPath}alone.conf | head -1 | awk -F "[/]" '{print $2}' | awk -F "[g][r][p][c]" '{print $1}')
				fi
			fi
		fi

		local defaultPortFile=
		defaultPortFile=$(find ${configPath}* | grep "default")

		if [[ -n "${defaultPortFile}" ]]; then 		currentDefaultPort=$(echo "${defaultPortFile}" | awk -F [_] '{print $4}')
		else
			currentDefaultPort=$(jq -r .inbounds[0].port ${configPath}${frontingType}.json)
		fi

	fi
	if [[ "${coreInstallType}" == "1" || "${coreInstallType}" == "3" ]]; then
		if [[ "${coreInstallType}" == "3" ]]; then
			currentHost=$(jq -r .inbounds[0].streamSettings.tlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		else
			currentHost=$(jq -r .inbounds[0].streamSettings.xtlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		fi
		currentUUID=$(jq -r .inbounds[0].settings.clients[0].id ${configPath}${frontingType}.json)
		currentAdd=$(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json)
		if [[ "${currentAdd}" == "null" ]]; then
			currentAdd=${currentHost}
		fi
		currentPort=$(jq .inbounds[0].port ${configPath}${frontingType}.json)

	elif [[ "${coreInstallType}" == "2" ]]; then
		currentHost=$(jq -r .inbounds[0].streamSettings.tlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		currentAdd=$(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json)
		if [[ "${currentAdd}" == "null" ]]; then
			currentAdd=${currentHost}
		fi
		currentUUID=$(jq -r .inbounds[0].settings.clients[0].id ${configPath}${frontingType}.json)
		currentPort=$(jq .inbounds[0].port ${configPath}${frontingType}.json)
	fi
}

#Status display
showInstallStatus() {
	if [[ -n "${coreInstallType}" ]]; then
		if [[ "${coreInstallType}" ==1 || "${coreInstallType}" ==3 ]]; then
			if [[ -n $(pgrep -f xray/xray) ]]; then
				echoContent yellow "\nCore: Xray-core[Running]"
			else
				EchoContent yellow " nCore: Xray core [Not running]"
			fi

		elif [[ "${coreInstallType}" ==2 ]]; then
			if [[ -n $(pgrep -f v2ray/v2ray) ]]; then
				EchoContent yellow " nCore: v2ray core [Running]"
			else
				EchoContent yellow " nCore: v2ray core [Not running]"
			fi
		fi
		#Read Protocol Type
		readInstallProtocolType

		if [[ -n ${currentInstallProtocolType} ]]; then
			EchoContent yellow "Protocol installed:  c"
		fi
		if echo ${currentInstallProtocolType} | grep -q 0; then
			if [[ "${coreInstallType}" ==2 ]]; then
				echoContent yellow "VLESS+TCP[TLS] \c"
			else
				echoContent yellow "VLESS+TCP[TLS/XTLS] \c"
			fi
		fi

		if echo ${currentInstallProtocolType} | grep -q trojan; then
			if [[ "${coreInstallType}" ==1 ]]; then
				echoContent yellow "Trojan+TCP[TLS/XTLS] \c"
			fi
		fi

		if echo ${currentInstallProtocolType} | grep -q 1; then
			echoContent yellow "VLESS+WS[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 2; then
			echoContent yellow "Trojan+gRPC[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 3; then
			echoContent yellow "VMess+WS[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 4; then
			echoContent yellow "Trojan+TCP[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 5; then
			echoContent yellow "VLESS+gRPC[TLS] \c"
		fi
	fi
}

#Clean up old residues
cleanUp() {
	if [[ "$1" == "v2rayClean" ]]; then
		rm -rf "$(find /etc/v2ray-agent/v2ray/* | grep -E '(config_full.json|conf)')"
		handleV2Ray stop >/dev/null
		rm -f /etc/systemd/system/v2ray.service
	elif [[ "$1" == "xrayClean" ]]; then
		rm -rf "$(find /etc/v2ray-agent/xray/* | grep -E '(config_full.json|conf)')"
		handleXray stop >/dev/null
		rm -f /etc/systemd/system/xray.service

	elif [[ "$1" == "v2rayDel" ]]; then
		rm -rf /etc/v2ray-agent/v2ray/*

	elif [[ "$1" == "xrayDel" ]]; then
		rm -rf /etc/v2ray-agent/xray/*
	fi
}

initVar "$1"
checkSystem
checkCPUVendor
readInstallType
readInstallProtocolType
readConfigHostPathUUID
readInstallAlpn
readCustomPort
checkBTPanel
# -------------------------------------------------------------

#Initialize installation directory
mkdirTools() {
	mkdir -p /etc/v2ray-agent/tls
	mkdir -p /etc/v2ray-agent/subscribe
	mkdir -p /etc/v2ray-agent/subscribe_tmp
	mkdir -p /etc/v2ray-agent/v2ray/conf
	mkdir -p /etc/v2ray-agent/v2ray/tmp
	mkdir -p /etc/v2ray-agent/xray/conf
	mkdir -p /etc/v2ray-agent/xray/tmp
	mkdir -p /etc/v2ray-agent/trojan
	mkdir -p /etc/v2ray-agent/hysteria/conf
	mkdir -p /etc/systemd/system/
	mkdir -p /tmp/v2ray-agent-tls/
}

#Installation kit
installTools() {
	EchoContent skyBlue " n Progress $1/${totalProgress}: Installation tool"
	#Fix individual system issues with ubuntu
	if [[ "${release}" == "ubuntu" ]]; then
		dpkg --configure -a
	fi

	if [[ -n $(pgrep -f "apt") ]]; then
		pgrep -f apt | xargs kill -9
	fi

	echoContent green " ---> Check, install and update [New machine will be slow, if there is no response for a long time, please manually stop and restart]"

	${upgrade} >/etc/v2ray-agent/install.log 2>&1
	if grep <"/etc/v2ray-agent/install.log" -q "changed"; then
		${updateReleaseInfoChange} >/dev/null 2>&1
	fi

	if [[ "${release}" == "centos" ]]; then
		rm -rf /var/run/yum.pid
		${installType} epel-release >/dev/null 2>&1
	fi

	#	[[ -z `find /usr/bin /usr/sbin |grep -v grep|grep -w curl` ]]

	if ! find /usr/bin /usr/sbin | grep -q -w wget; then
		EchoContent green "-->Install wget"
		${installType} wget >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w curl; then
		EchoContent green "-->Install curl"
		${installType} curl >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w unzip; then
		EchoContent green "-->Install unzip"
		${installType} unzip >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w socat; then
		EchoContent green "-->Install socat"
		${installType} socat >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w tar; then
		EchoContent green "-->Install tar"
		${installType} tar >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w cron; then
		EchoContent green "-->Install crontabs"
		if [[ "${release}" == "ubuntu" ]] || [[ "${release}" == "debian" ]]; then
			${installType} cron >/dev/null 2>&1
		else
			${installType} crontabs >/dev/null 2>&1
		fi
	fi
	if ! find /usr/bin /usr/sbin | grep -q -w jq; then
		EchoContent green "-->Install jq"
		${installType} jq >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w binutils; then
		EchoContent green "-->Install binutils"
		${installType} binutils >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w ping6; then
		EchoContent green "-->Install ping6"
		${installType} inetutils-ping >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w qrencode; then
		EchoContent green "-->Install qrencode"
		${installType} qrencode >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w sudo; then
		EchoContent green "-->Install sudo"
		${installType} sudo >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w lsb-release; then
		EchoContent green "-->Install lsb release"
		${installType} lsb-release >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w lsof; then
		EchoContent green "-->Install lsof"
		${installType} lsof >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w dig; then
		EchoContent green "-->Install dig"
		if echo "${installType}" | grep -q -w "apt"; then
			${installType} dnsutils >/dev/null 2>&1
		elif echo "${installType}" | grep -q -w "yum"; then
			${installType} bind-utils >/dev/null 2>&1
		fi
	fi

	#Detect nginx version and provide option to uninstall or not

	if ! find /usr/bin /usr/sbin | grep -q -w nginx; then
		EchoContent green "-->Install nginx"
		installNginxTools
	else
		nginxVersion=$(nginx -v 2>&1)
		nginxVersion=$(echo "${nginxVersion}" | awk -F "[n][g][i][n][x][/]" '{print $2}' | awk -F "[.]" '{print $2}')
		if [[ ${nginxVersion} -lt 14 ]]; then
			Read - r - p "Read that the current Nginx version does not support gRPC, which will cause installation failure. Do you want to uninstall Nginx and reinstall it? [y/n]:" uninstallNginxStatus
			if [[ "${unInstallNginxStatus}" == "y" ]]; then
				${removeType} nginx >/dev/null 2>&1
				EchoContent yellow "-->nginx uninstallation completed"
				EchoContent green "-->Install nginx"
				installNginxTools >/dev/null 2>&1
			else
				exit 0
			fi
		fi
	fi
	if ! find /usr/bin /usr/sbin | grep -q -w semanage; then
		EchoContent green "-->Install semanage"
		${installType} bash-completion >/dev/null 2>&1

		if [[ "${centosVersion}" == "7" ]]; then 		policyCoreUtils="policycoreutils-python.x86_64"
		elif [[ "${centosVersion}" == "8" ]]; then 		policyCoreUtils="policycoreutils-python-utils-2.9-9.el8.noarch"
		fi

		if [[ -n "${policyCoreUtils}" ]]; then
			${installType} ${policyCoreUtils} >/dev/null 2>&1
		fi
		if [[ -n $(which semanage) ]]; then
			semanage port -a -t http_port_t -p tcp 31300

		fi
	fi

	if [[ ! -d "$HOME/.acme.sh" ]] || [[ -d "$HOME/.acme.sh" && -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
		EchoContent green "-->Install acme. sh"
		curl -s https://get.acme.sh  | sh >/etc/v2ray-agent/tls/acme.log 2>&1

		if [[ ! -d "$HOME/.acme.sh" ]] || [[ -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
			EchoContent red "ACME installation failed -->"
			tail -n 100 /etc/v2ray-agent/tls/acme.log
			EchoContent yellow "Error troubleshooting:
			EchoContent red "1. Failed to retrieve Github file. Please wait for Github to recover and try again. The recovery progress can be viewed[ https://www.githubstatus.com/]"
			EchoContent red "2. acme. sh script has a bug, which can be viewed[ https://github.com/acmesh-official/acme.sh ] issues"
			EchoContent red "3. For pure IPv6 machines, please set NAT64 and execute the following command"
			echoContent skyBlue "  echo -e \"nameserver 2001:67c:2b0::4\\\nnameserver 2001:67c:2b0::6\" >> /etc/resolv.conf"
			exit 0
		fi
	fi
}

#Install Nginx
installNginxTools() {

	if [[ "${release}" == "debian" ]]; then
		sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
		echo "deb http://nginx.org/packages/mainline/debian  $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
		echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
		curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key  >/dev/null 2>&1
		# gpg --dry-run --quiet --import --import-options import-show /tmp/nginx_signing.key
		sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "ubuntu" ]]; then
		sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
		echo "deb http://nginx.org/packages/mainline/ubuntu  $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
		echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
		curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key  >/dev/null 2>&1
		# gpg --dry-run --quiet --import --import-options import-show /tmp/nginx_signing.key
		sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "centos" ]]; then
		${installType} yum-utils >/dev/null 2>&1
		cat <<EOF >/etc/yum.repos.d/nginx.repo
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/\$releasever/\$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true

[nginx-mainline]
name=nginx mainline repo
baseurl=http://nginx.org/packages/mainline/centos/\$releasever/\$basearch/
gpgcheck=1
enabled=0
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
		sudo yum-config-manager --enable nginx-mainline >/dev/null 2>&1
	fi
	${installType} nginx >/dev/null 2>&1
	systemctl daemon-reload
	systemctl enable nginx
}

#Install Warp
installWarp() {
	${installType} gnupg2 -y >/dev/null 2>&1
	if [[ "${release}" == "debian" ]]; then
		curl -s https://pkg.cloudflareclient.com/pubkey.gpg  | sudo apt-key add - >/dev/null 2>&1
		echo "deb http://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null 2>&1
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "ubuntu" ]]; then
		curl -s https://pkg.cloudflareclient.com/pubkey.gpg  | sudo apt-key add - >/dev/null 2>&1
		echo "deb http://pkg.cloudflareclient.com/ focal main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null 2>&1
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "centos" ]]; then
		${installType} yum-utils >/dev/null 2>&1
		sudo rpm -ivh " http://pkg.cloudflareclient.com/cloudflare-release-el ${centosVersion}.rpm" >/dev/null 2>&1
	fi

	EchoContent green "-->Install WARP"
	${installType} cloudflare-warp >/dev/null 2>&1
	if [[ -z $(which warp-cli) ]]; then
		EchoContent red "-->Installation of WARP failed"
		exit 0
	fi
	systemctl enable warp-svc
	warp-cli --accept-tos register
	warp-cli --accept-tos set-mode proxy
	warp-cli --accept-tos set-proxy-port 31303
	warp-cli --accept-tos connect
	warp-cli --accept-tos enable-always-on

	#	if [[]]; then
	#	fi
	# todo curl --socks5 127.0.0.1:31303 https://www.cloudflare.com/cdn-cgi/trace
	# systemctl daemon-reload
	# systemctl enable cloudflare-warp
}
#Initialize Nginx request certificate configuration
initTLSNginxConfig() {
	handleNginx stop
	EchoContent skyBlue " n Progress $1/${totalProgress}: Initialize Nginx request certificate configuration"
	if [[ -n "${currentHost}" ]]; then
	Echo "Read the last installation record, domain name at last installation: ${currentHost}"
		echo
		Read - r - p "Please check for correctness. Do you want to use the domain name from the last installation? [y/n]:" historyDomainStatus
		if [[ "${historyDomainStatus}" == "y" ]]; then 		domain=${currentHost}
			EchoContent yellow " n -->Domain name: ${domain}"
		else
			echo
			EchoContent yellow "Please enter the domain name to be configured. Example: www.v2ray agent. com --->
			Read - r - p "Domain name:" domain
		fi
	else
		echo
		EchoContent yellow "Please enter the domain name to be configured. Example: www.v2ray agent. com --->
		Read - r - p "Domain name:" domain
	fi

	if [[ -z ${domain} ]]; then
		EchoContent red "Domain name cannot be empty -->"
		initTLSNginxConfig 3
	else
		dnsTLSDomain=$(echo "${domain}" | awk -F "[.]" '{print $(NF-1)"."$NF}')
		customPortFunction
		local port=80
		if [[ -n "${customPort}" ]]; then 		port=${customPort}
		fi

		#Modify Configuration
		touch ${nginxConfigPath}alone.conf
		cat <<EOF >${nginxConfigPath}alone.conf
server {
    listen ${port};
    listen [::]:${port};
    server_name ${domain};
    root /usr/share/nginx/html;
    location ~ /.well-known {
    	allow all;
    }
    location /test {
    	return 200 'fjkvymb6len';
    }
	location /ip {
		proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header REMOTE-HOST \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		default_type text/plain;
		return 200 \$proxy_add_x_forwarded_for;
	}
}
EOF
	fi

	readAcmeTLS
}

#Modify nginx redirection configuration
updateRedirectNginxConf() {

	#	if [[ ${BTPanelStatus} == "true" ]]; then
	#
	#		cat <<EOF >${nginxConfigPath}alone.conf
	#        server {
	#        		listen 127.0.0.1:31300;
	#        		server_name _;
	#        		return 403;
	#        }
	#EOF
	#
	#	elif [[ -n "${customPort}" ]]; then
	#		cat <<EOF >${nginxConfigPath}alone.conf
	#                server {
	#                		listen 127.0.0.1:31300;
	#                		server_name _;
	#                		return 403;
	#                }
	#EOF
	#	fi
	local redirectDomain=${domain}
	if [[ -n "${customPort}" ]]; then 	redirectDomain=${domain}:${customPort}
	fi
	cat <<EOF >${nginxConfigPath}alone.conf
server {
	listen 80;
	server_name ${domain};
	return 302 https://${redirectDomain};
}
server {
		listen 127.0.0.1:31300;
		server_name _;
		return 403;
}
EOF

	if echo "${selectCustomInstallType}" | grep -q 2 && echo "${selectCustomInstallType}" | grep -q 5 || [[ -z "${selectCustomInstallType}" ]]; then

		cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31302 http2 so_keepalive=on;
	server_name ${domain};
	root /usr/share/nginx/html;

	client_header_timeout 1071906480m;
    keepalive_timeout 1071906480m;

	location /s/{
	    add_header Content-Type text/plain;
    	alias /etc/v2ray-agent/subscribe/;
    }

    location /${currentPath}grpc {
    	if (\$content_type !~ "application/grpc") {
    		return 404;
    	}
		 client_max_body_size 0;
		grpc_set_header X-Real-IP \$proxy_add_x_forwarded_for;
		client_body_timeout 1071906480m;
		grpc_read_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301 ;
	}

	location /${currentPath}trojangrpc {
		if (\$content_type !~ "application/grpc") {
            		return 404;
		}
		 client_max_body_size 0;
		grpc_set_header X-Real-IP \$proxy_add_x_forwarded_for;
		client_body_timeout 1071906480m;
		grpc_read_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31304 ;
	}
	location /{
	        add_header Strict-Transport-Security "max-age=15552000; preload" always;
    }
}
EOF
	elif echo "${selectCustomInstallType}" | grep -q 5 || [[ -z "${selectCustomInstallType}" ]]; then 	cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/{
		    add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }
	location /${currentPath}grpc {
		client_max_body_size 0;
#		keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
		 send_timeout 1071906480m;
		 lingering_close always;
		 grpc_read_timeout 1071906480m;
		 grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301 ;
	}
}
EOF

	elif echo "${selectCustomInstallType}" | grep -q 2 || [[ -z "${selectCustomInstallType}" ]]; then

		cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/{
		    add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }
	location /${currentPath}trojangrpc {
		client_max_body_size 0;
		# keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
		 send_timeout 1071906480m;
		 lingering_close always;
		 grpc_read_timeout 1071906480m;
		 grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301 ;
	}
}
EOF
	else

		cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/{
		    add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }
	location /{
	}
}
EOF
	fi

	cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31300;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/{
		add_header Content-Type text/plain;
		alias /etc/v2ray-agent/subscribe/;
	}
	location /{
		add_header Strict-Transport-Security "max-age=15552000; preload" always;
	}
}
EOF

}

#Check IP
checkIP() {
	EchoContent skyBlue " n -->Check domain IP address"
	local checkDomain=${domain}
	if [[ -n "${customPort}" ]]; then 	checkDomain="http://${domain}:${customPort}"
	fi
	localIP=$(curl -s -m 2 "${checkDomain}/ip")

	handleNginx stop
	if [[ -z ${localIP} ]] || ! echo "${localIP}" | sed '1{s/[^(]*(//;s/).*//;q}' | grep -q '\.' && ! echo "${localIP}" | sed '1{s/[^(]*(//;s/).*//;q}' | grep -q ':'; then
		EchoContent red " n -->No IP detected for the current domain name"
		EchoContent skyBlue "-->Please perform the following checks in sequence"
		EchoContent yellow "-->1. Check if the domain name is written correctly"
		EchoContent yellow "-->2. Check if the DNS resolution of the domain name is correct"
		EchoContent yellow "-->3. If the parsing is correct, please wait for the dns to take effect. It is expected to take effect within three minutes"
		EchoContent yellow "-->4. If an Nginx startup issue is reported, please manually start nginx to check for errors. If you are unable to handle it yourself, please submit issues
		EchoContent yellow "-->5. Error log: ${localIP}"
		echo
		EchoContent skyBlue "-->If all the above settings are correct, please reinstall the pure system and try again"

		if [[ -n ${localIP} ]]; then
			EchoContent yellow "-->Detect abnormal return values. It is recommended to manually uninstall nginx and execute the script again
		fi
		local portFirewallPortStatus="443、80"

		if [[ -n "${customPort}" ]]; then
			portFirewallPortStatus="${customPort}"
		fi
		EchoContent red "-->Please check if the firewall rules are open ${portFirewallPortStatus}  n
		Read - r - p "Do you want to modify firewall rules through scripts to open the ${portFirewallPortStatus} port? [y/n]:" allPortFirewallStatus

		if [[ ${allPortFirewallStatus} == "y" ]]; then
			if [[ -n "${customPort}" ]]; then
				allowPort "${customPort}"
			else
				allowPort 80
				allowPort 443
			fi

			handleNginx start
			checkIP
		else
			exit 0
		fi
	else
		if echo "${localIP}" | awk -F "[,]" '{print $2}' | grep -q "." || echo "${localIP}" | awk -F "[,]" '{print $2}' | grep -q ":"; then
			EchoContent red " n -->Multiple IPs detected, please confirm whether to turn off Cloudflare's cloud"
			EchoContent yellow "-->Close the cloud and wait for three minutes before trying again"
			EchoContent yellow "-->The detected IP addresses are as follows: [${localIP}]
			exit 0
		fi
		EchoContent green "-->The current domain IP is: [${localIP}]"
	fi

}
#Custom email
customSSLEmail() {
	if echo "$1" | grep -q "validate email"; then
		Read - r - p "Do you want to re-enter the email address [y/n]:" sslEmailStatus
		if [[ "${sslEmailStatus}" == "y" ]]; then
			sed '/ACCOUNT_EMAIL/d' /root/.acme.sh/account.conf >/root/.acme.sh/account.conf_tmp && mv /root/.acme.sh/account.conf_tmp /root/.acme.sh/account.conf
		else
			exit 0
		fi
	fi

	if [[ -d "/root/.acme.sh" && -f "/root/.acme.sh/account.conf" ]]; then
		if ! grep -q "ACCOUNT_EMAIL" <"/root/.acme.sh/account.conf" && ! echo "${sslType}" | grep -q "letsencrypt"; then
			Read - r - p "Please enter email address:" sslEmail
			if echo "${sslEmail}" | grep -q "@"; then
				echo "ACCOUNT_EMAIL='${sslEmail}'" >>/root/.acme.sh/account.conf
				EchoContent green "-->Successfully added"
			else
				EchoContent yellow "Please re-enter the correct email format [Example: username@example.com ]"
				customSSLEmail
			fi
		fi
	fi

}
#Select SSL installation type
switchSSLType() {
	if [[ -z "${sslType}" ]]; then
		echoContent red "\n============================================================== "
		EchoContent yellow "1. letsencrypt [default]"
		echoContent yellow "2.zerossl"
		EchoContent yellow "3. buypass [does not support DNS requests]
		echoContent red "============================================================== "
		Read - r - p "Please select [Enter] to use default:" selectSSLType
		case ${selectSSLType} in
		1)
			sslType="letsencrypt"
			;;
		2)
			sslType="zerossl"
			;;
		3)
			sslType="buypass"
			;;
		*)
			sslType="letsencrypt"
			;;
		esac
		touch /etc/v2ray-agent/tls
		echo "${sslType}" >/etc/v2ray-agent/tls/ssl_type

	fi
}

#Choose the ACME installation certificate method
selectAcmeInstallSSL() {
	local installSSLIPv6=
	if echo "${localIP}" | grep -q ":"; then
		installSSLIPv6="--listen-v6"
	fi
	echo
	if [[ -n "${customPort}" ]]; then
		if [[ "${selectSSLType}" == "3" ]]; then
			EchoContent red "-->Buypass does not support free wildcard certificates"
			echo
			exit
		fi
		dnsSSLStatus=true
	else
		Read - r - p "Whether to use DNS to request a certificate [y/n]:" installSSLDNStatus
		if [[ ${installSSLDNStatus} =='y' ]]; then 		dnsSSLStatus=true
		fi
	fi
	acmeInstallSSL

	readAcmeTLS
}

#Install SSL certificate
acmeInstallSSL() {
	if [[ "${dnsSSLStatus}" == "true" ]]; then

		sudo "$HOME/.acme.sh/acme.sh" --issue -d "*.${dnsTLSDomain}" -d "${dnsTLSDomain}" --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please -k ec-256 --server "${sslType}" ${installSSLIPv6} 2>&1 | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null

		local txtValue=
		txtValue=$(tail -n 10 /etc/v2ray-agent/tls/acme.log | grep "TXT value" | awk -F "'" '{print $2}')
		if [[ -n "${txtValue}" ]]; then
			EchoContent green "-->Please manually add DNS TXT records"
			EchoContent yellow "-->Please refer to this tutorial for adding methods, https://github.com/reeceyng/v2ray-agent/blob/master/documents/dns_txt.md "
			EchoContent yellow "->Just like installing wildcard certificates on multiple machines in a domain name, please add multiple TXT records without modifying the previously added TXT records
			echoContent green " --->  name：_acme-challenge"
			echoContent green " --->  value：${txtValue}"
			EchoContent yellow "-->Please wait for 1-2 minutes after adding is completed
			echo
			Read - r - p "Add completed [y/n]:" addDNSTXTRecordStatus
			if [[ "${addDNSTXTRecordStatus}" == "y" ]]; then 			local txtAnswer=
				txtAnswer=$(dig +nocmd "_acme-challenge.${dnsTLSDomain}" txt +noall +answer | awk -F "[\"]" '{print $2}')
				if echo "${txtAnswer}" | grep -q "${txtValue}"; then
					EchoContent green "-->TXT record verification passed"
					EchoContent green "-->Generating certificate"
					sudo "$HOME/.acme.sh/acme.sh" --renew -d "*.${dnsTLSDomain}" -d "${dnsTLSDomain}" --yes-I-know-dns-manual-mode-enough-go-ahead-please --ecc --server "${sslType}" ${installSSLIPv6} 2>&1 | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null
				else
					EchoContent red "-->Verification failed, please wait 1-2 minutes and try again"
					acmeInstallSSL
				fi
			else
				EchoContent red "-->Abandon"
				exit 0
			fi
		fi
	else
		EchoContent green "-->Generating certificate"
		sudo "$HOME/.acme.sh/acme.sh" --issue -d "${tlsDomain}" --standalone -k ec-256 --server "${sslType}" ${installSSLIPv6} 2>&1 | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null
	fi
}
#Custom Port
customPortFunction() {
	local historyCustomPortStatus="n"
	local showPort=
	if [[ -n "${customPort}" || -n "${currentPort}" ]]; then
		echo
		Read - r - p "Read the port from the previous installation, do you want to use the port from the previous installation? [y/n]:" historyCustomimPortStatus
		if [[ "${historyCustomPortStatus}" == "y" ]]; then 		showPort="${currentPort}"
			if [[ -n "${customPort}" ]]; then 			showPort="${customPort}"
			fi
			EchoContent yellow " n -->Port: ${showPort}"
		fi
	fi

	if [[ "${historyCustomPortStatus}" == "n" ]]; then
		echo
		EchoContent yellow "Please enter the port [default: 443]. For custom ports, only DNS is allowed to apply for certificates [enter to use default]"
		Read - r - p "Port:" customPort
		if [[ -n "${customPort}" ]]; then
			if ((customPort >=1 && customPort <=65535)); then
				checkCustomPort
				allowPort "${customPort}"
			else
				EchoContent red "-->Port input error"
				exit
			fi
		else
			EchoContent yellow " n -->Port: 443"
		fi
	fi
}

#Detect if the port is occupied
checkCustomPort() {
	if lsof -i "tcp:${customPort}" | grep -q LISTEN; then
		EchoContent red " n -->${customPort} port is occupied, please manually close and install  n
		lsof -i tcp:80 | grep LISTEN
		exit 0
	fi
}

#Install TLS
installTLS() {
	EchoContent skyBlue " n Progress $1/${totalProgress}: Apply for TLS certificate  n
	local tlsDomain=${domain}

	#Install tls
	if [[ -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" && -f "/etc/v2ray-agent/tls/${tlsDomain}.key" && -n $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]] || [[ -d "$HOME/.acme.sh/${tlsDomain}_ecc" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" ]]; then
		EchoContent green "-->Certificate detected"
		# checkTLStatus
		renewalTLS

		if [[ -z $(find /etc/v2ray-agent/tls/-name "${tlsDomain}.crt") ]] || [[ -z $(find /etc/v2ray-agent/tls/-name "${tlsDomain}.key") ]] || [[ -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
			sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${tlsDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
		else
			EchoContent yellow "-->If the certificate has not expired or is customized, please select [n]  n
			Read - r - p "Do you want to reinstall? [y/n]:" reInstallStatus
			if [[ "${reInstallStatus}" == "y" ]]; then
				rm -rf /etc/v2ray-agent/tls/*
				installTLS "$1"
			fi
		fi

	elif [[ -d "$HOME/.acme.sh" ]] && [[ ! -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" || ! -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" ]]; then
		EchoContent green "-->Install TLS certificate"

		if [[ "${installDNSACMEStatus}" != "true" ]]; then
			switchSSLType
			customSSLEmail
			selectAcmeInstallSSL
		else
			EchoContent green "-->Detected that a wildcard certificate has been installed, automatically generating"
		fi
		if [[ "${installDNSACMEStatus}" == "true" ]]; then
			echo
			if [[ -d "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc" && -f "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc/*.${dnsTLSDomain}.key" && -f "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc/*.${dnsTLSDomain}.cer" ]]; then
				sudo "$HOME/.acme.sh/acme.sh" --installcert -d "*.${dnsTLSDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
			fi

		elif [[ -d "$HOME/.acme.sh/${tlsDomain}_ecc" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" ]]; then
			sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${tlsDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
		fi

		if [[ ! -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" || ! -f "/etc/v2ray-agent/tls/${tlsDomain}.key" ]] || [[ -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.key") || -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
			tail -n 10 /etc/v2ray-agent/tls/acme.log
			if [[ ${installTLSCount} == "1" ]]; then
				EchoContent red "-->TLS installation failed, please check acme logs"
				exit 0
			fi

			installTLSCount=1
			echo
			EchoContent red "-->TLS installation failed, checking if ports 80 and 443 are open"
			allowPort 80
			allowPort 443
			EchoContent yellow "-->Try installing TLS certificate again"

			if tail -n 10 /etc/v2ray-agent/tls/acme.log | grep -q "Could not validate email address as valid"; then
				EchoContent red "-->The email cannot pass SSL vendor verification, please re-enter"
				echo
				customSSLEmail "validate email"
				installTLS "$1"
			else
				installTLS "$1"
			fi

		fi

		EchoContent green "-->TLS generated successfully"
	else
		EchoContent yellow "-->acme. sh not installed"
		exit 0
	fi
}
#Configure disguised blogs
initNginxConfig() {
	EchoContent skyBlue " n Progress $1/${totalProgress}: Configure Nginx"

	cat <<EOF >${nginxConfigPath}alone.conf
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};
    root /usr/share/nginx/html;
    location ~ /.well-known {allow all;}
    location /test {return 200 'fjkvymb6len';}
}
EOF
}

#Custom/Random Path
randomPathFunction() {
	EchoContent skyBlue " n Progress $1/${totalProgress}: Generate Random Path"

	if [[ -n "${currentPath}" ]]; then
		echo
		Read - r - p "Read the last installation record. Do you want to use the path from the last installation? [y/n]:" historyPathStatus
		echo
	fi

	if [[ "${historyPathStatus}" == "y" ]]; then 	customPath=${currentPath}
		EchoContent green "-->Successfully used  n
	else
		EchoContent yellow "Please enter a custom path [example: alone], no slashes required, [carriage return] random path"
		Read - r - p 'path:' customPath

		if [[ -z "${customPath}" ]]; then 		customPath=$(head -n 50 /dev/urandom | sed 's/[^a-z]//g' | strings -n 4 | tr '[:upper:]' '[:lower:]' | head -1)
			currentPath=${customPath:0:4}
			customPath=${currentPath}
		else
			currentPath=${customPath}
		fi

	fi
	echoContent yellow "\n path:${currentPath}"
	echoContent skyBlue "\n----------------------------"
}
#Nginx disguised as a blog
nginxBlog() {
	EchoContent skyBlue " n Progress $1/${totalProgress}: Add a disguised site"
	if [[ -d "/usr/share/nginx/html" && -f "/usr/share/nginx/html/check" ]]; then
		echo
		Read - r - p "Detected installation of masquerade site, do you need to reinstall [y/n]:" nginxBlogInstallStatus
		if [[ "${nginxBlogInstallStatus}" == "y" ]]; then
			rm -rf /usr/share/nginx/html
			randomNum=$((RANDOM % 9 + 1))
			wget -q -P /usr/share/nginx https://raw.githubusercontent.com/reeceyng/v2ray-agent/master/fodder/blog/unable/html ${randomNum}.zip >/dev/null
			unzip -o /usr/share/nginx/html${randomNum}.zip -d /usr/share/nginx/html >/dev/null
			rm -f /usr/share/nginx/html${randomNum}.zip*
			EchoContent green "-->Successfully added disguised site"
		fi
	else
		randomNum=$((RANDOM % 9 + 1))
		rm -rf /usr/share/nginx/html
		wget -q -P /usr/share/nginx https://raw.githubusercontent.com/reeceyng/v2ray-agent/master/fodder/blog/unable/html ${randomNum}.zip >/dev/null
		unzip -o /usr/share/nginx/html${randomNum}.zip -d /usr/share/nginx/html >/dev/null
		rm -f /usr/share/nginx/html${randomNum}.zip*
		EchoContent green "-->Successfully added disguised site"
	fi

}

#Modify HTTP_port_Port t
updateSELinuxHTTPPortT() {

	$(find /usr/bin /usr/sbin | grep -w journalctl) -xe >/etc/v2ray-agent/nginx_error.log 2>&1

	if find /usr/bin /usr/sbin | grep -q -w semanage && find /usr/bin /usr/sbin | grep -q -w getenforce && grep -E "31300|31302" </etc/v2ray-agent/nginx_error.log | grep -q "Permission denied"; then
		EchoContent red "-->Check if the SELinux port is open"
		if ! $ (find /usr/bin /usr/sbin | grep -w semanage) port -l | grep http_port | grep -q 31300; then
			$(find /usr/bin /usr/sbin | grep -w semanage) port -a -t http_port_t -p tcp 31300
			EchoContent green "-->http_port_t Port 31300 successfully opened"
		fi

		if ! $ (find /usr/bin /usr/sbin | grep -w semanage) port -l | grep http_port | grep -q 31302; then
			$(find /usr/bin /usr/sbin | grep -w semanage) port -a -t http_port_t -p tcp 31302
			EchoContent green "-->http_port_t Port 31302 successfully opened"
		fi
		handleNginx start

	else
		exit 0
	fi
}

#Operation Nginx
handleNginx() {

	if [[ -z $(pgrep -f "nginx") ]] && [[ "$1" == "start" ]]; then
		systemctl start nginx 2>/etc/v2ray-agent/nginx_error.log

		sleep 0.5

		if [[ -z $(pgrep -f nginx) ]]; then
			EchoContent red "-->Nginx startup failed"
			EchoContent red "-->Please manually try installing nginx and execute the script again"

			if grep -q "journalctl -xe" </etc/v2ray-agent/nginx_error.log; then
				updateSELinuxHTTPPortT
			fi

			# exit 0
		else
			EchoContent green "-->Nginx started successfully"
		fi

	elif [[ -n $(pgrep -f "nginx") ]] && [[ "$1" == "stop" ]]; then
		systemctl stop nginx
		sleep 0.5
		if [[ -n $(pgrep -f "nginx") ]]; then
			pgrep -f "nginx" | xargs kill -9
		fi
		EchoContent green "-->Nginx closed successfully"
	fi
}

#Timed task updating tls certificate
installCronTLS() {
	EchoContent skyBlue " n Progress $1/${totalProgress}: Add scheduled maintenance certificate"
	crontab -l >/etc/v2ray-agent/backup_crontab.cron
	local historyCrontab
	historyCrontab=$(sed '/v2ray-agent/d;/acme.sh/d' /etc/v2ray-agent/backup_crontab.cron)
	echo "${historyCrontab}" >/etc/v2ray-agent/backup_crontab.cron
	echo "30 1 * * * /bin/bash /etc/v2ray-agent/install.sh RenewTLS >> /etc/v2ray-agent/crontab_tls.log 2>&1" >>/etc/v2ray-agent/backup_crontab.cron
	crontab /etc/v2ray-agent/backup_crontab.cron
	EchoContent green " n -->Successfully added scheduled maintenance certificate"
}

#Update certificate
renewalTLS() {

	if [[ -n $1 ]]; then
		EchoContent skyBlue " n Progress $1/1: Update Certificate"
	fi
	readAcmeTLS
	local domain=${currentHost}
	if [[ -z "${currentHost}" && -n "${tlsDomain}" ]]; then 	domain=${tlsDomain}
	fi

	if [[ -f "/etc/v2ray-agent/tls/ssl_type" ]]; then
		if grep -q "buypass" <"/etc/v2ray-agent/tls/ssl_type"; then 		sslRenewalDays=180
		fi
	fi
	if [[ -d "$HOME/.acme.sh/${domain}_ecc" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]] || [[ "${installDNSACMEStatus}" == "true" ]]; then
		modifyTime=

		if [[ "${installDNSACMEStatus}" == "true" ]]; then
			modifyTime=$(stat "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc/*.${dnsTLSDomain}.cer" | sed -n '7,6p' | awk '{print $2" "$3" "$4" "$5}')
		else
			modifyTime=$(stat "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" | sed -n '7,6p' | awk '{print $2" "$3" "$4" "$5}')
		fi

		modifyTime=$(date +%s -d "${modifyTime}")
		currentTime=$(date +%s)
		((stampDiff =currentTime - modifyTime))
		((days =stampDiff /86400))
		((remainingDays =sslRenewalDays - days))

		tlsStatus=${remainingDays}
		if [[ ${remainingDays} -le 0 ]]; then
			TlsStatus="Expired"
		fi

		EchoContent skyBlue "-->Certificate Check Date: $(date"+% F% H:% M:% S ")
		EchoContent skyBlue "-->Certificate generation date: $(date - d @" ${modifyTime} "+"% F% H:% M:% S ")
		EchoContent skyBlue "-->Number of days for certificate generation: ${days}"
		EchoContent skyBlue "-->Certificate days remaining:" ${tlsStatus}
		EchoContent skyBlue "-->The certificate will be automatically updated the last day before expiration. If the update fails, please manually update"

		if [[ ${remainingDays} -le 1 ]]; then
			EchoContent yellow "-->Regenerate certificate"
			handleNginx stop
			sudo "$HOME/.acme.sh/acme.sh" --cron --home "$HOME/.acme.sh"
			sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${domain}" --fullchainpath /etc/v2ray-agent/tls/"${domain}.crt" --keypath /etc/v2ray-agent/tls/"${domain}.key" --ecc
			reloadCore
			handleNginx start
		else
			EchoContent green "-->Certificate is valid"
		fi
	else
		EchoContent red "-->Not installed"
	fi
}
#Viewing the Status of TLS Certificates
checkTLStatus() {

	if [[ -d "$HOME/.acme.sh/${currentHost}_ecc" ]] && [[ -f "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.key" ]] && [[ -f "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.cer" ]]; then
		modifyTime=$(stat "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.cer" | sed -n '7,6p' | awk '{print $2" "$3" "$4" "$5}')

		modifyTime=$(date +%s -d "${modifyTime}")
		currentTime=$(date +%s)
		((stampDiff =currentTime - modifyTime))
		((days =stampDiff /86400))
		((remainingDays =sslRenewalDays - days))

		tlsStatus=${remainingDays}
		if [[ ${remainingDays} -le 0 ]]; then
			TlsStatus="Expired"
		fi

		EchoContent skyBlue "-->Certificate generation date: $(date - d" @ ${modifyTime} "+"% F% H:% M:% S ")
		EchoContent skyBlue "-->Number of days for certificate generation: ${days}"
		EchoContent skyBlue "-->Certificate days remaining: ${tlsStatus}"
	fi
}

#Install V2Ray, specify version
installV2Ray() {
	readInstallType
	EchoContent skyBlue " n Progress $1/${totalProgress}: Install V2Ray"

	if [[ "${coreInstallType}" != "2" && "${coreInstallType}" != "3" ]]; then
		if [[ "${selectCoreType}" == "2" ]]; then

			version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases  | jq -r '. []|select (.prerelease==false)|.tag_name' | grep -v 'v5' | head -1)
		else
			version=${v2rayCoreVersion}
		fi

		EchoContent green "-->v2ray core version: ${version}"
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/v2ray/" https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/v2ray/" https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip" >/dev/null 2>&1
		fi

		unzip -o "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip" -d /etc/v2ray-agent/v2ray >/dev/null
		rm -rf "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip"
	else
		if [[ "${selectCoreType}" == "3" ]]; then
			EchoContent green "-->Lock v2ray core version to v4.32.1"
			rm -f /etc/v2ray-agent/v2ray/v2ray
			rm -f /etc/v2ray-agent/v2ray/v2ctl
			installV2Ray "$1"
		else
			EchoContent green "-->v2ray core version: $(/etc/v2ray agent/v2ray/v2ray -- version | awk '{print $2}' | head -1)
			Read - r - p "Do you want to update or upgrade? [y/n]:" reInstallV2RayStatus
			if [[ "${reInstallV2RayStatus}" == "y" ]]; then
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				installV2Ray "$1"
			fi
		fi
	fi
}

#Installing Hysteria
installHysteria() {
	readInstallType
	EchoContent skyBlue " n Progress $1/${totalProgress}: Installing Hysteria"

	if [[ -z "${hysteriaConfigPath}" ]]; then

		version=$(curl -s https://api.github.com/repos/apernet/hysteria/releases  | jq -r '. []|select (.prerelease==false)|.tag_name' | head -1)

		EchoContent green "-->Hysteria version: ${version}"
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/hysteria/" https://github.com/apernet/hysteria/releases/download/${version}/${hysteriaCoreCPUVendor}"
		else
			wget -c -P /etc/v2ray-agent/hysteria/" https://github.com/apernet/hysteria/releases/download/${version}/${hysteriaCoreCPUVendor}" >/dev/null 2>&1
		fi
		mv "/etc/v2ray-agent/hysteria/${hysteriaCoreCPUVendor}" /etc/v2ray-agent/hysteria/hysteria
		chmod 655 /etc/v2ray-agent/hysteria/hysteria
	else
		EchoContent green "-->Hysteria version: $(/etc/v2ray agent/Hysteria/hydrogen -- version | awk '{print $3}')
		Read - r - p "Do you want to update or upgrade? [y/n]:" reInstallHysteriaStatus
		if [[ "${reInstallHysteriaStatus}" == "y" ]]; then
			rm -f /etc/v2ray-agent/hysteria/hysteria
			installHysteria "$1"
		fi
	fi

}
#Installing xray
installXray() {
	readInstallType
	EchoContent skyBlue " n Progress $1/${totalProgress}: Installing Xray"

	if [[ "${coreInstallType}" != "1" ]]; then

		version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases  | jq -r ".[]|select (.prerelease==${prereleaseStatus})|.tag_name" | head -1)

		EchoContent green "-->Xray core version: ${version}"
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/xray/" https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/xray/" https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip" >/dev/null 2>&1
		fi

		unzip -o "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip" -d /etc/v2ray-agent/xray >/dev/null
		rm -rf "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip"
		chmod 655 /etc/v2ray-agent/xray/xray
	else
		EchoContent green "-->Xray core version: $(/etc/v2ray agent/xray/xray -- version | awk '{print $2}' | head -1)
		Read - r - p "Do you want to update or upgrade? [y/n]:" reInstallXrayStatus
		if [[ "${reInstallXrayStatus}" == "y" ]]; then
			rm -f /etc/v2ray-agent/xray/xray
			installXray "$1"
		fi
	fi
}

#V2ray version management
v2rayVersionManageMenu() {
	EchoContent skyBlue " n Progress $1/${totalProgress}: V2Ray Version Management"
	if [[ ! -d "/etc/v2ray-agent/v2ray/" ]]; then
		EchoContent red "-->No installation directory detected, please execute the script to install the content"
		menu
		exit 0
	fi
	echoContent red "\n============================================================== "
	EchoContent yellow "1. Upgrade v2ray core"
	EchoContent yellow "2. Fallback v2ray core"
	EchoContent yellow "3. Close v2ray core"
	EchoContent yellow "4. Open v2ray core"
	EchoContent yellow "5. Restart v2ray core"
	echoContent red "============================================================== "
	Read - r - p "Please select:" selectV2RayType
	if [[ "${selectV2RayType}" == "1" ]]; then
		updateV2Ray
	elif [[ "${selectV2RayType}" == "2" ]]; then
		EchoContent yellow " n1. Only the last five versions can be rolled back"
		EchoContent yellow "2. There is no guarantee that it can be used normally after rollback"
		EchoContent yellow "3. If the fallback version does not support the current config, it will not be able to connect. Be cautious
		echoContent skyBlue "------------------------Version-------------------------------"
		curl -s https://api.github.com/repos/v2fly/v2ray-core/releases  | jq -r '. []|select (.prerelease==false)|.tag_name' | grep -v 'v5' | head -5 | awk '{print ""NR""":"$0}'

		echoContent skyBlue "--------------------------------------------------------------"
		Read - r - p "Please enter the version you want to rollback:" selectV2rayVersionType
		version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases  | jq -r '. []|select (.prerelease==false)|.tag_name' | grep -v 'v5' | head -5 | awk '{print ""NR""":"$0}' | grep "${selectV2rayVersionType}:" | awk -F "[:]" '{print $2}')
		if [[ -n "${version}" ]]; then
			updateV2Ray "${version}"
		else
			EchoContent red " n -->Input error, please re-enter"
			v2rayVersionManageMenu 1
		fi
	elif [[ "${selectV2RayType}" == "3" ]]; then
		handleV2Ray stop
	elif [[ "${selectV2RayType}" == "4" ]]; then
		handleV2Ray start
	elif [[ "${selectV2RayType}" == "5" ]]; then
		reloadCore
	fi
}

#Xray version management
xrayVersionManageMenu() {
	EchoContent skyBlue " n Progress $1/${totalProgress}: Xray version management"
	if [[ ! -d "/etc/v2ray-agent/xray/" ]]; then
		EchoContent red "-->No installation directory detected, please execute the script to install the content"
		menu
		exit 0
	fi
	echoContent red "\n============================================================== "
	EchoContent yellow "1. Upgrade Xray core"
	EchoContent yellow "2. Upgrade Xray core preview version"
	EchoContent yellow "3. Fallback Xray core"
	EchoContent yellow "4. Close Xray core"
	EchoContent yellow "5. Open Xray core"
	EchoContent yellow "6. Restart Xray core"
	echoContent red "============================================================== "
	Read - r - p "Please select:" selectXrayType
	if [[ "${selectXrayType}" == "1" ]]; then
		updateXray
	elif [[ "${selectXrayType}" == "2" ]]; then

		prereleaseStatus=true
		updateXray

	elif [[ "${selectXrayType}" == "3" ]]; then
		EchoContent yellow " n1. Only the last five versions can be rolled back"
		EchoContent yellow "2. There is no guarantee that it can be used normally after rollback"
		EchoContent yellow "3. If the fallback version does not support the current config, it will not be able to connect. Be cautious
		echoContent skyBlue "------------------------Version-------------------------------"
		curl -s https://api.github.com/repos/XTLS/Xray-core/releases  | jq -r '. []|select (.prerelease==false)|.tag_name' | head -5 | awk '{print ""NR""":"$0}'
		echoContent skyBlue "--------------------------------------------------------------"
		Read - r - p "Please enter the version you want to rollback:" selectXrayVersionType
		version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases  | jq -r '. []|select (.prerelease==false)|.tag_name' | head -5 | awk '{print ""NR""":"$0}' | grep "${selectXrayVersionType}:" | awk -F "[:]" '{print $2}')
		if [[ -n "${version}" ]]; then
			updateXray "${version}"
		else
			EchoContent red " n -->Input error, please re-enter"
			xrayVersionManageMenu 1
		fi
	elif [[ "${selectXrayType}" == "4" ]]; then
		handleXray stop
	elif [[ "${selectXrayType}" == "5" ]]; then
		handleXray start
	elif [[ "${selectXrayType}" == "6" ]]; then
		reloadCore
	fi

}
#Update V2Ray
updateV2Ray() {
	readInstallType
	if [[ -z "${coreInstallType}" ]]; then

		if [[ -n "$1" ]]; then 		version=$1
		else
			version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases  | jq -r '. []|select (.prerelease==false)|.tag_name' | grep -v 'v5' | head -1)
		fi
		#Use locked version
		if [[ -n "${v2rayCoreVersion}" ]]; then 		version=${v2rayCoreVersion}
		fi
		EchoContent green "-->v2ray core version: ${version}"

		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/v2ray/" https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip"
		else
			wget -c -P "/etc/v2ray-agent/v2ray/https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip" >/dev/null 2>&1
		fi

		unzip -o "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip" -d /etc/v2ray-agent/v2ray >/dev/null
		rm -rf "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip"
		handleV2Ray stop
		handleV2Ray start
	else
		EchoContent green "-->Current v2ray core version: $(/etc/v2ray agent/v2ray/v2ray -- version | awk '{print $2}' | head -1)

		if [[ -n "$1" ]]; then 		version=$1
		else
			version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases  | jq -r '. []|select (.prerelease==false)|.tag_name' | grep -v 'v5' | head -1)
		fi

		if [[ -n "${v2rayCoreVersion}" ]]; then 		version=${v2rayCoreVersion}
		fi
		if [[ -n "$1" ]]; then
			Read - r - p "Fallback version is ${version}, do you want to continue? [y/n]:" rollbackV2RayStatus
			if [[ "${rollbackV2RayStatus}" == "y" ]]; then
				if [[ "${coreInstallType}" == "2" ]]; then
					EchoContent green "-->Current v2ray core version: $(/etc/v2ray agent/v2ray/v2ray -- version | awk '{print $2}' | head -1)
				elif [[ "${coreInstallType}" == "1" || "${coreInstallType}" == "3" ]]; then
					EchoContent green "-->Current Xray core version: $(/etc/v2ray agent/xray/xray -- version | awk '{print $2}' | head -1)
				fi

				handleV2Ray stop
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				updateV2Ray "${version}"
			else
				EchoContent green "-->Abandon fallback version"
			fi
		elif [[ "${version}" == "v$(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)" ]]; then
			Read - r - p "The current version is the same as the latest version. Do you want to reinstall it? [y/n]:" reInstallV2RayStatus
			if [[ "${reInstallV2RayStatus}" == "y" ]]; then
				handleV2Ray stop
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				updateV2Ray
			else
				EchoContent green "-->Abort reinstallation"
			fi
		else
			The latest version is: ${version}. Do you want to update it? [y/n]: "installV2RayStatus
			if [[ "${installV2RayStatus}" == "y" ]]; then
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				updateV2Ray
			else
				EchoContent green "-->Discard update"
			fi

		fi
	fi
}

#Update Xray
updateXray() {
	readInstallType
	if [[ -z "${coreInstallType}" ]]; then
		if [[ -n "$1" ]]; then 		version=$1
		else
			version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases  | jq -r ".[]|select (.prerelease==${prereleaseStatus})|.tag_name" | head -1)
		fi

		EchoContent green "-->Xray core version: ${version}"

		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/xray/" https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/xray/" https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip" >/dev/null 2>&1
		fi

		unzip -o "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip" -d /etc/v2ray-agent/xray >/dev/null
		rm -rf "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip"
		chmod 655 /etc/v2ray-agent/xray/xray
		handleXray stop
		handleXray start
	else
		EchoContent green "-->Current Xray core version: $(/etc/v2ray agent/xray/xray -- version | awk '{print $2}' | head -1)

		if [[ -n "$1" ]]; then 		version=$1
		else
			version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases  | jq -r ".[]|select (.prerelease==${prereleaseStatus})|.tag_name" | head -1)
		fi

		if [[ -n "$1" ]]; then
			Read - r - p "Fallback version is ${version}, do you want to continue? [y/n]:" rollbackXrayStatus
			if [[ "${rollbackXrayStatus}" == "y" ]]; then
				EchoContent green "-->Current Xray core version: $(/etc/v2ray agent/xray/xray -- version | awk '{print $2}' | head -1)

				handleXray stop
				rm -f /etc/v2ray-agent/xray/xray
				updateXray "${version}"
			else
				EchoContent green "-->Abandon fallback version"
			fi
		elif [[ "${version}" == "v$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)" ]]; then
			Read - r - p "The current version is the same as the latest version. Do you want to reinstall it? [y/n]:" reInstallXrayStatus
			if [[ "${reInstallXrayStatus}" == "y" ]]; then
				handleXray stop
				rm -f /etc/v2ray-agent/xray/xray
				rm -f /etc/v2ray-agent/xray/xray
				updateXray
			else
				EchoContent green "-->Abort reinstallation"
			fi
		else
			The latest version is: ${version}. Do you want to update it? [y/n]: "installXrayStatus
			if [[ "${installXrayStatus}" == "y" ]]; then
				rm -f /etc/v2ray-agent/xray/xray
				updateXray
			else
				EchoContent green "-->Discard update"
			fi

		fi
	fi
}

#Verify if the entire service is available
checkGFWStatue() {
	readInstallType
	EchoContent skyBlue " n Progress $1/${totalProgress}: Verify service startup status"
	if [[ "${coreInstallType}" == "1" || "${coreInstallType}" == "3" ]] && [[ -n $(pgrep -f xray/xray) ]]; then
		EchoContent green "-->Service started successfully"
	elif [[ "${coreInstallType}" == "2" ]] && [[ -n $(pgrep -f v2ray/v2ray) ]]; then
		EchoContent green "-->Service started successfully"
	else
		EchoContent red "-->Service startup failed, please check if the terminal has log printing"
		exit 0
	fi

}

#V2Ray starts automatically upon startup
installV2RayService() {
	EchoContent skyBlue " n Progress $1/${totalProgress}: Configure V2Ray to boot automatically"
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
		rm -rf /etc/systemd/system/v2ray.service
		touch /etc/systemd/system/v2ray.service
		execStart='/etc/v2ray-agent/v2ray/v2ray -confdir /etc/v2ray-agent/v2ray/conf'
		cat <<EOF >/etc/systemd/system/v2ray.service
[Unit]
Description=V2Ray - A unified platform for anti-censorship
Documentation=https://v2ray.com  https://guide.v2fly.org
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=${execStart}
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable v2ray.service
		EchoContent green "-->Configure V2Ray to boot successfully"
	fi
}

#Installing Hysteria Boot Self Start
installHysteriaService() {
	EchoContent skyBlue " n Progress $1/${totalProgress}: Configure Hysteria to boot automatically"
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
		rm -rf /etc/systemd/system/hysteria.service
		touch /etc/systemd/system/hysteria.service
		execStart='/etc/v2ray-agent/hysteria/hysteria --log-level info -c /etc/v2ray-agent/hysteria/conf/config.json server'
		cat <<EOF >/etc/systemd/system/hysteria.service
    [Unit]
    Description=Hysteria Service
    Documentation=https://github.com/apernet/hysteria/wiki
    After=network.target nss-lookup.target
    Wants=network-online.target

    [Service]
    Type=simple
    User=root
    CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
    NoNewPrivileges=yes
    ExecStart=${execStart}
    Restart=on-failure
    RestartPreventExitStatus=23
    LimitNPROC=10000
    LimitNOFILE=1000000

    [Install]
    WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable hysteria.service
		EchoContent green "-->Configure Hysteria to start automatically and successfully"
	fi
}
#X-ray starts automatically upon startup
installXrayService() {
	EchoContent skyBlue " n Progress $1/${totalProgress}: Configure Xray to boot automatically"
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
		rm -rf /etc/systemd/system/xray.service
		touch /etc/systemd/system/xray.service
		execStart='/etc/v2ray-agent/xray/xray run -confdir /etc/v2ray-agent/xray/conf'
		cat <<EOF >/etc/systemd/system/xray.service
[Unit]
Description=Xray Service
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=${execStart}
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable xray.service
		EchoContent green "-->Configuration of Xray startup successful"
	fi
}

#Operate V2Ray
handleV2Ray() {
	# shellcheck disable=SC2010
	if find /bin /usr/bin | grep -q systemctl && ls /etc/systemd/system/| grep -q v2ray.service; then
		if [[ -z $(pgrep -f "v2ray/v2ray") ]] && [[ "$1" == "start" ]]; then
			systemctl start v2ray.service
		elif [[ -n $(pgrep -f "v2ray/v2ray") ]] && [[ "$1" == "stop" ]]; then
			systemctl stop v2ray.service
		fi
	fi
	sleep 0.8

	if [[ "$1" == "start" ]]; then
		if [[ -n $(pgrep -f "v2ray/v2ray") ]]; then
			EchoContent green "-->V2Ray started successfully"
		else
			EchoContent red "V2Ray startup failed"
			EchoContent red "Please manually execute [/etc/v2ray agent/v2ray/v2ray confdir/etc/v2ray agent/v2ray/conf] to view the error log"
			exit 0
		fi
	elif [[ "$1" == "stop" ]]; then
		if [[ -z $(pgrep -f "v2ray/v2ray") ]]; then
			EchoContent green "-->V2Ray closed successfully"
		else
			EchoContent red "V2Ray shutdown failed"
			EchoContent red "Please manually execute [ps - ef | grep - v grep | grep v2ray | awk '{print  $2}' | xargs kill -9]"
			exit 0
		fi
	fi
}

#Operate Hysteria
handleHysteria() {
	# shellcheck disable=SC2010
	if find /bin /usr/bin | grep -q systemctl && ls /etc/systemd/system/| grep -q hysteria.service; then
		if [[ -z $(pgrep -f "hysteria/hysteria") ]] && [[ "$1" == "start" ]]; then 		systemctl start hysteria.service
		elif [[ -n $(pgrep -f "hysteria/hysteria") ]] && [[ "$1" == "stop" ]]; then 		systemctl stop hysteria.service
		fi
	fi
	sleep 0.8

	if [[ "$1" == "start" ]]; then
		if [[ -n $(pgrep -f "hysteria/hysteria") ]]; Then	 		echoContent green "-->Hysteria started successfully"
		else
			EchoContent red "Hysteria startup failed"
			EchoContent red "Please manually execute [/etc/v2ray agent/system/hybrid -- log level debug - c/etc/v2ray agent/system/conf/config.json server] to view the error log
			exit 0
		fi
	elif [[ "$1" == "stop" ]]; then
		if [[ -z $(pgrep -f "hysteria/hysteria") ]]; Then	 		echoContent green "-->Hysteria closed successfully"
		else
			EchoContent red "Hysteria shutdown failed"
			EchoContent red "Please manually execute [ps - ef | grep - v grep | grep hybrid | awk '{print  $2}' | xargs kill -9]"
			exit 0
		fi
	fi
}
#Operation xray
handleXray() {
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]] && [[ -n $(find /etc/systemd/system/-name "xray.service") ]]; then
		if [[ -z $(pgrep -f "xray/xray") ]] && [[ "$1" == "start" ]]; then
			systemctl start xray.service
		elif [[ -n $(pgrep -f "xray/xray") ]] && [[ "$1" == "stop" ]]; then
			systemctl stop xray.service
		fi
	fi

	sleep 0.8

	if [[ "$1" == "start" ]]; then
		if [[ -n $(pgrep -f "xray/xray") ]]; then
			EchoContent green "-->Xray started successfully"
		else
			EchoContent red "Xray startup failed"
			EchoContent red "Please manually execute [/etc/v2ray agent/xray/xray confdir/etc/v2ray agent/xray/conf] to view the error log"
			exit 0
		fi
	elif [[ "$1" == "stop" ]]; then
		if [[ -z $(pgrep -f "xray/xray") ]]; then
			EchoContent green "-->X-ray closed successfully"
		else
			EchoContent red "xray closing failed"
			EchoContent red "Please manually execute [ps - ef | grep - v grep | grep xray | awk '{print  $2}' | xargs kill -9]"
			exit 0
		fi
	fi
}
#Obtain clients configuration
getClients() {
	local path=$1

	local addClientsStatus=$2
	previousClients=
	if [[ ${addClientsStatus} == "true" ]]; then
		if [[ ! -f "${path}" ]]; then
			echo
			local protocol
			protocol=$(echo "${path}" | awk -F "[_]" '{print $2 $3}')
			EchoContent yellow "did not read the configuration file of the previous installation of this protocol [${protocol}], using the first uuid of the configuration file"
		else
			previousClients=$(jq -r ".inbounds[0].settings.clients" "${path}")
		fi

	fi
}

#Add client configuration
addClients() {
	local path=$1
	local addClientsStatus=$2
	if [[ ${addClientsStatus} == "true" && -n "${previousClients}" ]]; then 	config=$(jq -r ".inbounds[0].settings.clients =${previousClients}" "${path}")
		echo "${config}" | jq . > "${path}"
	fi
}
#Add hybrid configuration
addClientsHysteria() {
	local path=$1
	local addClientsStatus=$2

	if [[ ${addClientsStatus} == "true" && -n "${previousClients}" ]]; then 	local uuids=	uuids=$(echo "${previousClients}" | jq -r [.[].id])

		if [[ "${frontingType}" == "02_trojan_TCP_inbounds" ]]; then 		uuids=$(echo "${previousClients}" | jq -r [.[].password])
		fi
		config=$(jq -r ".auth.config =${uuids}" "${path}")
		echo "${config}" | jq . > "${path}"
	fi
}

#Initialize Hysteria Port
initHysteriaPort() {
	readHysteriaConfig
	if [[ -n "${hysteriaPort}" ]]; then
		Read - r - p "Read the port from the previous installation, do you want to use the port from the previous installation? [y/n]:" historyHystereriaPortStatus
		if [[ "${historyHysteriaPortStatus}" == "y" ]]; then
			EchoContent yellow " n -->Port: ${hysteriaPort}"
		else
			hysteriaPort=
		fi
	fi

	if [[ -z "${hysteriaPort}" ]]; then
		EchoContent yellow "Please enter the Hysteria port [example: 10000], which cannot be duplicated with other services"
		Read - r - p "Port:" hysteriaPort
	fi
	if [[ -z ${hysteriaPort} ]]; then
		EchoContent red "-->Port cannot be empty"
		initHysteriaPort "$2"
	elif ((hysteriaPort < 1 || hysteriaPort > 65535)); then
		EchoContent red "-->Port illegal"
		initHysteriaPort "$2"
	fi
	allowPort "${hysteriaPort}"
}

#Initialize the protocol for Hysteria
initHysteriaProtocol() {
	EchoContent skyBlue " n Please select a protocol type"
	echoContent red "============================================================== "
	EchoContent yellow "1. udp (QUIC) (default)"
	echoContent yellow "2.faketcp"
	echoContent yellow "3.wechat-video"
	echoContent red "============================================================== "
	Read - r - p "Please select:" selectHysteriaProtocol
	case ${selectHysteriaProtocol} in
	1)
		hysteriaProtocol="udp"
		;;
	2)
		hysteriaProtocol="faketcp"
		;;
	3)
		hysteriaProtocol="wechat-video"
		;;
	*)
		hysteriaProtocol="udp"
		;;
	esac
	EchoContent yellow " n -->Protocol: ${hysteriaProtocol}  n
}

#Initialize Hysteria network information
initHysteriaNetwork() {

	EchoContent yellow "Please enter the average latency from local to server, and fill it in according to the actual situation (default: 180, unit: ms)"
	Read - r - p "Delay:" hysteriaLag
	if [[ -z "${hysteriaLag}" ]]; then 	hysteriaLag=180
		EchoContent yellow " n -->Delay: ${hysteriaLag}  n
	fi

	EchoContent yellow "Please enter the downstream speed of the local bandwidth peak (default: 100, unit: Mbps)
	Read - r - p "Downstream speed:" hysteriaClientDownloadSpeed
	if [[ -z "${hysteriaClientDownloadSpeed}" ]]; then 	hysteriaClientDownloadSpeed=100
		EchoContent yellow " n -->Downlink speed: ${hysteriaClientDownloadSpeed}  n
	fi

	EchoContent yellow "Please enter the uplink speed of the local bandwidth peak (default: 50, unit: Mbps)
	Read - r - p "UploadSpeed:" hysteriaClientUploadSpeed
	if [[ -z "${hysteriaClientUploadSpeed}" ]]; then 	hysteriaClientUploadSpeed=50
		EchoContent yellow " n -->UploadSpeed: ${hysteriaClientUploadSpeed}  n
	fi

	cat <<EOF >/etc/v2ray-agent/hysteria/conf/client_network.json
{
	"hysteriaLag":"${hysteriaLag}",
	"hysteriaClientUploadSpeed":"${hysteriaClientUploadSpeed}",
	"hysteriaClientDownloadSpeed":"${hysteriaClientDownloadSpeed}"
}
EOF

}
#Initialize Hysteria configuration
initHysteriaConfig() {
	EchoContent skyBlue " n Progress $1/${totalProgress}: Initialize Hysteria configuration"

	initHysteriaPort
	initHysteriaProtocol
	initHysteriaNetwork

	getClients "${configPath}${frontingType}.json" true
	cat <<EOF >/etc/v2ray-agent/hysteria/conf/config.json
{
	"listen": ":${hysteriaPort}",
	"protocol": "${hysteriaProtocol}",
	"disable_udp": false,
	"cert": "/etc/v2ray-agent/tls/${currentHost}.crt",
	"key": "/etc/v2ray-agent/tls/${currentHost}.key",
	"auth": {
		"mode": "passwords",
		"config": []
	},
	"alpn": "h3",
	"recv_window_conn": 15728640,
	"recv_window_client": 67108864,
	"max_conn_client": 4096,
	"disable_mtu_discovery": true,
	"resolve_preference": "46",
	"resolver": " https://8.8.8.8:443/dns -query"
}
EOF

	addClientsHysteria "/etc/v2ray-agent/hysteria/conf/config.json" true
}

#Initialize V2Ray configuration file
initV2RayConfig() {
	EchoContent skyBlue " n Progress $2/${totalProgress}: Initialize V2Ray configuration"
	echo

	Read - r - p "Do you want to customize UUID? [y/n]:" customUUIDStatus
	echo
	if [[ "${customUUIDStatus}" == "y" ]]; then
		Read - r - p "Please enter a valid UUID:" currentCustomimUUID
		if [[ -n "${currentCustomUUID}" ]]; then 		uuid=${currentCustomUUID}
		fi
	fi
	local addClientsStatus=
	if [[ -n "${currentUUID}" && -z "${uuid}" ]]; then
		Read - r - p "Read the last installation record, do you want to use the UUID from the last installation? [y/n]:" historyUUIDStatus
		if [[ "${historyUUIDStatus}" == "y" ]]; then 		uuid=${currentUUID}
			addClientsStatus=true
		else
			uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
		fi
	elif [[ -z "${uuid}" ]]; then 	uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
	fi

	if [[ -z "${uuid}" ]]; then
		addClientsStatus=
		EchoContent red " n -->uuid read error, regenerate"
		uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
	fi

	movePreviousConfig
	# log
	cat <<EOF >/etc/v2ray-agent/v2ray/conf/00_log.json
{
  "log": {
    "error": "/etc/v2ray-agent/v2ray/error.log",
    "loglevel": "warning"
  }
}
EOF
	# outbounds
	if [[ -n "${pingIPv6}" ]]; then
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/10_ipv6_outbounds.json
{
    "outbounds": [
        {
          "protocol": "freedom",
          "settings": {},
          "tag": "direct"
        }
    ]
}
EOF

	else
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4-out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6-out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole-out"
        }
    ]
}
EOF
	fi

	# dns
	cat <<EOF >/etc/v2ray-agent/v2ray/conf/11_dns.json
{
    "dns": {
        "servers": [
          "localhost"
        ]
  }
}
EOF

	# VLESS_TCP_TLS
	#Fallback nginx
	local fallbacksList='{"dest":31300,"xver":0},{"alpn":"h2","dest":31302,"xver":0}'

	# trojan
	if echo "${selectCustomInstallType}" | grep -q 4 || [[ "$1" == "all" ]]; then

		fallbacksList='{"dest":31296,"xver":1},{"alpn":"h2","dest":31302,"xver":0}'

		getClients "${configPath}../tmp/04_trojan_TCP_inbounds.json" "${addClientsStatus}"
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/04_trojan_TCP_inbounds.json
{
"inbounds":[
	{
	  "port": 31296,
	  "listen": "127.0.0.1",
	  "protocol": "trojan",
	  "tag":"trojanTCP",
	  "settings": {
		"clients": [
		  {
			"password": "${uuid}",
			"email": "${domain}_${uuid}"
		  }
		],
		"fallbacks":[
			{"dest":"31300"}
		]
	  },
	  "streamSettings": {
		"network": "tcp",
		"security": "none",
		"tcpSettings": {
			"acceptProxyProtocol": true
		}
	  }
	}
	]
}
EOF
		addClients "/etc/v2ray-agent/v2ray/conf/04_trojan_TCP_inbounds.json" "${addClientsStatus}"
	fi

	# VLESS_WS_TLS
	if echo "${selectCustomInstallType}" | grep -q 1 || [[ "$1" == "all" ]]; then 	fallbacksList=${fallbacksList}',{"path":"/'${customPath}'ws","dest":31297,"xver":1}'
		getClients "${configPath}../tmp/03_VLESS_WS_inbounds.json" "${addClientsStatus}"
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/03_VLESS_WS_inbounds.json
{
"inbounds":[
    {
	  "port": 31297,
	  "listen": "127.0.0.1",
	  "protocol": "vless",
	  "tag":"VLESSWS",
	  "settings": {
		"clients": [
		  {
			"id": "${uuid}",
			"email": "${domain}_${uuid}"
		  }
		],
		"decryption": "none"
	  },
	  "streamSettings": {
		"network": "ws",
		"security": "none",
		"wsSettings": {
		  "acceptProxyProtocol": true,
		  "path": "/${customPath}ws"
		}
	  }
	}
]
}
EOF
		addClients "/etc/v2ray-agent/v2ray/conf/03_VLESS_WS_inbounds.json" "${addClientsStatus}"
	fi

	# trojan_grpc
	if echo "${selectCustomInstallType}" | grep -q 2 || [[ "$1" == "all" ]]; then
		if ! echo "${selectCustomInstallType}" | grep -q 5 && [[ -n ${selectCustomInstallType} ]]; then 		fallbacksList=${fallbacksList//31302/31304}
		fi
		getClients "${configPath}../tmp/04_trojan_gRPC_inbounds.json" "${addClientsStatus}"
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/04_trojan_gRPC_inbounds.json
{
    "inbounds": [
        {
            "port": 31304,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "tag": "trojangRPCTCP",
            "settings": {
                "clients": [
                    {
                        "password": "${uuid}",
                        "email": "${domain}_${uuid}"
                    }
                ],
                "fallbacks": [
                    {
                        "dest": "31300"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "${customPath}trojangrpc"
                }
            }
        }
    ]
}
EOF
		addClients "/etc/v2ray-agent/v2ray/conf/04_trojan_gRPC_inbounds.json" "${addClientsStatus}"
	fi

	# VMess_WS
	if echo "${selectCustomInstallType}" | grep -q 3 || [[ "$1" == "all" ]]; then 	fallbacksList=${fallbacksList}',{"path":"/'${customPath}'vws","dest":31299,"xver":1}'

		getClients "${configPath}../tmp/05_VMess_WS_inbounds.json" "${addClientsStatus}"

		cat <<EOF >/etc/v2ray-agent/v2ray/conf/05_VMess_WS_inbounds.json
{
"inbounds":[
{
  "listen": "127.0.0.1",
  "port": 31299,
  "protocol": "vmess",
  "tag":"VMessWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "alterId": 0,
        "add": "${add}",
        "email": "${domain}_${uuid}"
      }
    ]
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}vws"
    }
  }
}
]
}
EOF
		addClients "/etc/v2ray-agent/v2ray/conf/05_VMess_WS_inbounds.json" "${addClientsStatus}"
	fi

	if echo "${selectCustomInstallType}" | grep -q 5 || [[ "$1" == "all" ]]; then
		getClients "${configPath}../tmp/06_VLESS_gRPC_inbounds.json" "${addClientsStatus}"
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/06_VLESS_gRPC_inbounds.json
{
    "inbounds":[
    {
        "port": 31301,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "tag":"VLESSGRPC",
        "settings": {
            "clients": [
                {
                    "id": "${uuid}",
                    "add": "${add}",
                    "email": "${domain}_${uuid}"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "grpc",
            "grpcSettings": {
                "serviceName": "${customPath}grpc"
            }
        }
    }
]
}
EOF
		addClients "/etc/v2ray-agent/v2ray/conf/06_VLESS_gRPC_inbounds.json" "${addClientsStatus}"
	fi

	# VLESS_TCP
	getClients "${configPath}../tmp/02_VLESS_TCP_inbounds.json" "${addClientsStatus}"
	local defaultPort=443
	if [[ -n "${customPort}" ]]; then 	defaultPort=${customPort}
	fi

	cat <<EOF >/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json
{
"inbounds":[
{
  "port": ${defaultPort},
  "protocol": "vless",
  "tag":"VLESSTCP",
  "settings": {
    "clients": [
     {
        "id": "${uuid}",
        "add":"${add}",
        "email": "${domain}_VLESS_TLS-direct_TCP"
      }
    ],
    "decryption": "none",
    "fallbacks": [
        ${fallbacksList}
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "minVersion": "1.2",
      "alpn": [
        "http/1.1",
        "h2"
      ],
      "certificates": [
        {
          "certificateFile": "/etc/v2ray-agent/tls/${domain}.crt",
          "keyFile": "/etc/v2ray-agent/tls/${domain}.key",
          "ocspStapling": 3600,
          "usage":"encipherment"
        }
      ]
    }
  }
}
]
}
EOF
	addClients "/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json" "${addClientsStatus}"

}

#Initialize Xray Trojan XTLS configuration file
initXrayFrontingConfig() {
	if [[ -z "${configPath}" ]]; then
		EchoContent red "-->Not installed, please use script to install"
		menu
		exit 0
	fi
	if [[ "${coreInstallType}" != "1" ]]; then
		EchoContent red "-->No available types installed"
	fi
	local xtlsType=
	if echo ${currentInstallProtocolType} | grep -q trojan; then
		xtlsType=VLESS
	else
		xtlsType=Trojan

	fi

	EchoContent skyBlue " nFunction 1/${totalProgress}: Front switch to ${xtlsType}"
	echoContent red "\n============================================================== "
	EchoContent yellow "# Precautions  n
	EchoContent yellow "will replace the prefix with ${xtlsType}"
	EchoContent yellow "If Trojan is in front, when viewing the account, two nodes of the Trojan protocol will appear, one of which is not available with xtls
	EchoContent yellow "Executing again can switch to the previous preceding  n

	EchoContent yellow "1. Switch to ${xtlsType}"
	echoContent red "============================================================== "
	Read - r - p "Please select:" selectType
	if [[ "${selectType}" == "1" ]]; then

		if [[ "${xtlsType}" == "Trojan" ]]; then

			local VLESSConfig
			VLESSConfig=$(cat ${configPath}${frontingType}.json)
			VLESSConfig=${VLESSConfig//"id"/"password"}
			VLESSConfig=${VLESSConfig//VLESSTCP/TrojanTCPXTLS}
			VLESSConfig=${VLESSConfig//VLESS/Trojan}
			VLESSConfig=${VLESSConfig//"vless"/"trojan"}
			VLESSConfig=${VLESSConfig//"id"/"password"}

			echo "${VLESSConfig}" | jq . >$ {configPath}02_trojan_TCP_inbounds.json
			rm ${configPath}${frontingType}.json
		elif [[ "${xtlsType}" == "VLESS" ]]; then

			local VLESSConfig
			VLESSConfig=$(cat ${configPath}02_trojan_TCP_inbounds.json)
			VLESSConfig=${VLESSConfig//"password"/"id"}
			VLESSConfig=${VLESSConfig//TrojanTCPXTLS/VLESSTCP}
			VLESSConfig=${VLESSConfig//Trojan/VLESS}
			VLESSConfig=${VLESSConfig//"trojan"/"vless"}
			VLESSConfig=${VLESSConfig//"password"/"id"}

			echo "${VLESSConfig}" | jq . >$ {configPath}02_VLESS_TCP_inbounds.json
			rm ${configPath}02_trojan_TCP_inbounds.json
		fi
		reloadCore
	fi

	exit 0
}

#Move last configuration file to temporary file
movePreviousConfig() {
	if [[ -n "${configPath}" ]] && [[ -f "${configPath}02_VLESS_TCP_inbounds.json" ]]; then
		rm -rf ${configPath}../tmp/*
		mv ${configPath}* ${configPath}../tmp/
	fi

}

#Initialize Xray configuration file
initXrayConfig() {
	EchoContent skyBlue " n Progress $2/${totalProgress}: Initialize Xray configuration"
	echo
	local uuid=
	local addClientsStatus=
	if [[ -n "${currentUUID}" ]]; then
		Read - r - p "Read the last installation record, do you want to use the UUID from the last installation? [y/n]:" historyUUIDStatus
		if [[ "${historyUUIDStatus}" == "y" ]]; then 		uuid=${currentUUID}
			EchoContent green " n -->Successfully used"
			if [[ -z "${uuid}" ]]; then
				EchoContent red " n -->uuid read error, regenerate"
			fi
		fi
    fi

	if [[ -z "${uuid}" ]]; then
		EchoContent yellow "Please enter a custom UUID [legal], [enter] a random UUID"
		read -r -p 'UUID:' customUUID
		if [[ -n ${customUUID} ]]; then 		uuid=${customUUID}
		else
			uuid=$(/etc/v2ray-agent/xray/xray uuid)
		fi
	fi
		
	echoContent yellow "\n ${uuid}"

	movePreviousConfig

	# log
	cat <<EOF >/etc/v2ray-agent/xray/conf/00_log.json
{
  "log": {
    "error": "/etc/v2ray-agent/xray/error.log",
    "loglevel": "warning"
  }
}
EOF

	# outbounds
	if [[ -n "${pingIPv6}" ]]; then
		cat <<EOF >/etc/v2ray-agent/xray/conf/10_ipv6_outbounds.json
{
    "outbounds": [
        {
          "protocol": "freedom",
          "settings": {},
          "tag": "direct"
        }
    ]
}
EOF

	else
		cat <<EOF >/etc/v2ray-agent/xray/conf/10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4-out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6-out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole-out"
        }
    ]
}
EOF
	fi

	# dns
	cat <<EOF >/etc/v2ray-agent/xray/conf/11_dns.json
{
    "dns": {
        "servers": [
          "8.8.8.8"
        ]
  }
}
EOF

	# VLESS_TCP_TLS/XTLS
	#Fallback nginx
	local fallbacksList='{"dest":31300,"xver":0},{"alpn":"h2","dest":31302,"xver":0}'

	# trojan
	if echo "${selectCustomInstallType}" | grep -q 4 || [[ "$1" == "all" ]]; then 	fallbacksList='{"dest":31296,"xver":1},{"alpn":"h2","dest":31302,"xver":0}'
		getClients "${configPath}../tmp/04_trojan_TCP_inbounds.json" "${addClientsStatus}"

		cat <<EOF >/etc/v2ray-agent/xray/conf/04_trojan_TCP_inbounds.json
{
"inbounds":[
	{
	  "port": 31296,
	  "listen": "127.0.0.1",
	  "protocol": "trojan",
	  "tag":"trojanTCP",
	  "settings": {
		"clients": [
		  {
			"password": "${uuid}",
			"email": "${domain}_${uuid}"
		  }
		],
		"fallbacks":[
			{"dest":"31300"}
		]
	  },
	  "streamSettings": {
		"network": "tcp",
		"security": "none",
		"tcpSettings": {
			"acceptProxyProtocol": true
		}
	  }
	}
	]
}
EOF
		addClients "/etc/v2ray-agent/xray/conf/04_trojan_TCP_inbounds.json" "${addClientsStatus}"
	fi

	# VLESS_WS_TLS
	if echo "${selectCustomInstallType}" | grep -q 1 || [[ "$1" == "all" ]]; then 	fallbacksList=${fallbacksList}',{"path":"/'${customPath}'ws","dest":31297,"xver":1}'
		getClients "${configPath}../tmp/03_VLESS_WS_inbounds.json" "${addClientsStatus}"
		cat <<EOF >/etc/v2ray-agent/xray/conf/03_VLESS_WS_inbounds.json
{
"inbounds":[
    {
	  "port": 31297,
	  "listen": "127.0.0.1",
	  "protocol": "vless",
	  "tag":"VLESSWS",
	  "settings": {
		"clients": [
		  {
			"id": "${uuid}",
			"email": "${domain}_${uuid}"
		  }
		],
		"decryption": "none"
	  },
	  "streamSettings": {
		"network": "ws",
		"security": "none",
		"wsSettings": {
		  "acceptProxyProtocol": true,
		  "path": "/${customPath}ws"
		}
	  }
	}
]
}
EOF
		addClients "/etc/v2ray-agent/xray/conf/03_VLESS_WS_inbounds.json" "${addClientsStatus}"
	fi

	# trojan_grpc
	if echo "${selectCustomInstallType}" | grep -q 2 || [[ "$1" == "all" ]]; then
		if ! echo "${selectCustomInstallType}" | grep -q 5 && [[ -n ${selectCustomInstallType} ]]; then 		fallbacksList=${fallbacksList//31302/31304}
		fi
		getClients "${configPath}../tmp/04_trojan_gRPC_inbounds.json" "${addClientsStatus}"
		cat <<EOF >/etc/v2ray-agent/xray/conf/04_trojan_gRPC_inbounds.json
{
    "inbounds": [
        {
            "port": 31304,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "tag": "trojangRPCTCP",
            "settings": {
                "clients": [
                    {
                        "password": "${uuid}",
                        "email": "${domain}_${uuid}"
                    }
                ],
                "fallbacks": [
                    {
                        "dest": "31300"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "${customPath}trojangrpc"
                }
            }
        }
    ]
}
EOF
		addClients "/etc/v2ray-agent/xray/conf/04_trojan_gRPC_inbounds.json" "${addClientsStatus}"
	fi

	# VMess_WS
	if echo "${selectCustomInstallType}" | grep -q 3 || [[ "$1" == "all" ]]; then 	fallbacksList=${fallbacksList}',{"path":"/'${customPath}'vws","dest":31299,"xver":1}'
		getClients "${configPath}../tmp/05_VMess_WS_inbounds.json" "${addClientsStatus}"
		cat <<EOF >/etc/v2ray-agent/xray/conf/05_VMess_WS_inbounds.json
{
"inbounds":[
{
  "listen": "127.0.0.1",
  "port": 31299,
  "protocol": "vmess",
  "tag":"VMessWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "alterId": 0,
        "add": "${add}",
        "email": "${domain}_${uuid}"
      }
    ]
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}vws"
    }
  }
}
]
}
EOF
		addClients "/etc/v2ray-agent/xray/conf/05_VMess_WS_inbounds.json" "${addClientsStatus}"
	fi

	if echo "${selectCustomInstallType}" | grep -q 5 || [[ "$1" == "all" ]]; then
		getClients "${configPath}../tmp/06_VLESS_gRPC_inbounds.json" "${addClientsStatus}"
		cat <<EOF >/etc/v2ray-agent/xray/conf/06_VLESS_gRPC_inbounds.json
{
    "inbounds":[
    {
        "port": 31301,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "tag":"VLESSGRPC",
        "settings": {
            "clients": [
                {
                    "id": "${uuid}",
                    "add": "${add}",
                    "email": "${domain}_${uuid}"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "grpc",
            "grpcSettings": {
                "serviceName": "${customPath}grpc"
            }
        }
    }
]
}
EOF
		addClients "/etc/v2ray-agent/xray/conf/06_VLESS_gRPC_inbounds.json" "${addClientsStatus}"
	fi

	# VLESS_TCP
	getClients "${configPath}../tmp/02_VLESS_TCP_inbounds.json" "${addClientsStatus}"
	local defaultPort=443
	if [[ -n "${customPort}" ]]; then 	defaultPort=${customPort}
	fi
	if [ "$xtlsRprxVision" ==true ]; then
		cat <<EOF >/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json
{
"inbounds":[
{
  "port": ${defaultPort},
  "protocol": "vless",
  "tag":"VLESSTCP",
  "settings": {
    "clients": [
     {
        "id": "${uuid}",
        "add":"${add}",
        "flow":"xtls-rprx-vision",
        "email": "${domain}_${uuid}"
      }
    ],
    "decryption": "none",
    "fallbacks": [
        ${fallbacksList}
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "minVersion": "1.2",
      "alpn": [
        "http/1.1",
        "h2"
      ],
      "certificates": [
        {
          "certificateFile": "/etc/v2ray-agent/tls/${domain}.crt",
          "keyFile": "/etc/v2ray-agent/tls/${domain}.key",
          "ocspStapling": 3600,
          "usage":"encipherment"
        }
      ]
    }
  }
}
]
}
EOF
else
		cat <<EOF >/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json
{
"inbounds":[
{
  "port": ${defaultPort},
  "protocol": "vless",
  "tag":"VLESSTCP",
  "settings": {
    "clients": [
     {
        "id": "${uuid}",
        "add":"${add}",
        "flow":"xtls-rprx-direct",
        "email": "${domain}_${uuid}"
      }
    ],
    "decryption": "none",
    "fallbacks": [
        ${fallbacksList}
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "xtls",
    "xtlsSettings": {
      "minVersion": "1.2",
      "alpn": [
        "http/1.1",
        "h2"
      ],
      "certificates": [
        {
          "certificateFile": "/etc/v2ray-agent/tls/${domain}.crt",
          "keyFile": "/etc/v2ray-agent/tls/${domain}.key",
          "ocspStapling": 3600,
          "usage":"encipherment"
        }
      ]
    }
  }
}
]
}
EOF
fi
	addClients "/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json" "${addClientsStatus}"
}

#Initialize Trojan Go configuration
initTrojanGoConfig() {

	EchoContent skyBlue " n Progress $1/${totalProgress}: Initialize Trojan configuration"
	cat <<EOF >/etc/v2ray-agent/trojan/config_full.json
{
    "run_type": "server",
    "local_addr": "127.0.0.1",
    "local_port": 31296,
    "remote_addr": "127.0.0.1",
    "remote_port": 31300,
    "disable_http_check":true,
    "log_level":3,
    "log_file":"/etc/v2ray-agent/trojan/trojan.log",
    "password": [
        "${uuid}"
    ],
    "dns":[
        "localhost"
    ],
    "transport_plugin":{
        "enabled":true,
        "type":"plaintext"
    },
    "websocket": {
        "enabled": true,
        "path": "/${customPath}tws",
        "host": "${domain}",
        "add":"${add}"
    },
    "router": {
        "enabled": false
    }
}
EOF
}

#Custom CDN IP
customCDNIP() {
	EchoContent skyBlue " n Progress $1/${totalProgress}: Add cloudflare custom CNAME"
	echoContent red "\n============================================================== "
	EchoContent yellow "# Precautions"
	EchoContent yellow " n Tutorial address:
	echoContent skyBlue " https://github.com/reeceyng/v2ray-agent/blob/master/documents/optimize_V2Ray.md "
	EchoContent red " n If you are not familiar with Cloudflare optimization, please do not use"
	EchoContent yellow " n 1. Move: 104.16.123.96"
	EchoContent yellow "2. Unicom: www.cloudflare. com
	EchoContent yellow "3. Telecom: www.digitaloan.com
	echoContent skyBlue "----------------------------"
	Read - r - p "Please select [carriage return not used]:" selectCloudflareType
	case ${selectCloudflareType} in
	1)
		add="104.16.123.96"
		;;
	2)
		add="www.cloudflare.com"
		;;
	3)
		add="www.digitalocean.com"
		;;
	*)
		add="${domain}"
		EchoContent yellow " n -->Do not use"
		;;
	esac
}
#Universal
defaultBase64Code() {
	local type=$1
	local email=$2
	local id=$3

	port=${currentDefaultPort}

	local subAccount
	subAccount=$(echo "${email}" | awk -F "[_]" '{print $1}')_$ (echo "${id}_currentHost" | md5sum | awk '{print $1}')
	email="${email:0:3}"
	if [[ "${type}" == "vlesstcp" ]]; then

		if [[ "${coreInstallType}" == "1" ]] && echo "${currentInstallProtocolType}" | grep -q 0; then
			EchoContent yellow "-->Universal format (VLESS+TCP+TLS/xtls rprx direct)
			echoContent green "    vless://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=xtls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-direct#${email}\n"

			EchoContent yellow "-->Format plaintext (VLESS+TCP+TLS/xtls rprx direct)
			EchoContent green "Protocol type: VLESS, address: ${currentHost}, port: ${currentDefaultPort}, user ID: ${id}, security: xtls, transmission method: TCP, flow: xtls rprx direct, account name: ${email}  n
			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${currentHost}:${currentDefaultPort}? encryption=none&security=xtls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-direct#${email}
EOF
			EchoContent yellow "-->QR code VLESS (VLESS+TCP+TLS/xtls rprx direct)
			echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F ${id}%40${currentHost}%3A${currentDefaultPort}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${currentHost}%3D${currentHost}%26headerType%3Dnone%26sni%3D${currentHost}%26flow%3Dxtls-rprx-direct%23${email}\n"

			echoContent skyBlue "----------------------------------------------------------------------------------"

			EchoContent yellow "-->Universal format (VLESS+TCP+TLS/xtls rprx splice)
			echoContent green "    vless://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=xtls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-splice#${email/direct/splice}\n"

			EchoContent yellow "-->Format plaintext (VLESS+TCP+TLS/xtls rprx splice)
			EchoContent green "Protocol type: VLESS, address: ${currentHost}, port: ${currentDefaultPort}, user ID: ${id}, security: xtls, transmission method: TCP, flow: xtls rprx splice, account name: ${email/direct/device}  n
			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${currentHost}:${currentDefaultPort}? encryption=none&security=xtls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-splice#${email/direct/splice}
EOF
			EchoContent yellow "-->QR code VLESS (VLESS+TCP+TLS/xtls rprx splice)
			echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F ${id}%40${currentHost}%3A${currentDefaultPort}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${currentHost}%3D${currentHost}%26headerType%3Dnone%26sni%3D${currentHost}%26flow%3Dxtls-rprx-splice%23${email/direct/splice}\n"

		elif [[ "${coreInstallType}" ==2 ]]; then
			EchoContent yellow "-->Universal format (VLESS+TCP+TLS)
			echoContent green "    vless://${id}@${currentHost}:${currentDefaultPort}?security=tls&encryption=none&host=${currentHost}&headerType=none&type=tcp#${email}\n"

			EchoContent yellow "-->Format plaintext (VLESS+TCP+TLS/xtls rprx splice)
			EchoContent green "Protocol type: VLESS, address: ${currentHost}, port: ${currentDefaultPort}, user ID: ${id}, security: tls, transmission method: TCP, account name: ${email/direct/device}  n

			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${currentHost}:${currentDefaultPort}? security=tls&encryption=none&host=${currentHost}&headerType=none&type=tcp#${email}
EOF
			EchoContent yellow "-->QR code VLESS (VLESS+TCP+TLS)
			echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3a%2f%2f ${id}%40${currentHost}%3a${currentDefaultPort}%3fsecurity%3dtls%26encryption%3dnone%26host%3d${currentHost}%26headerType%3dnone%26type%3dtcp%23${email}\n"
		
		elif [[ "${coreInstallType}" ==3 ]] && echo "${currentInstallProtocolType}" | grep -q 0; then
			EchoContent yellow "-->Universal format (VLESS+TCP+TLS/xtls rprx vision)
			echoContent green "    vless://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=tls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-vision#${email/direct/splice}-xray-vision\n"

			EchoContent yellow "-->Format plaintext (VLESS+TCP+TLS/xtls rprx vision)
			EchoContent green "Protocol type: VLESS, address: ${currentHost}, port: ${currentDefaultPort}, user ID: ${id}, security: tls, transmission method: TCP, flow: xtls rprx vision, account name: ${email/direct/device} xray vision  n

			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${currentHost}:${currentDefaultPort}? security=tls&encryption=none&host=${currentHost}&headerType=none&type=tcp&sni=${currentHost}&flow=xtls-rprx-vision#${email}-xray-vision
EOF
			EchoContent yellow "-->QR code VLESS (VLESS+TCP+TLS)
			echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F ${id}%40${currentHost}%3A${currentDefaultPort}%3Fencryption%3Dnone%26security%3Dtls%26type%3Dtcp%26${currentHost}%3D${currentHost}%26headerType%3Dnone%26sni%3D${currentHost}%26flow%3Dxtls-rprx-vision%23${email/direct/splice}\n"
		fi

	elif [[ "${type}" == "trojanTCPXTLS" ]]; then
		EchoContent yellow "-->Universal format (Trojan+TCP+TLS/xtls rprx direct)
		echoContent green "    trojan://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=xtls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-direct#${email}\n"

		EchoContent yellow "-->Format plaintext (Trojan+TCP+TLS/xtls rprx direct)
		EchoContent green "Protocol type: Trojan, address: ${currentHost}, port: ${currentDefaultPort}, user ID: ${id}, security: xtls, transmission method: TCP, flow: xtls rprx direct, account name: ${email}  n
		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${currentHost}:${currentDefaultPort}? encryption=none&security=xtls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-direct#${email}
EOF
		EchoContent yellow "-->QR code Trojan (Trojan+TCP+TLS/xtls rprx direct)
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3A%2F%2F ${id}%40${currentHost}%3A${currentDefaultPort}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${currentHost}%3D${currentHost}%26headerType%3Dnone%26sni%3D${currentHost}%26flow%3Dxtls-rprx-direct%23${email}\n"

		echoContent skyBlue "----------------------------------------------------------------------------------"

		EchoContent yellow "-->Universal format (Trojan+TCP+TLS/xtls rprx splice)
		echoContent green "    trojan://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=xtls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-splice#${email/direct/splice}\n"

		EchoContent yellow "-->Format plaintext (Trojan+TCP+TLS/xtls rprx splice)
		EchoContent green "Protocol type: VLESS, address: ${currentHost}, port: ${currentDefaultPort}, user ID: ${id}, security: xtls, transmission method: TCP, flow: xtls rprx splice, account name: ${email/direct/device}  n
		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${currentHost}:${currentDefaultPort}? encryption=none&security=xtls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-splice#${email/direct/splice}
EOF
		EchoContent yellow "-->QR code Trojan (Trojan+TCP+TLS/xtls rprx splice)
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3A%2F%2F ${id}%40${currentHost}%3A${currentDefaultPort}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${currentHost}%3D${currentHost}%26headerType%3Dnone%26sni%3D${currentHost}%26flow%3Dxtls-rprx-splice%23${email/direct/splice}\n"

	elif [[ "${type}" == "vmessws" ]]; then
		qrCodeBase64Default=$(echo -n "{\"port\":${currentDefaultPort},\"ps\":\"${email}-vmess-ws\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${currentHost}\",\"type\":\"none\",\"path\":\"/${currentPath}vws\",\"net\":\"ws\",\"add\":\"${currentAdd}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${currentHost}\",\"sni\":\"${currentHost}\"}" | base64 -w 0)
		qrCodeBase64Default="${qrCodeBase64Default///}"

		EchoContent yellow "-->General JSON (VMess+WS+TLS)"
		echoContent green "    {\"port\":${currentDefaultPort},\"ps\":\"${email}-vmess-ws\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${currentHost}\",\"type\":\"none\",\"path\":\"/${currentPath}vws\",\"net\":\"ws\",\"add\":\"${currentAdd}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${currentHost}\",\"sni\":\"${currentHost}\"}\n"
		EchoContent yellow "-->Universal vmess (VMess+WS+TLS) link"
		echoContent green "    vmess://${qrCodeBase64Default}\n"
		EchoContent yellow "-->QR code vmess (VMess+WS+TLS)"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vmess://${qrCodeBase64Default}
EOF
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vmess://${qrCodeBase64Default}\n"

		#	elif [[ "${type}" == "vmesstcp" ]]; then
		#
		#		echoContent red "path:${path}"
		#		qrCodeBase64Default=$(echo -n "{\"add\":\"${add}\",\"aid\":0,\"host\":\"${host}\",\"id\":\"${id}\",\"net\":\"tcp\",\"path\":\"${path}\",\"port\":${port},\"ps\":\"${email}\",\"scy\":\"none\",\"sni\":\"${host}\",\"tls\":\"tls\",\"v\":2,\"type\":\"http\",\"allowInsecure\":0,\"peer\":\"${host}\",\"obfs\":\"http\",\"obfsParam\":\"${host}\"}" | base64)
		#		qrCodeBase64Default="${qrCodeBase64Default///}"
		#
		#		EchoContent yellow "-->General JSON (VMess+TCP+TLS)"
		#		echoContent green "    {\"port\":'${port}',\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${host}\",\"type\":\"http\",\"path\":\"${path}\",\"net\":\"http\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"post\",\"peer\":\"${host}\",\"obfs\":\"http\",\"obfsParam\":\"${host}\"}\n"
		#		EchoContent yellow "-->Universal vmess (VMess+TCP+TLS) link"
		#		echoContent green "    vmess://${qrCodeBase64Default}\n"
		#
		#		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
		#vmess://${qrCodeBase64Default}
		#EOF
		#		EchoContent yellow "-->QR code vmess (VMess+TCP+TLS)"
		#		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vmess://${qrCodeBase64Default}\n"

	elif [[ "${type}" == "vlessws" ]]; then

		EchoContent yellow "-->Universal format (VLESS+WS+TLS)
		echoContent green "    vless://${id}@${currentAdd}:${currentDefaultPort}?encryption=none&security=tls&type=ws&host=${currentHost}&sni=${currentHost}&path=/${currentPath}ws#${email}-vless-ws\n"

		EchoContent yellow "-->Format plaintext (VLESS+WS+TLS)
		EchoContent green "Protocol type: VLESS, address: ${currentAdd}, disguised domain name/SNI: ${currentHost}, port: ${currentDefaultPort}, user ID: ${id}, security: tls, transmission method: ws, path:/${currentPath} ws, account name: ${email} vless ws  n

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${currentAdd}:${currentDefaultPort}? encryption=none&security=tls&type=ws&host=${currentHost}&sni=${currentHost}&path=/${currentPath}ws#${email}-vless-ws
EOF

		EchoContent yellow "-->QR code VLESS (VLESS+WS+TLS)
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F ${id}%40${currentAdd}%3A${currentDefaultPort}%3Fencryption%3Dnone%26security%3Dtls%26type%3Dws%26host%3D${currentHost}%26sni%3D${currentHost}%26path%3D%252f${currentPath}ws%23${email}"

	elif [[ "${type}" == "vlessgrpc" ]]; then

		EchoContent yellow "-->General format (VLESS+gRPC+TLS)
		echoContent green "    vless://${id}@${currentAdd}:${currentDefaultPort}?encryption=none&security=tls&type=grpc&host=${currentHost}&path=${currentPath}grpc&serviceName=${currentPath}grpc&alpn=h2&sni=${currentHost}#${email}-vless-grpc\n"

		EchoContent yellow "-->Format plaintext (VLESS+gRPC+TLS)
		EchoContent green "Protocol type: VLESS, address: ${currentAdd}, disguised domain name/SNI: ${currentHost}, port: ${currentDefaultPort}, user ID: ${id}, security: tls, transmission method: gRPC, alpn: h2, serviceName: ${currentPath} grpc, account name: ${email} - vless grpc  n

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${currentAdd}:${currentDefaultPort}? encryption=none&security=tls&type=grpc&host=${currentHost}&path=${currentPath}grpc&serviceName=${currentPath}grpc&alpn=h2&sni=${currentHost}#${email}-vless-grpc
EOF
		EchoContent yellow "-->QR code VLESS (VLESS+gRPC+TLS)
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F ${id}%40${currentAdd}%3A${currentDefaultPort}%3Fencryption%3Dnone%26security%3Dtls%26type%3Dgrpc%26host%3D${currentHost}%26serviceName%3D${currentPath}grpc%26path%3D${currentPath}grpc%26sni%3D${currentHost}%26alpn%3Dh2%23${email}"

	elif [[ "${type}" == "trojan" ]]; then
		# URLEncode
		echoContent yellow " ---> Trojan(TLS)"
		echoContent green "    trojan://${id}@${currentHost}:${currentDefaultPort}?peer=${currentHost}&sni=${currentHost}&alpn=http/1.1#${currentHost}-trojan\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${currentHost}:${currentDefaultPort}? peer=${currentHost}&sni=${currentHost}&alpn=http/1.1#${email}-trojan
EOF
		EchoContent yellow "-->QR code Trojan (TLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f ${id}%40${currentHost}%3a${port}%3fpeer%3d${currentHost}%26sni%3d${currentHost}%26alpn%3Dhttp/1.1%23${email}\n"

	elif [[ "${type}" == "trojangrpc" ]]; then
		# URLEncode

		echoContent yellow " ---> Trojan gRPC(TLS)"
		echoContent green "    trojan://${id}@${currentAdd}:${currentDefaultPort}?encryption=none&peer=${currentHost}&security=tls&type=grpc&sni=${currentHost}&alpn=h2&path=${currentPath}trojangrpc&serviceName=${currentPath}trojangrpc#${email}-trojan-grpc\n"
		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${currentAdd}:${currentDefaultPort}? encryption=none&peer=${currentHost}&security=tls&type=grpc&sni=${currentHost}&alpn=h2&path=${currentPath}trojangrpc&serviceName=${currentPath}trojangrpc#${email}-trojan-grpc
EOF
		EchoContent yellow "-->QR code Trojan gRPC (TLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f ${id}%40${currentAdd}%3a${currentDefaultPort}%3Fencryption%3Dnone%26security%3Dtls%26peer%3d${currentHost}%26type%3Dgrpc%26sni%3d${currentHost}%26path%3D${currentPath}trojangrpc%26alpn%3Dh2%26serviceName%3D${currentPath}trojangrpc%23${email}\n"

	elif [[ "${type}" == "hysteria" ]]; then
		echoContent yellow " ---> Hysteria(TLS)"
		echoContent green "    hysteria://${currentHost}:${hysteriaPort}?protocol=${hysteriaProtocol}&auth=${id}&peer=${currentHost}&insecure=0&alpn=h3&upmbps=${hysteriaClientUploadSpeed}&downmbps=${hysteriaClientDownloadSpeed}#${email}\n"
		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
hysteria://${currentHost}:${hysteriaPort}? protocol=${hysteriaProtocol}&auth=${id}&peer=${currentHost}&insecure=0&alpn=h3&upmbps=${hysteriaClientUploadSpeed}&downmbps=${hysteriaClientDownloadSpeed}#${email}
EOF
		EchoContent yellow "-->QR code Hysteria (TLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=hysteria%3A%2F%2F ${currentHost}%3A${hysteriaPort}%3Fprotocol%3D${hysteriaProtocol}%26auth%3D${id}%26peer%3D${currentHost}%26insecure%3D0%26alpn%3Dh3%26upmbps%3D${hysteriaClientUploadSpeed}%26downmbps%3D${hysteriaClientDownloadSpeed}%23${email}\n"
	fi

}
#Account
showAccounts() {
	readInstallType
	readInstallProtocolType
	readConfigHostPathUUID
	readHysteriaConfig
	EchoContent skyBlue " n Progress $1/${totalProgress}: Account"
	local show
	# VLESS TCP
	if [[ -n "${configPath}" ]]; then 	show=1
		if echo "${currentInstallProtocolType}" | grep -q trojan; then
			echoContent skyBlue "=====================Trojan TCP TLS/XTLS-direct/XTLS-splice ======================\n"
			jq .inbounds[0].settings.clients ${configPath}02_trojan_TCP_inbounds.json | jq -c '. []' | while read -r user; do
				local email=
				email=$(echo "${user}" | jq -r .email)
				EchoContent skyBlue " n -->Account: ${email}"
				defaultBase64Code trojanTCPXTLS "${email}" "$(echo "${user}" | jq -r .password)"
			done

		else
			echoContent skyBlue "================VLESS TCP TLS/XTLS-direct/XTLS-splice/XTLS-vision ================\n"
			jq .inbounds[0].settings.clients ${configPath}02_VLESS_TCP_inbounds.json | jq -c '. []' | while read -r user; do
				local email=
				email=$(echo "${user}" | jq -r .email)

				EchoContent skyBlue " n -->Account: ${email}"
				echo
				defaultBase64Code vlesstcp "${email}" "$(echo "${user}" | jq -r .id)"
			done
		fi

		# VLESS WS
		if echo ${currentInstallProtocolType} | grep -q 1; then
			echoContent skyBlue "\n================================VLESS WS TLS CDN ================================\n"

			jq .inbounds[0].settings.clients ${configPath}03_VLESS_WS_inbounds.json | jq -c '. []' | while read -r user; do
				local email=
				email=$(echo "${user}" | jq -r .email)

				EchoContent skyBlue " n -->Account: ${email}"
				echo
				local path="${currentPath}ws"
				#	if [[ ${coreInstallType} == "1" ]]; then
				#		EchoContent yellow "Xray will have a 0-RTT path after it, which is not compatible with clients centered on v2ray. Please manually delete it before using it 
				#		path="${currentPath}ws"
				#	fi
				defaultBase64Code vlessws "${email}" "$(echo "${user}" | jq -r .id)"
			done
		fi

		# VMess WS
		if echo ${currentInstallProtocolType} | grep -q 3; then
			echoContent skyBlue "\n================================VMess WS TLS CDN ================================\n"
			local path="${currentPath}vws"
			if [[ ${coreInstallType} == "1" ]]; then 			path="${currentPath}vws"
			fi
			jq .inbounds[0].settings.clients ${configPath}05_VMess_WS_inbounds.json | jq -c '. []' | while read -r user; do
				local email=
				email=$(echo "${user}" | jq -r .email)

				EchoContent skyBlue " n -->Account: ${email}"
				echo
				defaultBase64Code vmessws "${email}" "$(echo "${user}" | jq -r .id)"
			done
		fi

		# VLESS grpc
		if echo ${currentInstallProtocolType} | grep -q 5; then
			echoContent skyBlue "\n===============================VLESS gRPC TLS CDN ===============================\n"
			EchoContent red " n -->gRPC is in the testing stage and may not be compatible with the client you are using. If it cannot be used, please ignore it
			#			local serviceName
			#			serviceName=$(jq -r .inbounds[0].streamSettings.grpcSettings.serviceName ${configPath}06_VLESS_gRPC_inbounds.json)
			jq .inbounds[0].settings.clients ${configPath}06_VLESS_gRPC_inbounds.json | jq -c '. []' | while read -r user; do

				local email=
				email=$(echo "${user}" | jq -r .email)

				EchoContent skyBlue " n -->Account: ${email}"
				echo
				defaultBase64Code vlessgrpc "${email}" "$(echo "${user}" | jq -r .id)"
			done
		fi
	fi

	# trojan tcp
	if echo ${currentInstallProtocolType} | grep -q 4; then
		echoContent skyBlue "\n================================== Trojan TLS  ==================================\n"
		jq .inbounds[0].settings.clients ${configPath}04_trojan_TCP_inbounds.json | jq -c '. []' | while read -r user; do
			local email=
			email=$(echo "${user}" | jq -r .email)
			EchoContent skyBlue " n -->Account: ${email}"

			defaultBase64Code trojan "${email}" "$(echo "${user}" | jq -r .password)"
		done
	fi

	if echo ${currentInstallProtocolType} | grep -q 2; then
		echoContent skyBlue "\n================================ Trojan gRPC TLS  ================================\n"
		EchoContent red " n -->gRPC is in the testing stage and may not be compatible with the client you are using. If it cannot be used, please ignore it
		jq .inbounds[0].settings.clients ${configPath}04_trojan_gRPC_inbounds.json | jq -c '. []' | while read -r user; do
			local email=
			email=$(echo "${user}" | jq -r .email)

			EchoContent skyBlue " n -->Account: ${email}"
			echo
			defaultBase64Code trojangrpc "${email}" "$(echo "${user}" | jq -r .password)"
		done
	fi
	if echo ${currentInstallProtocolType} | grep -q 6; then
		echoContent skyBlue "\n================================ Hysteria TLS  ================================\n"
		EchoContent red " n -->Hysteria's speed depends on the local network environment, and if used by QoS, the experience will be very poor. IDC may also consider it an attack, please use it with caution

		jq .auth.config ${hysteriaConfigPath}config.json | jq -r '. []' | while read -r user; do
			local defaultUser=
			local uuidType=
			uuidType=".id"

			if [[ "${frontingType}" == "02_trojan_TCP_inbounds" ]]; then 			uuidType=".password"
			fi

			defaultUser=$(jq '.inbounds[0].settings.clients[]|select('${uuidType}'== "'"${user}"'")' ${configPath}${frontingType}.json)
			local email=
			email=$(echo "${defaultUser}" | jq -r .email)

			if [[ -n ${defaultUser} ]]; then
				EchoContent skyBlue " n -->Account: ${email}"
				echo
				defaultBase64Code hysteria "${email}" "${user}"
			fi

		done

	fi

	if [[ -z ${show} ]]; then
		EchoContent red "-->Not installed"
	fi
}
#Remove nginx 302 configuration
removeNginx302() {
	local count=0
	grep -n "return 302" <"/etc/nginx/conf.d/alone.conf" | while read -r line; do

		if ! echo "${line}" | grep -q "request_uri"; then 		local removeIndex=
			removeIndex=$(echo "${line}" | awk -F "[:]" '{print $1}')
			removeIndex=$((removeIndex + count))
			sed -i "${removeIndex}d" /etc/nginx/conf.d/alone.conf
			count=$((count - 1))
		fi
	done
}

#Check if 302 was successful
checkNginx302() {
	local domain302Status=
	domain302Status=$(curl -s "https://${currentHost}")
	if echo "${domain302Status}" | grep -q "302"; then 	local domain302Result=
		domain302Result=$(curl -L -s "https://${currentHost}")
		if [[ -n "${domain302Result}" ]]; then
			EchoContent green "-->302 Redirection successfully set"
			exit 0
		fi
	fi
	EchoContent red "-->302 redirect setting failed, please carefully check if it is the same as the example"
	backupNginxConfig restoreBackup
}

#Backup and restore nginx files
backupNginxConfig() {
	if [[ "$1" == "backup" ]]; then
		cp /etc/nginx/conf.d/alone.conf /etc/v2ray-agent/alone_backup.conf
		EchoContent green "-->Successfully backed up nginx configuration file"
	fi

	if [[ "$1" == "restoreBackup" ]] && [[ -f "/etc/v2ray-agent/alone_backup.conf" ]]; then
		cp /etc/v2ray-agent/alone_backup.conf /etc/nginx/conf.d/alone.conf
		EchoContent green "-->Successfully restored and backed up nginx configuration file"
		rm /etc/v2ray-agent/alone_backup.conf
	fi

}
#Add 302 configuration
addNginx302() {
	#	local line302Result=
	#	line302Result=$(| tail -n 1)
	local count=1
	grep -n "Strict-Transport-Security" <"/etc/nginx/conf.d/alone.conf" | while read -r line; do
		if [[ -n "${line}" ]]; then
			local insertIndex=
			insertIndex="$(echo "${line}" | awk -F "[:]" '{print $1}')"
			insertIndex=$((insertIndex + count))
			sed "${insertIndex}i return 302 '$1';" /etc/nginx/conf.d/alone.conf >/etc/nginx/conf.d/tmpfile && mv /etc/nginx/conf.d/tmpfile /etc/nginx/conf.d/alone.conf
			count=$((count + 1))
		else
			EchoContent red "-->302 failed to add"
			backupNginxConfig restoreBackup
		fi

	done
}

#Update camouflage station
updateNginxBlog() {
	EchoContent skyBlue " n Progress $1/${totalProgress}: Change masquerade site"
	echoContent red "============================================================== "
	EchoContent yellow "# To customize, please manually copy the template file to/usr/share/nginx/html  n
	EchoContent yellow "1. Novice guidance"
	EchoContent yellow "2. Game website"
	EchoContent yellow "3. Personal Blog 01"
	EchoContent yellow "4. Enterprise website"
	EchoContent yellow "5. Unlock encrypted music file template[ https://github.com/ix64/unlock-music ]"
	echoContent yellow "6.mikutap[ https://github.com/HFIProgramming/mikutap ]"
	EchoContent yellow "7. Enterprise Station 02"
	EchoContent yellow "8. Personal Blog 02"
	EchoContent yellow "9.404 Auto jump to Baidu"
	EchoContent yellow "10.302 Redirect website"
	echoContent red "============================================================== "
	Read - r - p "Please select:" selectInstallNginxBlogType

	if [[ "${selectInstallNginxBlogType}" == "10" ]]; then
		echoContent red "\n============================================================== "
		EchoContent yellow "Redirection has a higher priority. If the camouflage site is changed after configuring 302, the camouflage site under the root route will not work
		EchoContent yellow "If you want to disguise the site's implementation function, you need to delete the 302 redirect configuration  n
		EchoContent yellow "1. Add"
		EchoContent yellow "2. Delete"
		echoContent red "============================================================== "
		Read - r - p "Please select:" redirectStatus

		if [[ "${redirectStatus}" == "1" ]]; then
			backupNginxConfig backup
			Please enter the domain name to redirect, for example https://www.baidu.com: " redirectDomain
			removeNginx302
			addNginx302 "${redirectDomain}"
			handleNginx stop
			handleNginx start
			if [[ -z $(pgrep -f nginx) ]]; then
				backupNginxConfig restoreBackup
				handleNginx start
				exit 0
			fi
			checkNginx302
			exit 0
		fi
		if [[ "${redirectStatus}" == "2" ]]; then
			removeNginx302
			EchoContent green "-->Successfully removed 302 redirection"
			exit 0
		fi
	fi
	if [[ "${selectInstallNginxBlogType}" =~ ^[1-9]$ ]]; then
		rm -rf /usr/share/nginx/*
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /usr/share/nginx " https://raw.githubusercontent.com/reeceyng/v2ray-agent/master/fodder/blog/unable/html ${selectInstallNginxBlogType}.zip" >/dev/null
		else
			wget -c -P /usr/share/nginx " https://raw.githubusercontent.com/reeceyng/v2ray-agent/master/fodder/blog/unable/html ${selectInstallNginxBlogType}.zip" >/dev/null
		fi

		unzip -o "/usr/share/nginx/html${selectInstallNginxBlogType}.zip" -d /usr/share/nginx/html >/dev/null
		rm -f "/usr/share/nginx/html${selectInstallNginxBlogType}.zip*"
		EchoContent green "-->Successfully replaced pseudo station"
	else
		EchoContent red "-->Selection error, please reselect"
		updateNginxBlog
	fi
}

#Add New Port
addCorePort() {
	EchoContent skyBlue " nFunction 1/${totalProgress}: Add new port"
	echoContent red "\n============================================================== "
	EchoContent yellow "# Precautions  n
	EchoContent yellow "supports batch addition"
	EchoContent yellow "does not affect the use of the default port"
	EchoContent yellow "When viewing an account, only the account on the default port will be displayed
	EchoContent yellow "Special characters are not allowed, pay attention to the format of commas"
	EchoContent yellow "Input example: 205320832087  n

	EchoContent yellow "1. Add Port"
	EchoContent yellow "2. Delete Port"
	echoContent red "============================================================== "
	Read - r - p "Please select:" selectNewPortType
	if [[ "${selectNewPortType}" == "1" ]]; then
		Read - r - p "Please enter the port number:" newPort
		Read - r - p "Please enter the default port number, which will also change the subscription port and node port. [Enter] defaults to 443:" defaultPort

		if [[ -n "${defaultPort}" ]]; then
			rm -rf "$(find ${configPath}* | grep "default")"
		fi

		if [[ -n "${newPort}" ]]; then

			while read -r port; do
				rm -rf "$(find ${configPath}* | grep "${port}")"

				local fileName=
				if [[ -n "${defaultPort}" && "${port}" == "${defaultPort}" ]]; then 				fileName="${configPath}02_dokodemodoor_inbounds_${port}_default.json"
				else
					fileName="${configPath}02_dokodemodoor_inbounds_${port}.json"
				fi

				#Open Port
				allowPort "${port}"

				local settingsPort=443
				if [[ -n "${customPort}" ]]; then 				settingsPort=${customPort}
				fi

				cat <<EOF >"${fileName}"
{
  "inbounds": [
	{
	  "listen": "0.0.0.0",
	  "port": ${port},
	  "protocol": "dokodemo-door",
	  "settings": {
		"address": "127.0.0.1",
		"port": ${settingsPort},
		"network": "tcp",
		"followRedirect": false
	  },
	  "tag": "dokodemo-door-newPort-${port}"
	}
  ]
}
EOF
			done < <(echo "${newPort}" | tr ',' '\n')

			EchoContent green "-->Successfully added"
			reloadCore
		fi
	elif [[ "${selectNewPortType}" == "2" ]]; then

		find ${configPath} -name "*dokodemodoor*" | awk -F "[c][o][n][f][/]" '{print ""NR""":"$2}'
		Read - r - p "Please enter the port number to delete:" portIndex
		local dokoConfig
		dokoConfig=$(find ${configPath} -name "*dokodemodoor*" | awk -F "[c][o][n][f][/]" '{print ""NR""":"$2}' | grep "${portIndex}:")
		if [[ -n "${dokoConfig}" ]]; then
			rm "${configPath}/$(echo "${dokoConfig}" | awk -F "[:]" '{print $2}')"
			reloadCore
		else
			EchoContent yellow " n -->Number input error, please reselect"
			addCorePort
		fi
	fi
}

#Uninstall Script
unInstall() {
	Read - r - p "Are you sure you want to uninstall the installation content? [y/n]:" uninstallStatus
	if [[ "${unInstallStatus}" != "y" ]]; then
		EchoContent green "-->Abort uninstallation"
		menu
		exit 0
	fi

	handleNginx stop
	if [[ -z $(pgrep -f "nginx") ]]; then
		EchoContent green "-->Stopping Nginx succeeded"
	fi

	if [[ "${coreInstallType}" == "1" ]]; then
		handleXray stop
		rm -rf /etc/systemd/system/xray.service
		EchoContent green "-->Delete Xray startup completion"

	elif [[ "${coreInstallType}" == "2" ]]; then

		handleV2Ray stop
		rm -rf /etc/systemd/system/v2ray.service
		EchoContent green "-->Delete V2Ray startup completion"

	fi

	if [[ -z "${hysteriaConfigPath}" ]]; then
		handleHysteria stop
		rm -rf /etc/systemd/system/hysteria.service
		EchoContent green "-->Delete Hysteria startup completion"
	fi

	if [[ -f "/root/.acme.sh/acme.sh.env" ]] && grep -q 'acme.sh.env' </root/.bashrc; then
		sed -i 's/. "\/root\/.acme.sh\/acme.sh.env"//g' "$(grep '. "/root/.acme.sh/acme.sh.env"' -rl /root/.bashrc)"
	fi
	rm -rf /root/.acme.sh
	EchoContent green "-->Delete acme. sh completed"

	rm -rf /tmp/v2ray-agent-tls/*
	if [[ -d "/etc/v2ray-agent/tls" ]] && [[ -n $(find /etc/v2ray-agent/tls/-name "*.key") ]] && [[ -n $(find /etc/v2ray-agent/tls/-name "*.crt") ]]; then
		mv /etc/v2ray-agent/tls /tmp/v2ray-agent-tls
		if [[ -n $(find /tmp/v2ray-agent-tls -name '*.key') ]]; then
			EchoContent yellow "-->Successfully backed up the certificate. Please note to keep it. [/tmp/v2ray agent tls]
		fi
	fi

	rm -rf /etc/v2ray-agent
	rm -rf ${nginxConfigPath}alone.conf

	if [[ -d "/usr/share/nginx/html" && -f "/usr/share/nginx/html/check" ]]; then
		rm -rf /usr/share/nginx/html
		EchoContent green "-->Delete disguised website completed"
	fi

	rm -rf /usr/bin/vasma
	rm -rf /usr/sbin/vasma
	EchoContent green "-->Uninstall shortcut completed"
	EchoContent green "-->Uninstalling v2ray agent script completed"
}

#updateGeoSite

#Modifying V2Ray CDN nodes
updateV2RayCDN() {

	#Todo refactoring this method
	EchoContent skyBlue " n Progress $1/${totalProgress}: Modifying CDN nodes"

	if [[ -n "${currentAdd}" ]]; then
		echoContent red "============================================================== "
		echoContent yellow "1.CNAME www.digitalocean.com"
		echoContent yellow "2.CNAME www.cloudflare.com"
		echoContent yellow "3.CNAME hostmonit.com"
		EchoContent yellow "4. Manual input"
		echoContent red "============================================================== "
		Read - r - p "Please select:" selectCDNType
		case ${selectCDNType} in
		1)
			setDomain="www.digitalocean.com"
			;;
		2)
			setDomain="www.cloudflare.com"
			;;
		3)
			setDomain="hostmonit.com"
			;;
		4)
			Read - r - p "Please enter the desired custom CDN IP or domain name:" setDomain
			;;
		esac

		if [[ -n ${setDomain} ]]; then
			if [[ -n "${currentAdd}" ]]; then
				sed -i "s/\"${currentAdd}\"/\"${setDomain}\"/g" "$(grep "${currentAdd}" -rl ${configPath}${frontingType}.json)"
			fi
			if [[ $(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json) == "${setDomain}" ]]; then
				EchoContent green "-->CDN modification successful"
				reloadCore
			else
				EchoContent red "-->Failed to modify CDN"
			fi
		fi
	else
		EchoContent red "-->No available types installed"
	fi
}

#ManageUser User Management
manageUser() {
	EchoContent skyBlue " n Progress $1/${totalProgress}: Multi User Management"
	echoContent skyBlue "-----------------------------------------------------"
	EchoContent yellow "1. Add user"
	EchoContent yellow "2. Delete user"
	echoContent skyBlue "-----------------------------------------------------"
	Read - r - p "Please select:" manageUserType
	if [[ "${manageUserType}" == "1" ]]; then
		addUser
	elif [[ "${manageUserType}" == "2" ]]; then
		removeUser
	else
		EchoContent red "-->Selection error"
	fi
}

#Customize uuid
customUUID() {
	#	Read - r - p "Do you want to customize UUID? [y/n]:" customUUIDStatus
	#	echo
	#	if [[ "${customUUIDStatus}" == "y" ]]; then
	Read - r - p "Please enter a valid UUID, [Enter] Random UUID:" currentCustomimUUID
	echo
	if [[ -z "${currentCustomUUID}" ]]; then
		#EchoContent red "-->UUID cannot be empty"
		currentCustomUUID=$(${ctlPath} uuid)
		echoContent yellow "uuid:${currentCustomUUID}\n"

	else
		jq -r -c '.inbounds[0].settings.clients[].id' ${configPath}${frontingType}.json | while read -r line; do
			if [[ "${line}" == "${currentCustomUUID}" ]]; then
				echo >/tmp/v2ray-agent
			fi
		done
		if [[ -f "/tmp/v2ray-agent" && -n $(cat /tmp/v2ray-agent) ]]; then
			EchoContent red "-->UUID cannot be repeated"
			rm /tmp/v2ray-agent
			exit 0
		fi
	fi
	#	fi
}

#Custom email
customUserEmail() {
	#	Read - r - p "Do you want to customize the email? [y/n]:" customEmailStatus
	#	echo
	#	if [[ "${customEmailStatus}" == "y" ]]; then
	Read - r - p "Please enter a valid email, [Enter] random email:" currentCustomimEmail
	echo
	if [[ -z "${currentCustomEmail}" ]]; then 	currentCustomEmail="${currentHost}_${currentCustomUUID}"
		echoContent yellow "email: ${currentCustomEmail}\n"
		#		EchoContent red "-->Email cannot be empty"
	else
		jq -r -c '.inbounds[0].settings.clients[].email' ${configPath}${frontingType}.json | while read -r line; do
			if [[ "${line}" == "${currentCustomEmail}" ]]; then
				echo >/tmp/v2ray-agent
			fi
		done
		if [[ -f "/tmp/v2ray-agent" && -n $(cat /tmp/v2ray-agent) ]]; then
			EchoContent red "-->Email cannot be repeated"
			rm /tmp/v2ray-agent
			exit 0
		fi
	fi
	#	fi
}

#Add User
addUser() {

	EchoContent yellow "After adding a new user, you need to review the subscription again"
	Read - r - p "Please enter the number of users to add:" userNum
	echo
	if [[ -z ${userNum} || ${userNum} -le 0 ]]; then
		EchoContent red "-->Input error, please re-enter"
		exit 0
	fi

	#Generate Users
	if [[ "${userNum}" == "1" ]]; then
		customUUID
		customUserEmail
	fi

	while [[ ${userNum} -gt 0 ]]; do
		local users=
		((userNum--)) || true
		if [[ -n "${currentCustomUUID}" ]]; then 		uuid=${currentCustomUUID}
		else
			uuid=$(${ctlPath} uuid)
		fi

		if [[ -n "${currentCustomEmail}" ]]; then 		email=${currentCustomEmail}
		else
			email=${currentHost}_$ {uuid}
		fi

		#	Compatible with v2ray core
		users="{\"id\":\"${uuid}\",\"flow\":\"xtls-rprx-direct\",\"email\":\"${email}\",\"alterId\":0}"

		if [[ "${coreInstallType}" == "2" ]]; then
			users="{\"id\":\"${uuid}\",\"email\":\"${email}\",\"alterId\":0}"
		fi

		if [[ "${coreInstallType}" == "3" ]]; then
			users="{\"id\":\"${uuid}\",\"flow\":\"xtls-rprx-vision\",\"email\":\"${email}\",\"alterId\":0}"
		fi

		if echo ${currentInstallProtocolType} | grep -q 0; then 		local vlessUsers="${users//\,\"alterId\":0/}"

			local vlessTcpResult
			vlessTcpResult=$(jq -r ".inbounds[0].settings.clients +=[${vlessUsers}]" ${configPath}${frontingType}.json)
			echo "${vlessTcpResult}" | jq . >$ {configPath}${frontingType}.json
		fi

		if echo ${currentInstallProtocolType} | grep -q trojan; then 		local trojanXTLSUsers="${users//\,\"alterId\":0/}"
			trojanXTLSUsers=${trojanXTLSUsers//"id"/"password"}

			local trojanXTLSResult
			trojanXTLSResult=$(jq -r ".inbounds[0].settings.clients +=[${trojanXTLSUsers}]" ${configPath}${frontingType}.json)
			echo "${trojanXTLSResult}" | jq . >$ {configPath}${frontingType}.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 1; then 		local vlessUsers="${users//\,\"alterId\":0/}"
			vlessUsers="${vlessUsers//\"flow\":\"xtls-rprx-direct\"\,/}"
			local vlessWsResult
			vlessWsResult=$(jq -r ".inbounds[0].settings.clients +=[${vlessUsers}]" ${configPath}03_VLESS_WS_inbounds.json)
			echo "${vlessWsResult}" | jq . >$ {configPath}03_VLESS_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 2; then 		local trojangRPCUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
			trojangRPCUsers="${trojangRPCUsers//\,\"alterId\":0/}"
			trojangRPCUsers=${trojangRPCUsers//"id"/"password"}

			local trojangRPCResult
			trojangRPCResult=$(jq -r ".inbounds[0].settings.clients +=[${trojangRPCUsers}]" ${configPath}04_trojan_gRPC_inbounds.json)
			echo "${trojangRPCResult}" | jq . >$ {configPath}04_trojan_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 3; then 		local vmessUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"

			local vmessWsResult
			vmessWsResult=$(jq -r ".inbounds[0].settings.clients +=[${vmessUsers}]" ${configPath}05_VMess_WS_inbounds.json)
			echo "${vmessWsResult}" | jq . >$ {configPath}05_VMess_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 5; then
			local vlessGRPCUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
			vlessGRPCUsers="${vlessGRPCUsers//\,\"alterId\":0/}"

			local vlessGRPCResult
			vlessGRPCResult=$(jq -r ".inbounds[0].settings.clients +=[${vlessGRPCUsers}]" ${configPath}06_VLESS_gRPC_inbounds.json)
			echo "${vlessGRPCResult}" | jq . >$ {configPath}06_VLESS_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 4; then 		local trojanUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
			trojanUsers="${trojanUsers//id/password}"
			trojanUsers="${trojanUsers//\,\"alterId\":0/}"

			local trojanTCPResult
			trojanTCPResult=$(jq -r ".inbounds[0].settings.clients +=[${trojanUsers}]" ${configPath}04_trojan_TCP_inbounds.json)
			echo "${trojanTCPResult}" | jq . >$ {configPath}04_trojan_TCP_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 6; then 		local hysteriaResult
			hysteriaResult=$(jq -r ".auth.config +=[\"${uuid}\"]" ${hysteriaConfigPath}config.json)
			echo "${hysteriaResult}" | jq . >$ {hysteriaConfigPath}config.json
		fi
	done

	reloadCore
	EchoContent green "-->Add completed"
	manageAccount 1
}

#Remove User
removeUser() {

	if echo ${currentInstallProtocolType} | grep -q 0 || echo ${currentInstallProtocolType} | grep -q trojan; then
		jq -r -c .inbounds[0].settings.clients[].email ${configPath}${frontingType}.json | awk '{print NR""":"$0}'
		Read - r - p "Please select the user number to delete [only supports single deletion]:" delUserIndex
		if [[ $(jq -r '.inbounds[0].settings.clients|length' ${configPath}${frontingType}.json) -lt ${delUserIndex} ]]; then
			EchoContent red "-->Selection error"
		else
			delUserIndex=$((delUserIndex - 1))
			local vlessTcpResult
			vlessTcpResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}${frontingType}.json)
			echo "${vlessTcpResult}" | jq . >$ {configPath}${frontingType}.json
		fi
	fi
	if [[ -n "${delUserIndex}" ]]; then
		if echo ${currentInstallProtocolType} | grep -q 1; then 		local vlessWSResult
			vlessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}03_VLESS_WS_inbounds.json)
			echo "${vlessWSResult}" | jq . >$ {configPath}03_VLESS_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 2; then 		local trojangRPCUsers
			trojangRPCUsers=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_gRPC_inbounds.json)
			echo "${trojangRPCUsers}" | jq . >$ {configPath}04_trojan_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 3; then 		local vmessWSResult
			vmessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}05_VMess_WS_inbounds.json)
			echo "${vmessWSResult}" | jq . >$ {configPath}05_VMess_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 5; then 		local vlessGRPCResult
			vlessGRPCResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}06_VLESS_gRPC_inbounds.json)
			echo "${vlessGRPCResult}" | jq . >$ {configPath}06_VLESS_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 4; then 		local trojanTCPResult
			trojanTCPResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_TCP_inbounds.json)
			echo "${trojanTCPResult}" | jq . >$ {configPath}04_trojan_TCP_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 6; then 		local hysteriaResult
			hysteriaResult=$(jq -r 'del(.auth.config['${delUserIndex}'])' ${hysteriaConfigPath}config.json)
			echo "${hysteriaResult}" | jq . >$ {hysteriaConfigPath}config.json
		fi

		reloadCore
	fi
	manageAccount 1
}
#Update Script
updateV2RayAgent() {
	local scriptType=
	echoContent red "\n============================================================== "
	EchoContent yellow "1. Upgrade to the latest stable version"
	EchoContent yellow "2. Upgrade to the latest development version"
	echoContent red "============================================================== "
	Read - r - p "Please select:" selectScriptType
	if [[ "${selectScriptType}" == "1" ]]; then 	scriptType="master"
	elif [[ "${selectScriptType}" == "2" ]]; then 	scriptType="dev"
	else
	updateV2RayAgent
	fi

	EchoContent skyBlue " n Progress $1/${totalProgress}: Update v2ray agent script"
	rm -rf /etc/v2ray-agent/install.sh
	if wget --help | grep -q show-progress; then
		wget -c -q --show-progress -P /etc/v2ray-agent/-N --no-check-certificate " https://raw.githubusercontent.com/reeceyng/v2ray-agent/${scriptType}/install.sh"
	else
		wget -c -q -P /etc/v2ray-agent/-N --no-check-certificate " https://raw.githubusercontent.com/reeceyng/v2ray-agent/${scriptType}/install.sh"
	fi

	sudo chmod 700 /etc/v2ray-agent/install.sh
	local version
	Version=$(grep 'Current version: v' "/etc/v2ray agent/install. sh" | awk - F "[v]" {print $2} '| tail - n+2 | head - n 1 | awk - F "["] "{print $1}')

	EchoContent green " n -->Update completed"
	EchoContent yellow "-->Please manually execute [vasma] to open the script"
	EchoContent green "-->Current version: ${version}  n
	If the update is not successful, please manually execute the following command  n
	echoContent skyBlue "wget -P /root -N --no-check-certificate https://raw.githubusercontent.com/reeceyng/v2ray-agent/${scriptType}/install.sh && chmod 700 /root/install.sh && /root/install.sh"
	echo
	exit 0
}

#Firewall
handleFirewall() {
	if systemctl status ufw 2>/dev/null | grep -q "active (exited)" && [[ "$1" == "stop" ]]; then
		systemctl stop ufw >/dev/null 2>&1
		systemctl disable ufw >/dev/null 2>&1
		EchoContent green "-->ufw closed successfully"

	fi

	if systemctl status firewalld 2>/dev/null | grep -q "active (running)" && [[ "$1" == "stop" ]]; then
		systemctl stop firewalld >/dev/null 2>&1
		systemctl disable firewalld >/dev/null 2>&1
		EchoContent green "-->Firewalld closed successfully"
	fi
}

#Install BBR
bbrInstall() {
	echoContent red "\n============================================================== "
	EchoContent green "A mature work of [ylx2016] for BBR and DD scripts, address:[ https://github.com/ylx2016/Linux-NetSpeed ]Please be familiar with“
	EchoContent yellow "1. Installation script [recommended original BBR+FQ]
	EchoContent yellow "2. Fallback to home directory"
	echoContent red "============================================================== "
	Read - r - p "Please select:" installBBRStatus
	if [[ "${installBBRStatus}" == "1" ]]; then
		wget -N --no-check-certificate " https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh " && chmod +x tcp.sh && ./tcp.sh
	else
		menu
	fi
}

#View and check logs
checkLog() {
	if [[ -z ${configPath} ]]; then
		EchoContent red "-->No installation directory detected, please execute the script to install the content"
	fi
	local logStatus=false
	if grep -q "access" ${configPath}00_log.json; then
		logStatus=true
	fi

	EchoContent skyBlue " nFunction $1/${totalProgress}: View logs"
	echoContent red "\n============================================================== "
	EchoContent yellow "# It is recommended to open access logs only during debugging  n

	if [[ "${logStatus}" == "false" ]]; then
		EchoContent yellow "1. Open access log"
	else
		EchoContent yellow "1. Close access log"
	fi

	EchoContent yellow "2. Listen to access logs"
	EchoContent yellow "3. Listen for error logs"
	EchoContent yellow "4. View certificate timed task log"
	EchoContent yellow "5. View certificate installation log"
	EchoContent yellow "6. Clear Log"
	echoContent red "============================================================== "

	Read - r - p "Please select:" selectAccessLogType
	local configPathLog=${configPath//conf\//}

	case ${selectAccessLogType} in
	1)
		if [[ "${logStatus}" == "false" ]]; then
			cat <<EOF >${configPath}00_log.json
{
  "log": {
  	"access":"${configPathLog}access.log",
    "error": "${configPathLog}error.log",
    "loglevel": "debug"
  }
}
EOF
		elif [[ "${logStatus}" == "true" ]]; then
			cat <<EOF >${configPath}00_log.json
{
  "log": {
    "error": "${configPathLog}error.log",
    "loglevel": "warning"
  }
}
EOF
		fi
		reloadCore
		checkLog 1
		;;
	2)
		tail -f ${configPathLog}access.log
		;;
	3)
		tail -f ${configPathLog}error.log
		;;
	4)
		tail -n 100 /etc/v2ray-agent/crontab_tls.log
		;;
	5)
		tail -n 100 /etc/v2ray-agent/tls/acme.log
		;;
	6)
		echo >${configPathLog}access.log
		echo >${configPathLog}error.log
		;;
	esac
}

#Script Shortcut
aliasInstall() {

	If [[- f "$HOME/install. sh"]&&[- d "/etc/v2ray agent"]&&grep<"$HOME/install. sh" - q "Author: mack a"; then
		mv "$HOME/install.sh" /etc/v2ray-agent/install.sh
		local vasmaType=
		if [[ -d "/usr/bin/" ]]; then
			if [[ ! -f "/usr/bin/vasma" ]]; then
				ln -s /etc/v2ray-agent/install.sh /usr/bin/vasma
				chmod 700 /usr/bin/vasma
				vasmaType=true
			fi

			rm -rf "$HOME/install.sh"
		elif [[ -d "/usr/sbin" ]]; then
			if [[ ! -f "/usr/sbin/vasma" ]]; then
				ln -s /etc/v2ray-agent/install.sh /usr/sbin/vasma
				chmod 700 /usr/sbin/vasma
				vasmaType=true
			fi
			rm -rf "$HOME/install.sh"
		fi
		if [[ "${vasmaType}" == "true" ]]; then
			EchoContent green "Shortcut created successfully, can execute [vasma] to reopen the script"
		fi
	fi
}

#Check ipv6, ipv4
checkIPv6() {
	# pingIPv6=$(ping6 -c 1 www.google.com | sed '2{s/[^(]*(//;s/).*//;q;}' | tail -n +2)
	pingIPv6=$(ping6 -c 1 www.google.com | sed -n '1p' | sed 's/.*(//g;s/).*//g')

	if [[ -z "${pingIPv6}" ]]; then
		EchoContent red "-->does not support ipv6"
		exit 0
	fi
}

#Ipv6 diversion
ipv6Routing() {
	if [[ -z "${configPath}" ]]; then
		EchoContent red "-->Not installed, please use script to install"
		menu
		exit 0
	fi

	checkIPv6
	EchoContent skyBlue " nFunction 1/${totalProgress}: IPv6 redirection"
	echoContent red "\n============================================================== "
	EchoContent yellow "1. Add domain name"
	EchoContent yellow "2. Uninstalling IPv6 redirection"
	echoContent red "============================================================== "
	Read - r - p "Please select:" ipv6Status
	if [[ "${ipv6Status}" == "1" ]]; then
		echoContent red "============================================================== "
		EchoContent yellow "# Precautions  n
		EchoContent yellow "1. The rule only supports predefined domain name lists[ https://github.com/v2fly/domain-list-community ]"
		EchoContent yellow "2. Detailed documentation[ https://www.v2fly.org/config/routing.html ]"
		EchoContent yellow "3. If the kernel fails to start, please check the domain name and add it again
		EchoContent yellow "4. Special characters are not allowed, pay attention to the format of commas"
		EchoContent yellow "5. Every addition is a re addition, and the last domain name will not be retained"
		EchoContent yellow "6. It is strongly recommended to block domestic websites by entering [cn] below
		EchoContent yellow "7. Input examples: Google, YouTube, Facebook, cn  n
		Read - r - p "Please enter the domain name according to the above example:" domainList

		if [[ -f "${configPath}09_routing.json" ]]; then

			unInstallRouting IPv6-out outboundTag

			routing=$(jq -r ".routing.rules +=[{\"type\":\"field\",\"domain\":[\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"IPv6-out\"}]" ${configPath}09_routing.json)

			echo "${routing}" | jq . >$ {configPath}09_routing.json

		else
			cat <<EOF >"${configPath}09_routing.json"
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "domain": [
            	"geosite:${domainList//,/\",\"geosite:}"
            ],
            "outboundTag": "IPv6-out"
          }
        ]
  }
}
EOF
		fi

		unInstallOutbounds IPv6-out

		outbounds=$(jq -r '.outbounds +=[{"protocol":"freedom","settings":{"domainStrategy":"UseIPv6"},"tag":"IPv6-out"}]' ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >$ {configPath}10_ipv4_outbounds.json

		EchoContent green "-->Successfully added"

	elif [[ "${ipv6Status}" == "2" ]]; then

		unInstallRouting IPv6-out outboundTag

		unInstallOutbounds IPv6-out

		EchoContent green "-->IPv6 offloading successfully"
	else
		EchoContent red "-->Selection error"
		exit 0
	fi

	reloadCore
}

#BT Download Management
btTools() {
	if [[ -z "${configPath}" ]]; then
		EchoContent red "-->Not installed, please use script to install"
		menu
		exit 0
	fi

	EchoContent skyBlue " nFunction 1/${totalProgress}: bt Download Management"
	echoContent red "\n============================================================== "

	if [[ -f ${configPath}09_routing.json ]] && grep -q bittorrent <${configPath}09_routing.json; then
		EchoContent yellow "Current state: Disabled"
	else
		EchoContent yellow "Current state: not disabled"
	fi

	EchoContent yellow "1. Disabled"
	EchoContent yellow "2. Open"
	echoContent red "============================================================== "
	Read - r - p "Please select:" btStatus
	if [[ "${btStatus}" == "1" ]]; then

		if [[ -f "${configPath}09_routing.json" ]]; then

			unInstallRouting blackhole-out outboundTag

			routing=$(jq -r '.routing.rules +=[{"type":"field","outboundTag":"blackhole-out","protocol":["bittorrent"]}]' ${configPath}09_routing.json)

			echo "${routing}" | jq . >$ {configPath}09_routing.json

		else
			cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "outboundTag": "blackhole-out",
            "protocol": [ "bittorrent" ]
          }
        ]
  }
}
EOF
		fi

		installSniffing

		unInstallOutbounds blackhole-out

		outbounds=$(jq -r '.outbounds +=[{"protocol":"blackhole","tag":"blackhole-out"}]' ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >$ {configPath}10_ipv4_outbounds.json

		EchoContent green "-->BT download disabled successfully"

	elif [[ "${btStatus}" == "2" ]]; then

		unInstallSniffing

		unInstallRouting blackhole-out outboundTag bittorrent

		#		unInstallOutbounds blackhole-out

		EchoContent green "-->BT download opened successfully"
	else
		EchoContent red "-->Selection error"
		exit 0
	fi

	reloadCore
}

#Domain blacklist
blacklist() {
	if [[ -z "${configPath}" ]]; then
		EchoContent red "-->Not installed, please use script to install"
		menu
		exit 0
	fi

	EchoContent skyBlue " n Progress $1/${totalProgress}: Domain blacklist"
	echoContent red "\n============================================================== "
	EchoContent yellow "1. Add domain name"
	EchoContent yellow "2. Remove blacklist"
	echoContent red "============================================================== "
	Read - r - p "Please select:" blacklistStatus
	if [[ "${blacklistStatus}" == "1" ]]; then
		echoContent red "============================================================== "
		EchoContent yellow "# Precautions  n
		EchoContent yellow "1. The rule only supports predefined domain name lists[ https://github.com/v2fly/domain-list-community ]"
		EchoContent yellow "2. Detailed documentation[ https://www.v2fly.org/config/routing.html ]"
		EchoContent yellow "3. If the kernel fails to start, please check the domain name and add it again
		EchoContent yellow "4. Special characters are not allowed, pay attention to the format of commas"
		EchoContent yellow "5. Every addition is a re addition, and the last domain name will not be retained"
		EchoContent yellow "6. Input example: speedtest, Facebook  n
		Read - r - p "Please enter the domain name according to the above example:" domainList

		if [[ -f "${configPath}09_routing.json" ]]; then
			unInstallRouting blackhole-out outboundTag

			routing=$(jq -r ".routing.rules +=[{\"type\":\"field\",\"domain\":[\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"blackhole-out\"}]" ${configPath}09_routing.json)

			echo "${routing}" | jq . >$ {configPath}09_routing.json

		else
			cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "domain": [
            	"geosite:${domainList//,/\",\"geosite:}"
            ],
            "outboundTag": "blackhole-out"
          }
        ]
  }
}
EOF
		fi

		EchoContent green "-->Successfully added"

	elif [[ "${blacklistStatus}" == "2" ]]; then

		unInstallRouting blackhole-out outboundTag

		EchoContent green "-->Domain blacklist successfully deleted"
	else
		EchoContent red "-->Selection error"
		exit 0
	fi
	reloadCore
}

#Uninstalling Routing based on tag
unInstallRouting() {
	local tag=$1
	local type=$2
	local protocol=$3

	if [[ -f "${configPath}09_routing.json" ]]; then
		local routing
		if grep -q "${tag}" ${configPath}09_routing.json && grep -q "${type}" ${configPath}09_routing.json; then

			jq -c .routing.rules[] ${configPath}09_routing.json | while read -r line; do
				local index=$((index + 1))
				local delStatus=0
				if [[ "${type}" == "outboundTag" ]] && echo "${line}" | jq .outboundTag | grep -q "${tag}"; then 				delStatus=1
				elif [[ "${type}" == "inboundTag" ]] && echo "${line}" | jq .inboundTag | grep -q "${tag}"; then 				delStatus=1
				fi

				if [[ -n ${protocol} ]] && echo "${line}" | jq .protocol | grep -q "${protocol}"; then 				delStatus=1
				elif [[ -z ${protocol} ]] && [[ $(echo "${line}" | jq .protocol) != "null" ]]; then
					delStatus=0
				fi

				if [[ ${delStatus} ==1 ]]; then	 				routing=$(jq -r 'del(.routing.rules['"$(("${index}" - 1))"'])' ${configPath}09_routing.json)
					echo "${routing}" | jq . >$ {configPath}09_routing.json
				fi
			done
		fi
	fi
}

#Unload outbound based on tag
unInstallOutbounds() {
	local tag=$1

	if grep -q "${tag}" ${configPath}10_ipv4_outbounds.json; then
		local ipv6OutIndex
		ipv6OutIndex=$(jq .outbounds[].tag ${configPath}10_ipv4_outbounds.json | awk '{print ""NR""":"$0}' | grep "${tag}" | awk -F "[:]" '{print $1}' | head -1)
		if [[ ${ipv6OutIndex} -gt 0 ]]; then	 		routing=$(jq -r 'del(.outbounds['$(("${ipv6OutIndex}" - 1))'])' ${configPath}10_ipv4_outbounds.json)
			echo "${routing}" | jq . >$ {configPath}10_ipv4_outbounds.json
		fi
	fi

}

#Uninstall Sniffer
unInstallSniffing() {

	find ${configPath} -name "*inbounds.json*" | awk -F "[c][o][n][f][/]" '{print $2}' | while read -r inbound; do
		sniffing=$(jq -r 'del(.inbounds[0].sniffing)' "${configPath}${inbound}")
		echo "${sniffing}" | jq . > "${configPath}${inbound}"
	done
}

#Install sniffer
installSniffing() {

	find ${configPath} -name "*inbounds.json*" | awk -F "[c][o][n][f][/]" '{print $2}' | while read -r inbound; do
		sniffing=$(jq -r '.inbounds[0].sniffing ={"enabled":true,"destOverride":["http","tls"]}' "${configPath}${inbound}")
		echo "${sniffing}" | jq . > "${configPath}${inbound}"
	done
}

#Warp diversion
warpRouting() {
	EchoContent skyBlue " n Progress $1/${totalProgress}: WARP diversion"
	echoContent red "============================================================== "
	#	EchoContent yellow "# Precautions  n
	#	EchoContent yellow "1. After several rounds of testing, there are bugs in the official Warp. Restarting it will cause Warp to fail and fail to start, and there is also a possibility of CPU usage skyrocketing
	#	EchoContent yellow "2. Without restarting the machine, it can be used normally. If you must use the official warp, it is recommended not to restart the machine
	#	EchoContent yellow "3. Some machines can still be used normally after restarting"
	#	EchoContent yellow "4. Unable to use after reboot, can also be uninstalled and reinstalled"
	#Install Warp
	if [[ -z $(which warp-cli) ]]; then
		echo
		Read - r - p "WARP not installed, do you want to install it? [y/n]:" installCloudflareWarpStatus
		if [[ "${installCloudflareWarpStatus}" == "y" ]]; then
			installWarp
		else
			EchoContent yellow "-->Abort installation"
			exit 0
		fi
	fi

	echoContent red "\n============================================================== "
	EchoContent yellow "1. Add domain name"
	EchoContent yellow "2. Uninstall WARP diversion"
	echoContent red "============================================================== "
	Read - r - p "Please select:" warpStatus
	if [[ "${warpStatus}" == "1" ]]; then
		echoContent red "============================================================== "
		EchoContent yellow "# Precautions  n
		EchoContent yellow "1. The rule only supports predefined domain name lists[ https://github.com/v2fly/domain-list-community ]"
		EchoContent yellow "2. Detailed documentation[ https://www.v2fly.org/config/routing.html ]"
		EchoContent yellow "3. Traffic can only be diverted to warp, cannot be specified as ipv4 or ipv6"
		EchoContent yellow "4. If the kernel fails to start, please check the domain name and add it again
		EchoContent yellow "5. Special characters are not allowed, pay attention to the format of commas"
		EchoContent yellow "6. Every addition is a re addition, and the last domain name will not be retained"
		EchoContent yellow "7. Input examples: Google, YouTube, Facebook  n
		Read - r - p "Please enter the domain name according to the above example:" domainList

		if [[ -f "${configPath}09_routing.json" ]]; then
			unInstallRouting warp-socks-out outboundTag

			routing=$(jq -r ".routing.rules +=[{\"type\":\"field\",\"domain\":[\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"warp-socks-out\"}]" ${configPath}09_routing.json)

			echo "${routing}" | jq . >$ {configPath}09_routing.json

		else
			cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "domain": [
            	"geosite:${domainList//,/\",\"geosite:}"
            ],
            "outboundTag": "warp-socks-out"
          }
        ]
  }
}
EOF
		fi
		unInstallOutbounds warp-socks-out

		local outbounds
		outbounds=$(jq -r '.outbounds +=[{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":31303}]},"tag":"warp-socks-out"}]' ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >$ {configPath}10_ipv4_outbounds.json

		EchoContent green "-->Successfully added"

	elif [[ "${warpStatus}" == "2" ]]; then

		${removeType} cloudflare-warp >/dev/null 2>&1

		unInstallRouting warp-socks-out outboundTag

		unInstallOutbounds warp-socks-out

		EchoContent green "-->WARP offloading successfully"
	else
		EchoContent red "-->Selection error"
		exit 0
	fi
	reloadCore
}
#Streaming Toolbox
streamingToolbox() {
	EchoContent skyBlue " nFunction 1/${totalProgress}: Streaming Toolbox"
	echoContent red "\n============================================================== "
	#	EchoContent yellow "1. Netflix detection"
	EchoContent yellow "1. Any door landing machine unlocks streaming media"
	EchoContent yellow "2. DNS unlocking streaming"
	EchoContent yellow "3. VMess+WS+TLS Unlock Streaming"
	Read - r - p "Please select:" selectType

	case ${selectType} in
	1)
		dokodemoDoorUnblockStreamingMedia
		;;
	2)
		dnsUnlockNetflix
		;;
	3)
		unblockVMessWSTLSStreamingMedia
		;;
	esac

}

#Unlocking streaming media through any door
dokodemoDoorUnblockStreamingMedia() {
	EchoContent skyBlue " nFunction 1/${totalProgress}: Unlock streaming media on any door landing machine"
	echoContent red "\n============================================================== "
	EchoContent yellow "# Precautions"
	EchoContent yellow "For detailed explanation of unlocking any door, please refer to this article[ https://github.com/reeceyng/v2ray-agent/blob/master/documents/netflix/dokodemo-unblock_netflix.md ]\n"

	EchoContent yellow "1. Add Outbound"
	EchoContent yellow "2. Add inbound"
	EchoContent yellow "3. Uninstall"
	Read - r - p "Please select:" selectType

	case ${selectType} in
	1)
		setDokodemoDoorUnblockStreamingMediaOutbounds
		;;
	2)
		setDokodemoDoorUnblockStreamingMediaInbounds
		;;
	3)
		removeDokodemoDoorUnblockStreamingMedia
		;;
	esac
}

#VMess+WS+TLS Go to War to Unlock Streaming Media [Outbound Only]
unblockVMessWSTLSStreamingMedia() {
	EchoContent skyBlue " nFunction 1/${totalProgress}: VMess+WS+TLS Outbound Unlock Streaming"
	echoContent red "\n============================================================== "
	EchoContent yellow "# Precautions"
	EchoContent yellow "Suitable for unlocking VMess services provided by other service providers  n

	EchoContent yellow "1. Add Outbound"
	EchoContent yellow "2. Uninstall"
	Read - r - p "Please select:" selectType

	case ${selectType} in
	1)
		setVMessWSTLSUnblockStreamingMediaOutbounds
		;;
	2)
		removeVMessWSTLSUnblockStreamingMedia
		;;
	esac
}

#Set VMess+WS+TLS to unlock Netflix [outbound only]
setVMessWSTLSUnblockStreamingMediaOutbounds() {
	Read - r - p "Please enter the address to unlock streaming media VMess+WS+TLS:" setVMessWSTLSAddress
	echoContent red "============================================================== "
	EchoContent yellow "# Precautions  n
	EchoContent yellow "1. The rule only supports predefined domain name lists[ https://github.com/v2fly/domain-list-community ]"
	EchoContent yellow "2. Detailed documentation[ https://www.v2fly.org/config/routing.html ]"
	EchoContent yellow "3. If the kernel fails to start, please check the domain name and add it again
	EchoContent yellow "4. Special characters are not allowed, pay attention to the format of commas"
	EchoContent yellow "5. Every addition is a re addition, and the last domain name will not be retained"
	EchoContent yellow "6. Input examples: netflix, disney, hulu  n
	Read - r - p "Please enter the domain name according to the above example:" domainList

	if [[ -z ${domainList} ]]; then
		EchoContent red "-->Domain name cannot be empty"
		setVMessWSTLSUnblockStreamingMediaOutbounds
	fi

	if [[ -n "${setVMessWSTLSAddress}" ]]; then

		unInstallOutbounds VMess-out

		echo
		Read - r - p "Please enter the port for VMess+WS+TLS:" setVMessWSTLSPort
		echo
		if [[ -z "${setVMessWSTLSPort}" ]]; then
			EchoContent red "-->Port cannot be empty"
		fi

		Read - r - p "Please enter the UUID of VMess+WS+TLS:" setVMessWSTLSUUID
		echo
		if [[ -z "${setVMessWSTLSUUID}" ]]; then
			EchoContent red "-->UUID cannot be empty"
		fi

		Read - r - p "Please enter the Path path for VMess+WS+TLS:" setVMessWSTLSPath
		echo
		if [[ -z "${setVMessWSTLSPath}" ]]; then
			EchoContent red "-->Path cannot be empty"
		fi

		outbounds=$(jq -r ".outbounds +=[{\"tag\":\"VMess-out\",\"protocol\":\"vmess\",\"streamSettings\":{\"network\":\"ws\",\"security\":\"tls\",\"tlsSettings\":{\"allowInsecure\":false},\"wsSettings\":{\"path\":\"${setVMessWSTLSPath}\"}},\"mux\":{\"enabled\":true,\"concurrency\":8},\"settings\":{\"vnext\":[{\"address\":\"${setVMessWSTLSAddress}\",\"port\":${setVMessWSTLSPort},\"users\":[{\"id\":\"$ {setVMessWSTLSUUID}\",\"security\":\"auto\",\"alterId\":0}]}]}}]" ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >$ {configPath}10_ipv4_outbounds.json

		if [[ -f "${configPath}09_routing.json" ]]; then
			unInstallRouting VMess-out outboundTag

			local routing

			routing=$(jq -r ".routing.rules +=[{\"type\":\"field\",\"domain\":[\"ip.sb\",\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"VMess-out\"}]" ${configPath}09_routing.json)

			echo "${routing}" | jq . >$ {configPath}09_routing.json
		else
			cat <<EOF >${configPath}09_routing.json
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "domain": [
          "ip.sb",
          "geosite:${domainList//,/\",\"geosite:}"
        ],
        "outboundTag": "VMess-out"
      }
    ]
  }
}
EOF
		fi
		reloadCore
		EchoContent green "-->Successfully added outbound unlock"
		exit 0
	fi
	EchoContent red "-->Address cannot be empty"
	setVMessWSTLSUnblockStreamingMediaOutbounds
}

#Set any door to unlock Netflix [outbound]
setDokodemoDoorUnblockStreamingMediaOutbounds() {
	Read - r - p "Please enter the IP for unlocking streaming vps:" setIP
	echoContent red "============================================================== "
	EchoContent yellow "# Precautions  n
	EchoContent yellow "1. The rule only supports predefined domain name lists[ https://github.com/v2fly/domain-list-community ]"
	EchoContent yellow "2. Detailed documentation[ https://www.v2fly.org/config/routing.html ]"
	EchoContent yellow "3. If the kernel fails to start, please check the domain name and add it again
	EchoContent yellow "4. Special characters are not allowed, pay attention to the format of commas"
	EchoContent yellow "5. Every addition is a re addition, and the last domain name will not be retained"
	EchoContent yellow "6. Input examples: netflix, disney, hulu  n
	Read - r - p "Please enter the domain name according to the above example:" domainList

	if [[ -z ${domainList} ]]; then
		EchoContent red "-->Domain name cannot be empty"
		setDokodemoDoorUnblockStreamingMediaOutbounds
	fi

	if [[ -n "${setIP}" ]]; then

		unInstallOutbounds streamingMedia-80
		unInstallOutbounds streamingMedia-443

		outbounds=$(jq -r ".outbounds +=[{\"tag\":\"streamingMedia-80\",\"protocol\":\"freedom\",\"settings\":{\"domainStrategy\":\"AsIs\",\"redirect\":\"${setIP}:22387\"}},{\"tag\":\"streamingMedia-443\",\"protocol\":\"freedom\",\"settings\":{\"domainStrategy\":\"AsIs\",\"redirect\":\"${setIP}:22388\"}}]" ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >$ {configPath}10_ipv4_outbounds.json

		if [[ -f "${configPath}09_routing.json" ]]; then
			unInstallRouting streamingMedia-80 outboundTag
			unInstallRouting streamingMedia-443 outboundTag

			local routing

			routing=$(jq -r ".routing.rules +=[{\"type\":\"field\",\"port\":80,\"domain\":[\"ip.sb\",\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"streamingMedia-80\"},{\"type\":\"field\",\"port\":443,\"domain\":[\"ip.sb\",\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"streamingMedia-443\"}]" ${configPath}09_routing.json)

			echo "${routing}" | jq . >$ {configPath}09_routing.json
		else
			cat <<EOF >${configPath}09_routing.json
{
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "port": 80,
        "domain": [
          "ip.sb",
          "geosite:${domainList//,/\",\"geosite:}"
        ],
        "outboundTag": "streamingMedia-80"
      },
      {
        "type": "field",
        "port": 443,
        "domain": [
          "ip.sb",
          "geosite:${domainList//,/\",\"geosite:}"
        ],
        "outboundTag": "streamingMedia-443"
      }
    ]
  }
}
EOF
		fi
		reloadCore
		EchoContent green "-->Successfully added outbound unlock"
		exit 0
	fi
	EchoContent red "-->IP cannot be empty"
}

#Set any door to unlock Netflix [inbound]
setDokodemoDoorUnblockStreamingMediaInbounds() {

	EchoContent skyBlue " nFunction 1/${totalProgress}: Add inbound to any door"
	echoContent red "\n============================================================== "
	EchoContent yellow "# Precautions  n
	EchoContent yellow "1. The rule only supports predefined domain name lists[ https://github.com/v2fly/domain-list-community ]"
	EchoContent yellow "2. Detailed documentation[ https://www.v2fly.org/config/routing.html ]"
	EchoContent yellow "3. If the kernel fails to start, please check the domain name and add it again
	EchoContent yellow "4. Special characters are not allowed, pay attention to the format of commas"
	EchoContent yellow "5. Every addition is a re addition, and the last domain name will not be retained"
	EchoContent yellow "6. IP input examples: 1.1.1.1, 1.1.1.2
	EchoContent yellow "7. The following domain name must be consistent with the outbound VPS"
	#	EchoContent yellow "8. If there is a firewall, please manually open ports 22387 and 22388
	EchoContent yellow "8. Example of domain name entry: netflix, disney, hulu  n
	Read - r - p "Please enter the IP that allows access to the unlocked vps:" setIPs
	if [[ -n "${setIPs}" ]]; then
		Read - r - p "Please enter the domain name according to the above example:" domainList
		allowPort 22387
		allowPort 22388

		cat <<EOF >${configPath}01_netflix_inbounds.json
{
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 22387,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "0.0.0.0",
        "port": 80,
        "network": "tcp",
        "followRedirect": false
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http"
        ]
      },
      "tag": "streamingMedia-80"
    },
    {
      "listen": "0.0.0.0",
      "port": 22388,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "0.0.0.0",
        "port": 443,
        "network": "tcp",
        "followRedirect": false
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "tls"
        ]
      },
      "tag": "streamingMedia-443"
    }
  ]
}
EOF

		cat <<EOF >${configPath}10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4-out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6-out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole-out"
        }
    ]
}
EOF

		if [[ -f "${configPath}09_routing.json" ]]; then
			unInstallRouting streamingMedia-80 inboundTag
			unInstallRouting streamingMedia-443 inboundTag

			local routing
			routing=$(jq -r ".routing.rules +=[{\"source\":[\"${setIPs//,/\",\"}\"],\"type\":\"field\",\"inboundTag\":[\"streamingMedia-80\",\"streamingMedia-443\"],\"outboundTag\":\"direct\"},{\"domains\":[\"geosite:${domainList//,/\",\"geosite:}\"],\"type\":\"field\",\"inboundTag\":[\"streamingMedia-80\",\"streamingMedia-443\"],\"outboundTag\":\"blackhole-out\"}]" ${configPath}09_routing.json)
			echo "${routing}" | jq . >$ {configPath}09_routing.json
		else
			cat <<EOF >${configPath}09_routing.json
            {
              "routing": {
                "rules": [
                  {
                    "source": [
                    	"${setIPs//,/\",\"}"
                    ],
                    "type": "field",
                    "inboundTag": [
                      "streamingMedia-80",
                      "streamingMedia-443"
                    ],
                    "outboundTag": "direct"
                  },
                  {
                    "domains": [
                    	"geosite:${domainList//,/\",\"geosite:}"
                    ],
                    "type": "field",
                    "inboundTag": [
                      "streamingMedia-80",
                      "streamingMedia-443"
                    ],
                    "outboundTag": "blackhole-out"
                  }
                ]
              }
            }
EOF

		fi

		reloadCore
		EchoContent green "-->Successfully added landing machine inbound unlocking"
		exit 0
	fi
	EchoContent red "-->IP cannot be empty"
}

#Remove any door to unlock Netflix
removeDokodemoDoorUnblockStreamingMedia() {

	unInstallOutbounds streamingMedia-80
	unInstallOutbounds streamingMedia-443

	unInstallRouting streamingMedia-80 inboundTag
	unInstallRouting streamingMedia-443 inboundTag

	unInstallRouting streamingMedia-80 outboundTag
	unInstallRouting streamingMedia-443 outboundTag

	rm -rf ${configPath}01_netflix_inbounds.json

	reloadCore
	EchoContent green "-->Uninstallation successful"
}

#Remove VMess+WS+TLS to unlock streaming media
removeVMessWSTLSUnblockStreamingMedia() {

	unInstallOutbounds VMess-out

	unInstallRouting VMess-out outboundTag

	reloadCore
	EchoContent green "-->Uninstallation successful"
}

#Restart Core
reloadCore() {
	if [[ "${coreInstallType}" == "1" || "${coreInstallType}" == "3" ]]; then
		handleXray stop
		handleXray start
	elif [[ "${coreInstallType}" == "2" ]]; then
		handleV2Ray stop
		handleV2Ray start
	fi

	if [[ -n "${hysteriaConfigPath}" ]]; then
		handleHysteria stop
		handleHysteria start
	fi
}

#DNS unlocking Netflix
dnsUnlockNetflix() {
	if [[ -z "${configPath}" ]]; then
		EchoContent red "-->Not installed, please use script to install"
		menu
		exit 0
	fi
	EchoContent skyBlue " nFunction 1/${totalProgress}: DNS Unlock Streaming"
	echoContent red "\n============================================================== "
	EchoContent yellow "1. Add"
	EchoContent yellow "2. Uninstall"
	Read - r - p "Please select:" selectType

	case ${selectType} in
	1)
		setUnlockDNS
		;;
	2)
		removeUnlockDNS
		;;
	esac
}

#Set DNS
setUnlockDNS() {
	Read - r - p "Please enter the unlock streaming DNS:" setDNS
	if [[ -n ${setDNS} ]]; then
		echoContent red "============================================================== "
		EchoContent yellow "# Precautions  n
		EchoContent yellow "1. The rule only supports predefined domain name lists[ https://github.com/v2fly/domain-list-community ]"
		EchoContent yellow "2. Detailed documentation[ https://www.v2fly.org/config/routing.html ]"
		EchoContent yellow "3. If the kernel fails to start, please check the domain name and add it again
		EchoContent yellow "4. Special characters are not allowed, pay attention to the format of commas"
		EchoContent yellow "5. Every addition is a re addition, and the last domain name will not be retained"
		EchoContent yellow "6. Input example: netflix, disney, hulu"
		EchoContent yellow "7. Please enter 1 for the default scheme, which includes the following content"
		echoContent yellow "netflix,bahamut,hulu,hbo,disney,bbc,4chan,fox,abema,dmm,niconico,pixiv,bilibili,viu"
		Read - r - p "Please enter the domain name according to the above example:" domainList
		if [[ "${domainList}" == "1" ]]; then
			cat <<EOF >${configPath}11_dns.json
            {
            	"dns": {
            		"servers": [
            			{
            				"address": "${setDNS}",
            				"port": 53,
            				"domains": [
            					"geosite:netflix",
            					"geosite:bahamut",
            					"geosite:hulu",
            					"geosite:hbo",
            					"geosite:disney",
            					"geosite:bbc",
            					"geosite:4chan",
            					"geosite:fox",
            					"geosite:abema",
            					"geosite:dmm",
            					"geosite:niconico",
            					"geosite:pixiv",
            					"geosite:bilibili",
            					"geosite:viu"
            				]
            			},
            		"localhost"
            		]
            	}
            }
EOF
		elif [[ -n "${domainList}" ]]; then
			cat <<EOF >${configPath}11_dns.json
                        {
                        	"dns": {
                        		"servers": [
                        			{
                        				"address": "${setDNS}",
                        				"port": 53,
                        				"domains": [
                        					"geosite:${domainList//,/\",\"geosite:}"
                        				]
                        			},
                        		"localhost"
                        		]
                        	}
                        }
EOF
		fi

		reloadCore

		EchoContent yellow " n -->If you are still unable to watch, you can try the following two options"
		EchoContent yellow "1. Restart VPS"
		EchoContent yellow "2. After uninstalling DNS and unlocking, modify the local [/etc/resolv. conf] DNS settings and restart vps  n
	else
		EchoContent red "-->dns cannot be empty"
	fi
	exit 0
}

#Remove Netflix Unlock
removeUnlockDNS() {
	cat <<EOF >${configPath}11_dns.json
{
	"dns": {
		"servers": [
			"localhost"
		]
	}
}
EOF
	reloadCore

	EchoContent green "-->Uninstallation successful"

	exit 0
}

#V2ray core personalized installation
customV2RayInstall() {
	EchoContent skyBlue
	EchoContent yellow "VLESS is pre installed and defaults to 0. If only 0 needs to be installed, then only 0 can be selected
	echoContent yellow "0.VLESS+TLS/XTLS+TCP"
	echoContent yellow "1.VLESS+TLS+WS[CDN]"
	echoContent yellow "2.Trojan+TLS+gRPC[CDN]"
	echoContent yellow "3.VMess+TLS+WS[CDN]"
	echoContent yellow "4.Trojan"
	echoContent yellow "5.VLESS+TLS+gRPC[CDN]"
	Read - r - p "Please select [multiple choices], [e.g.: 123]:" selectCustomimInstallType
	echoContent skyBlue "--------------------------------------------------------------"
	if [[ -z ${selectCustomInstallType} ]]; then
		selectCustomInstallType=0
	fi
	if [[ "${selectCustomInstallType}" =~ ^[0-5]+$ ]]; then
		cleanUp xrayClean
		totalProgress=17
		installTools 1
		#Apply for TLS
		initTLSNginxConfig 2
		installTLS 3
		handleNginx stop
		#Random path
		if echo ${selectCustomInstallType} | grep -q 1 || echo ${selectCustomInstallType} | grep -q 3 || echo ${selectCustomInstallType} | grep -q 4; then
			randomPathFunction 5
			customCDNIP 6
		fi
		nginxBlog 7
		updateRedirectNginxConf
		handleNginx start

		#Install V2Ray
		installV2Ray 8
		installV2RayService 9
		initV2RayConfig custom 10
		cleanUp xrayDel
		installCronTLS 14
		handleV2Ray stop
		handleV2Ray start
		#Generate Account
		checkGFWStatue 15
		showAccounts 16
	else
		EchoContent red "-->Illegal input"
		customV2RayInstall
	fi
}

#Xray core personalized installation
customXrayInstall() {
	EchoContent skyBlue
	EchoContent yellow "VLESS is pre installed and defaults to 0. If only 0 needs to be installed, then only 0 can be selected
	echoContent yellow "0.VLESS+TLS/XTLS+TCP"
	echoContent yellow "1.VLESS+TLS+WS[CDN]"
	echoContent yellow "2.Trojan+TLS+gRPC[CDN]"
	echoContent yellow "3.VMess+TLS+WS[CDN]"
	echoContent yellow "4.Trojan"
	echoContent yellow "5.VLESS+TLS+gRPC[CDN]"
	Read - r - p "Please select [multiple choices], [e.g.: 123]:" selectCustomimInstallType
	echoContent skyBlue "--------------------------------------------------------------"
	if [[ -z ${selectCustomInstallType} ]]; then
		EchoContent red "-->cannot be empty"
		customXrayInstall
	elif [[ "${selectCustomInstallType}" =~ ^[0-5]+$ ]]; then
		cleanUp v2rayClean
		totalProgress=17
		installTools 1
		#Apply for TLS
		initTLSNginxConfig 2
		handleXray stop
		handleNginx start
		checkIP

		installTLS 3
		handleNginx stop
		#Random path
		if echo "${selectCustomInstallType}" | grep -q 1 || echo "${selectCustomInstallType}" | grep -q 2 || echo "${selectCustomInstallType}" | grep -q 3 || echo "${selectCustomInstallType}" | grep -q 5; then
			randomPathFunction 5
			customCDNIP 6
		fi
		nginxBlog 7
		updateRedirectNginxConf
		handleNginx start

		#Install V2Ray
		installXray 8
		installXrayService 9
		initXrayConfig custom 10
		cleanUp v2rayDel

		installCronTLS 14
		handleXray stop
		handleXray start
		#Generate Account
		checkGFWStatue 15
		showAccounts 16
	else
		EchoContent red "-->Illegal input"
		customXrayInstall
	fi
}

#Choose core installation - v2ray core, xray core
selectCoreInstall() {
	EchoContent skyBlue " nFunction 1/${totalProgress}: Select Core Installation"
	echoContent red "\n============================================================== "
	echoContent yellow "1.Xray-core"
	echoContent yellow "2.v2ray-core"
EchoContent yellow "3. Xray core (using xtls rprx vision)
	echoContent red "============================================================== "
	Read - r - p "Please select:" selectCoreType
	case ${selectCoreType} in
	1)
		if [[ "${selectInstallType}" == "2" ]]; then
			customXrayInstall
		else
			xrayCoreInstall
		fi
		;;
	2)
		v2rayCoreVersion=
		if [[ "${selectInstallType}" == "2" ]]; then
			customV2RayInstall
		else
			v2rayCoreInstall
		fi
		;;
	3)
		xtlsRprxVision=true
		if [[ "${selectInstallType}" == "2" ]]; then
			customXrayInstall
		else
			xrayCoreInstall
		fi
		;;
	*)
		EchoContent red '->Selection error, reselect'
		selectCoreInstall
		;;
	esac
}

#V2ray core installation
v2rayCoreInstall() {
	cleanUp xrayClean
	selectCustomInstallType=
	totalProgress=13
	installTools 2
	#Apply for TLS
	initTLSNginxConfig 3

	handleV2Ray stop
	handleNginx start
	checkIP

	installTLS 4
	handleNginx stop
	#	initNginxConfig 5
	randomPathFunction 5
	#Install V2Ray
	installV2Ray 6
	installV2RayService 7
	customCDNIP 8
	initV2RayConfig all 9
	cleanUp xrayDel
	installCronTLS 10
	nginxBlog 11
	updateRedirectNginxConf
	handleV2Ray stop
	sleep 2
	handleV2Ray start
	handleNginx start
	#Generate Account
	checkGFWStatue 12
	showAccounts 13
}

#Xray core installation
xrayCoreInstall() {
	cleanUp v2rayClean
	selectCustomInstallType=
	totalProgress=13
	installTools 2
	#Apply for TLS
	initTLSNginxConfig 3

	handleXray stop
	handleNginx start
	checkIP

	installTLS 4
	handleNginx stop
	randomPathFunction 5
	#Installing Xray
	# handleV2Ray stop
	installXray 6
	installXrayService 7
	customCDNIP 8
	initXrayConfig all 9
	cleanUp v2rayDel
	installCronTLS 10
	nginxBlog 11
	updateRedirectNginxConf
	handleXray stop
	sleep 2
	handleXray start

	handleNginx start
	#Generate Account
	checkGFWStatue 12
	showAccounts 13
}
#Hysteria installation
hysteriaCoreInstall() {
	if [[ -z "${coreInstallType}" ]]; then
		EchoContent red " n -->Due to environmental dependencies, if installing Hysteria, please install Xray/V2ray first"
		menu
		exit 0
	fi
	totalProgress=5
	installHysteria 1
	initHysteriaConfig 2
	installHysteriaService 3
	handleHysteria stop
	handleHysteria start
	showAccounts 5
}
#Uninstalling Hysteria
unInstallHysteriaCore() {

	if [[ -z "${hysteriaConfigPath}" ]]; then
		EchoContent red " n -->Not installed"
		exit 0
	fi
	handleHysteria stop
	rm -rf /etc/v2ray-agent/hysteria/*
	rm -rf /etc/systemd/system/hysteria.service
	EchoContent green "-->Uninstall completed"
}

#Core management
coreVersionManageMenu() {

	if [[ -z "${coreInstallType}" ]]; then
		EchoContent red " n -->No installation directory detected, please execute the script to install the content"
		menu
		exit 0
	fi
	if [[ "${coreInstallType}" == "1" || "${coreInstallType}" == "3" ]]; then
		xrayVersionManageMenu 1
	elif [[ "${coreInstallType}" == "2" ]]; then
		v2rayCoreVersion=
		v2rayVersionManageMenu 1
	fi
}
#Scheduled Task Check Certificate
cronRenewTLS() {
	if [[ "${renewTLS}" == "RenewTLS" ]]; then
		renewalTLS
		exit 0
	fi
}
#Account management
manageAccount() {
	EchoContent skyBlue " nFunction 1/${totalProgress}: Account Management"
	echoContent red "\n============================================================== "
	EchoContent yellow "# After deleting or adding an account, you need to review the subscription again to generate a subscription"
	EchoContent yellow "# If Hysteria is installed, the account will also be added to Hysteria  n
	EchoContent yellow "1. View account"
	EchoContent yellow "2. View subscription"
	EchoContent yellow "3. Add User"
	EchoContent yellow "4. Delete user"
	echoContent red "============================================================== "
	Read - r - p "Please enter:" manageAccountStatus
	if [[ "${manageAccountStatus}" == "1" ]]; then
		showAccounts 1
	elif [[ "${manageAccountStatus}" == "2" ]]; then
		subscribe 1
	elif [[ "${manageAccountStatus}" == "3" ]]; then
		addUser
	elif [[ "${manageAccountStatus}" == "4" ]]; then
		removeUser
	else
		EchoContent red "-->Selection error"
	fi
}

#Subscription
subscribe() {
	if [[ -n "${configPath}" ]]; then
		EchoContent skyBlue
		EchoContent yellow "# Regenerate subscription when viewing subscription"
		EchoContent yellow "# Every time an account is added or deleted, it is necessary to review the subscription again"
		rm -rf /etc/v2ray-agent/subscribe/*
		rm -rf /etc/v2ray-agent/subscribe_tmp/*
		showAccounts >/dev/null
		mv /etc/v2ray-agent/subscribe_tmp/* /etc/v2ray-agent/subscribe/

		if [[ -n $(ls /etc/v2ray-agent/subscribe/) ]]; then
			find /etc/v2ray-agent/subscribe/* | while read -r email; do
				email=$(echo "${email}" | awk -F "[b][e][/]" '{print $2}')

				local base64Result
				base64Result=$(base64 -w 0 "/etc/v2ray-agent/subscribe/${email}")
				echo "${base64Result}" >"/etc/v2ray-agent/subscribe/${email}"
				echoContent skyBlue "--------------------------------------------------------------"
				echoContent yellow "email:${email}\n"
				local currentDomain=${currentHost}

				if [[ -n "${currentDefaultPort}" && "${currentDefaultPort}" != "443" ]]; then 				currentDomain="${currentHost}:${currentDefaultPort}"
				fi

				echoContent yellow "url:https://${currentDomain}/s/${email}\n"
				EchoContent yellow "Online QR code: https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=https://${currentDomain}/s/${email}\n"
				echo "https://${currentDomain}/s/${email}" | qrencode -s 10 -m 1 -t UTF8
				echoContent skyBlue "--------------------------------------------------------------"
			done
		fi
	else
		EchoContent red "-->Not installed"
	fi
}

#Switch Alpn
switchAlpn() {
	EchoContent skyBlue " nFunction 1/${totalProgress}: Switch Alpn"
	if [[ -z ${currentAlpn} ]]; then
		EchoContent red "-->Unable to read Alpn, please check if it is installed"
		exit 0
	fi

	echoContent red "\n============================================================== "
	EchoContent green "The current Alpn starts with: ${currentAlpn}"
	EchoContent yellow "1. When HTTP/1.1 comes first, trojan is available, and some clients of gRPC are available [clients support manual selection of alpn available]
	EchoContent yellow "2. When h2 comes first, gRPC is available, while some trojan clients are available [clients support manual selection of alpn available]
	EchoContent yellow "3. If the client does not support manual replacement of the Alpn, it is recommended to use this function to change the server's Alpn order and use the corresponding protocol"
	echoContent red "============================================================== "

	if [[ "${currentAlpn}" == "http/1.1" ]]; then
		EchoContent yellow "1. Switch to the first position of Alpn h2"
	elif [[ "${currentAlpn}" == "h2" ]]; then
		EchoContent yellow "1. Switch to the first position of Alpn HTTP/1.1"
	else
		EchoContent red 'does not match'
	fi

	echoContent red "============================================================== "

	Read - r - p "Please select:" selectSwitchAlpnType
	if [[ "${selectSwitchAlpnType}" == "1" && "${currentAlpn}" == "http/1.1" ]]; then

		local frontingTypeJSON
		if [[ "${coreInstallType}" == "1" ]]; then
			frontingTypeJSON=$(jq -r ".inbounds[0].streamSettings.xtlsSettings.alpn =[\"h2\",\"http/1.1\"]" ${configPath}${frontingType}.json)
		else
		    frontingTypeJSON=$(jq -r ".inbounds[0].streamSettings.tlsSettings.alpn =[\"h2\",\"http/1.1\"]" ${configPath}${frontingType}.json)
		fi
		echo "${frontingTypeJSON}" | jq . >$ {configPath}${frontingType}.json

	elif [[ "${selectSwitchAlpnType}" == "1" && "${currentAlpn}" == "h2" ]]; then 	local frontingTypeJSON
		if [[ "${coreInstallType}" == "1" ]]; then
			frontingTypeJSON=$(jq -r ".inbounds[0].streamSettings.xtlsSettings.alpn =[\"http/1.1\",\"h2\"]" ${configPath}${frontingType}.json)
		else
		    frontingTypeJSON=$(jq -r ".inbounds[0].streamSettings.tlsSettings.alpn =[\"http/1.1\",\"h2\"]" ${configPath}${frontingType}.json)
		fi
		echo "${frontingTypeJSON}" | jq . >$ {configPath}${frontingType}.json
	else
		EchoContent red "-->Selection error"
		exit 0
	fi
	reloadCore
}

#Hysteria Management
manageHysteria() {

	EchoContent skyBlue " n Progress 1/1: Hysteria Management"
	echoContent red "\n============================================================== "
	local hysteriaStatus=
	if [[ -n "${hysteriaConfigPath}" ]]; then
		EchoContent yellow "1. Reinstall"
		EchoContent yellow "2. Uninstall"
		EchoContent yellow "3. Update core"
		EchoContent yellow "4. View logs"
		hysteriaStatus=true
	else
		EchoContent yellow "1. Installation"
	fi

	echoContent red "============================================================== "
	Read - r - p "Please select:" installHysteriaStatus
	if [[ "${installHysteriaStatus}" == "1" ]]; then
		hysteriaCoreInstall
	elif [[ "${installHysteriaStatus}" == "2" && "${hysteriaStatus}" == "true" ]]; then
		unInstallHysteriaCore
	elif [[ "${installHysteriaStatus}" == "3" && "${hysteriaStatus}" == "true" ]]; then
		installHysteria 1
		handleHysteria start
	elif [[ "${installHysteriaStatus}" == "4" && "${hysteriaStatus}" == "true" ]]; then 	journalctl -fu hysteria
	fi
}
#Main Menu
menu() {
	cd "$HOME" || exit
	echoContent red "\n============================================================== "
	EchoContent green "Author: Reece"
	EchoContent green "Original author: mack a"
	EchoContent green "Current version: v2.7.3"
	echoContent green "Github: https://github.com/reeceyng/v2ray-agent "
	EchoContent green "Description: Eight in one co storage script  c"
	showInstallStatus
	echoContent red "\n============================================================== "
	if [[ -n "${coreInstallType}" ]]; then
		EchoContent yellow "1. Reinstall"
	else
		EchoContent yellow "1. Installation"
	fi

	EchoContent yellow "2. Any combination installation"
	if echo ${currentInstallProtocolType} | grep -q trojan; then
		EchoContent yellow "3. Switch VLESS [XTLS]"
	elif echo ${currentInstallProtocolType} | grep -q 0; then
		EchoContent yellow "3. Switch Trojan [XTLS]"
	fi

	EchoContent yellow "4. Hysteria management"
	EchoContent skyBlue
	EchoContent yellow "5. Account Management"
	EchoContent yellow "6. Changing the camouflage station"
	EchoContent yellow "7. Update Certificate"
	EchoContent yellow "8. Replace CDN node"
	EchoContent yellow "9. IPv6 diversion"
	EchoContent yellow "10. WARP diversion"
	EchoContent yellow "11. Streaming Tools"
	EchoContent yellow "12. Add new port"
	EchoContent yellow "13. BT Download Management"
	EchoContent yellow "14. Switching Alpn"
	EchoContent yellow "15. Domain blacklist"
	EchoContent skyBlue
	EchoContent yellow "16. Core management"
	EchoContent yellow "17. Update Script"
	EchoContent yellow "18. Install BBR and DD scripts"
	EchoContent skyBlue "-------- Script Management --------
	EchoContent yellow "19. View Log"
	EchoContent yellow "20. Uninstall Script"
	echoContent red "============================================================== "
	mkdirTools
	aliasInstall
	Read - r - p "Please select:" selectInstallType
	case ${selectInstallType} in
	1)
		selectCoreInstall
		;;
	2)
		selectCoreInstall
		;;
	3)
		initXrayFrontingConfig 1
		;;
	4)
		manageHysteria
		;;
	5)
		manageAccount 1
		;;
	6)
		updateNginxBlog 1
		;;
	7)
		renewalTLS 1
		;;
	8)
		updateV2RayCDN 1
		;;
	9)
		ipv6Routing 1
		;;
	10)
		warpRouting 1
		;;
	11)
		streamingToolbox 1
		;;
	12)
		addCorePort 1
		;;
	13)
		btTools 1
		;;
	14)
		switchAlpn 1
		;;
	15)
		blacklist 1
		;;
	16)
		coreVersionManageMenu 1
		;;
	17)
		updateV2RayAgent 1
		;;
	18)
		bbrInstall
		;;
	19)
		checkLog 1
		;;
	20)
		unInstall 1
		;;
	esac
}
cronRenewTLS
menu
