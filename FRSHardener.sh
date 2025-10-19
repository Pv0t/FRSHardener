#!/bin/bash

PACKAGE_NAME="openssh-server"
RED='\033[0;31m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
NOCOLOR='\033[0m'

echo ""
echo -e "                 Welcome to FRSHardener Project                                          "
echo ""
echo -e "${CYAN}INFO: ${NOCOLOR}All options related to Protocol 1 have been excluded from the sshd configuration file."
echo -e "*========================================================================================================="

if [ "$EUID" != "0" ]
then
	echo -e "${RED}WARNING: ${NOCOLOR}You are not running this tool with root privileges."
	exit 1
fi

function improve_sshd {
	if dpkg -l | grep -q "$PACKAGE_NAME"
	then
		echo -e "${CYAN}[INFO]: ${NOCOLOR} $PACKAGE_NAME is installed."
	else
		echo "${RED}WARNING: ${NOCOLOR} $PACKAGE_NAME is not installed."
		echo -e "${GREEN}INPUT: ${NOCOLOR}Do you wanna install $PACKAGE_NAME? [Y/N]"
		read -p "" openssh_install
		case $openssh_install in
			"Y") sudo apt install $PACKAGE_NAME ;;
			"N") exit 0 ;;
			"*") exit 0 ;;
		esac
	fi
	echo "#===General & Authentication===#" > /etc/ssh/sshd_config 
	echo -e "${GREEN}INPUT: ${NOCOLOR}Enter the port number you wish to use for the sshd(SSH) service: " 
	read -p "" sshd_port
	echo "Port" $sshd_port | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "Protocol 2" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "AddressFamily inet" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "DenyUsers root" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null

	echo -e "${GREEN}INPUT: ${NOCOLOR}Enter the username (excluding 'root') that you want to add to the 'AllowUsers' option: " 
	read -p "" user
	echo "AllowUsers" $users | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	
	echo "#DenyGroups" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "#AllowGroups" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "AuthorizedKeysFile .ssh/authorized_keys" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "Banner none" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	
	echo -e "${GREEN}INPUT: ${NOCOLOR}Do you wanna setup a 2FA authentication? [Y/N]"
	read -p "" 2fa
	#INSERT CASE HERE 
	echo "ChallengeResponseAuthentication no"
	echo "UsePAM no"

	echo "ClientAliveInterval 120" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "ClientAliveCountMax 1" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "Compression delayed" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "#ForceCommand" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "GatewayPorts no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "LoginGraceTime 30" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "LogLevel VERBOSE" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "HostbasedAuthentication no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "HostbasedUsesNameFromPacketOnly" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "IgnoreRhosts yes" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "IgnoreUserKnownHosts yes" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "MaxAuthTries 3" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "MaxSessions 2" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "PasswordAuthentication yes" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "PermitEmptyPasswords no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "PermitRootLogin no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "PubkeyAuthentication yes" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "MaxStartups 5:30:30" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null

	echo -e "${GREEN}INPUT: ${NOCOLOR}Write your Public IP: "
	read -p "" sshd_public_ip
	echo "ListenAddress "$sshd_public_ip":"$sshd_port | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "#ListenAddress 127.0.0.1:"$sshd_port "#For troubleshooting" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "PermitUserEnvironment no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "#PidFile /var/run/sshd.pid #-> Default" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "PrintLastLog no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "PrintMotd no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "#AuthorizedKeysCommand" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "#AuthorizedKeysCommandUser" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "#RequiredAuthentications" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "#ShowPatchLevel" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "StrictModes yes" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "#Subsystem" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "SyslogFacility AUTHPRIV" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "TCPKeepAlive no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "UseDNS no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "ChrootDirectory none" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "#===Cryptography===#" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "HostKey /etc/ssh/ssh_host_ed25519_key" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "KexAlgorithms curve25519-sha256" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "MACs hmac-sha2-512-etm@openssh.com" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "HostKeyAlgorithms ssh-ed25519" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "#===Forwarding===#" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "PermitOpen none" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "PermitTunnel no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "AllowAgentForwarding no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "AllowTcpForwarding no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "#===GSSAPI===#" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "GSSAPIAuthentication no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "GSSAPIKeyExchange no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "GSSAPICleanupCredentials yes" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "GSSAPIStrictAcceptorCheck yes" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "GSSAPIStoreCredentialsOnRekey no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "#===Kerberos===#" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "KerberosAuthentication no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "KerberosGetAFSToken no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "KerberosOrLocalPasswd yes" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "KerberosTicketCleanup yes" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "KerberosUseKuserok yes" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "#===X11-Settings===#" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "X11DisplayOffset 10" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "X11Forwarding no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "X11UseLocalhost no" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "XAuthLocation none" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "#============================" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
}




#rsyslog 

#fail2ban

#smtp-alert-configuration


echo -e "Options available:"
echo -e "\t1) Improve the sshd config + rsyslog log + fail2ban + SMTP."
echo -e "\t2) Improve the sshd config + rsyslog log + fail2ban."
echo -e "\t3) Improve the sshd config + rsyslog log."
echo -e "\t4) Improve the sshd config."

read -p "Select your option: " opt

case $opt in
	"1") improve_sshd && rsyslog && fail2ban && smtp ;;
	"2") improve_sshd && rsyslog && fail2ban ;;
	"3") improve_sshd && rsyslog ;;
	"4") improve_sshd ;;
	"*") exit 0 ;;
esac
