#!/bin/bash

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
	#TO-DO: CHECK IF THE SERVICE SSHD IS INSTALLED AND RUNNING
	echo "#===General & Authentication===#" > /etc/ssh/sshd_config 
	echo -e "${GREEN}INPUT: ${NOCOLOR}Enter the port number you wish to use for the sshd(SSH) service: " 
	read -p "" sshd_port
	echo "Port" $sshd_port | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "Protocol 2" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "AddressFamily inet" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	echo "DenyUsers root" | sudo tee -a /etc/ssh/sshd_config 1>/dev/null
	
	read -p "Write the username of your user (not root) to put inside the 'AllowUsers' option: " users
	
	echo "AllowUsers" $users | sudo tee -a /etc/ssh/sshd_config
	echo "#DenyGroups" | sudo tee -a /etc/ssh/sshd_config
	echo "#AllowGroups" | sudo tee -a /etc/ssh/sshd_config
	echo "AuthorizedKeysFile .ssh/authorized_keys" | sudo tee -a /etc/ssh/sshd_config
	echo "Banner none" | sudo tee -a /etc/ssh/sshd_config
	
	read -p "Do you wanna setup a 2FA authentication? [Y/N]" opt2
	#INSERT CASE HERE 
	echo "ChallengeResponseAuthentication no"
	echo "UsePAM no"

	echo "ClientAliveInterval 120" | sudo tee -a /etc/ssh/sshd_config
	echo "ClientAliveCountMax 1" | sudo tee -a /etc/ssh/sshd_config
	echo "Compression delayed" | sudo tee -a /etc/ssh/sshd_config
	echo "#ForceCommand" | sudo tee -a /etc/ssh/sshd_config
	echo "GatewayPorts no" | sudo tee -a /etc/ssh/sshd_config
	echo "LoginGraceTime 30" | sudo tee -a /etc/ssh/sshd_config
	echo "LogLevel VERBOSE" | sudo tee -a /etc/ssh/sshd_config
	echo "HostbasedAuthentication no" | sudo tee -a /etc/ssh/sshd_config
	echo "HostbasedUsesNameFromPacketOnly" | sudo tee -a /etc/ssh/sshd_config
	echo "IgnoreRhosts yes" | sudo tee -a /etc/ssh/sshd_config
	echo "IgnoreUserKnownHosts yes" | sudo tee -a /etc/ssh/sshd_config
	echo "MaxAuthTries 3" | sudo tee -a /etc/ssh/sshd_config
	echo "MaxSessions 2" | sudo tee -a /etc/ssh/sshd_config
	echo "PasswordAuthentication yes" | sudo tee -a /etc/ssh/sshd_config
	echo "PermitEmptyPasswords no" | sudo tee -a /etc/ssh/sshd_config
	echo "PermitRootLogin no" | sudo tee -a /etc/ssh/sshd_config
	echo "PubkeyAuthentication yes" | sudo tee -a /etc/ssh/sshd_config
	echo "MaxStartups 5:30:30" | sudo tee -a /etc/ssh/sshd_config
	
	read -p "Write your Public IP: " your_ip
	echo "ListenAddress "$your_ip":"$your_port | sudo tee -a /etc/ssh/sshd_config
	echo "#ListenAddress 127.0.0.1:"$your_port "#For troubleshooting" | sudo tee -a /etc/ssh/sshd_config

	echo "PermitUserEnvironment no" | sudo tee -a /etc/ssh/sshd_config
	echo "#PidFile /var/run/sshd.pid #-> Default" | sudo tee -a /etc/ssh/sshd_config
	echo "PrintLastLog no" | sudo tee -a /etc/ssh/sshd_config
	echo "PrintMotd no" | sudo tee -a /etc/ssh/sshd_config
	echo "#AuthorizedKeysCommand" | sudo tee -a /etc/ssh/sshd_config
	echo "#AuthorizedKeysCommandUser" | sudo tee -a /etc/ssh/sshd_config
	echo "#RequiredAuthentications" | sudo tee -a /etc/ssh/sshd_config
	echo "#ShowPatchLevel" | sudo tee -a /etc/ssh/sshd_config
	echo "StrictModes yes" | sudo tee -a /etc/ssh/sshd_config
	echo "#Subsystem" | sudo tee -a /etc/ssh/sshd_config
	echo "SyslogFacility AUTHPRIV" | sudo tee -a /etc/ssh/sshd_config
	echo "TCPKeepAlive no" | sudo tee -a /etc/ssh/sshd_config
	echo "UseDNS no" | sudo tee -a /etc/ssh/sshd_config
	echo "ChrootDirectory none" | sudo tee -a /etc/ssh/sshd_config
	echo "" | sudo tee -a /etc/ssh/sshd_config
	echo "#===Cryptography===#" | sudo tee -a /etc/ssh/sshd_config
	echo "HostKey /etc/ssh/ssh_host_ed25519_key" | sudo tee -a /etc/ssh/sshd_config
	echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com" | sudo tee -a /etc/ssh/sshd_config
	echo "KexAlgorithms curve25519-sha256" | sudo tee -a /etc/ssh/sshd_config
	echo "MACs hmac-sha2-512-etm@openssh.com" | sudo tee -a /etc/ssh/sshd_config
	echo "HostKeyAlgorithms ssh-ed25519" | sudo tee -a /etc/ssh/sshd_config
	echo "" | sudo tee -a /etc/ssh/sshd_config
	echo "#===Forwarding===#" | sudo tee -a /etc/ssh/sshd_config
	echo "PermitOpen none" | sudo tee -a /etc/ssh/sshd_config
	echo "PermitTunnel no" | sudo tee -a /etc/ssh/sshd_config
	echo "AllowAgentForwarding no" | sudo tee -a /etc/ssh/sshd_config
	echo "AllowTcpForwarding no" | sudo tee -a /etc/ssh/sshd_config
	echo "" | sudo tee -a /etc/ssh/sshd_config
	echo "#===GSSAPI===#" | sudo tee -a /etc/ssh/sshd_config
	echo "GSSAPIAuthentication no" | sudo tee -a /etc/ssh/sshd_config
	echo "GSSAPIKeyExchange no" | sudo tee -a /etc/ssh/sshd_config 
	echo "GSSAPICleanupCredentials yes" | sudo tee -a /etc/ssh/sshd_config
	echo "GSSAPIStrictAcceptorCheck yes" | sudo tee -a /etc/ssh/sshd_config 
	echo "GSSAPIStoreCredentialsOnRekey no" | sudo tee -a /etc/ssh/sshd_config
	echo "" | sudo tee -a /etc/ssh/sshd_config
	echo "#===Kerberos===#" | sudo tee -a /etc/ssh/sshd_config
	echo "KerberosAuthentication no" | sudo tee -a /etc/ssh/sshd_config
	echo "KerberosGetAFSToken no" | sudo tee -a /etc/ssh/sshd_config
	echo "KerberosOrLocalPasswd yes" | sudo tee -a /etc/ssh/sshd_config
	echo "KerberosTicketCleanup yes" | sudo tee -a /etc/ssh/sshd_config
	echo "KerberosUseKuserok yes" | sudo tee -a /etc/ssh/sshd_config
	echo "" | sudo tee -a /etc/ssh/sshd_config
	echo "#===X11-Settings===#" | sudo tee -a /etc/ssh/sshd_config
	echo "X11DisplayOffset 10" | sudo tee -a /etc/ssh/sshd_config
	echo "X11Forwarding no" | sudo tee -a /etc/ssh/sshd_config
	echo "X11UseLocalhost no" | sudo tee -a /etc/ssh/sshd_config 
	echo "XAuthLocation none" | sudo tee -a /etc/ssh/sshd_config
	echo "#============================" | sudo tee -a /etc/ssh/sshd_config   
}



#rsynclog 

#fail2ban

#smtp warning


echo -e "Options available:"
echo -e "\t1) Improve the sshd config + rsync log + fail2ban + SMTP."
echo -e "\t2) Improve the sshd config + rsync log + fail2ban."
echo -e "\t3) Improve the sshd config + rsync log."
echo -e "\t4) Improve the sshd config."

read -p "Select your option: " opt

case $opt in
	"1") improve_sshd && rsynclog && fail2ban && smtp ;;
	"2") improve_sshd && rsynclog && fail2ban ;;
	"3") improve_sshd && rsynclog ;;
	"4") improve_sshd ;;
	"*") exit 0 ;;
esac
