#!/bin/bash
################################################
#  NetFoundry login profile and help menu
################################################
#
#  This script was intended to be used on the 
#  netfoundry edge-router image created &
#  maintained by netfoundry.
#
################################################
#
#  Change log
#  1.0.0 - initial release
#  1.0.1 - check if ziti cli exists before running section
#
### Export Environment variables
export ZITI_HOME="/opt/netfoundry/ziti"
export ZITI_CLI="${ZITI_HOME}/ziti"
export ZITI_ROUTER="${ZITI_HOME}/ziti-router/ziti-router"

### Functions
# version comparison
vercomp () {

    if [[ "${1}" == "${2}" ]]
    then
        return 1
    fi
    local IFS=.
    local i ver1=(${1}) ver2=(${2})
    # fill empty fields in ver1 with zeros
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++))
    do
        ver1[i]=0
    done
    for ((i=0; i<${#ver1[@]}; i++))
    do
        if [[ -z ${ver2[i]} ]]
        then
            # fill empty fields in ver2 with zeros
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]}))
        then
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]}))
        then
            return 0
        fi
    done
    return 1

}

# add to path
add_netfoundry_path () {
    netfoundry_path="/opt/netfoundry"
    case ":${PATH}:" in
        *:"$netfoundry_path":*)
            ;;
        *)
            PATH=$netfoundry_path:$PATH
    esac
}

# print the banner if no override exists
print_banner() {

  if [[ $(ls /etc/profile.d/*.logo 2> /dev/null) ]]; then
    cat /etc/profile.d/*.logo
  else
    cat<<EOF
    _   __     __  ______                      __          
   / | / /__  / /_/ ____/___  __  ______  ____/ /______  __
  /  |/ / _ \/ __/ /_  / __ \/ / / / __ \/ __  / ___/ / / /
 / /|  /  __/ /_/ __/ / /_/ / /_/ / / / / /_/ / /  / /_/ / 
/_/ |_/\___/\__/_/    \____/\__,_/_/ /_/\__,_/_/   \__, /  
                                                  /____/   
EOF

  fi

}  

# print network information
print_net_info() {

  if [ ! -f "${HOME}/.hushnet" ]; then
    #IP
    MYPUBIP=$(curl -s --connect-timeout 15 https://api.ipify.org)

    # eth0:
    MYIF=$(/sbin/ip -o link show up|awk '$9=="UP" {print $2;}'|head -1)

    # 66.55.44.33/22
    MYIP=$(/sbin/ip add show "${MYIF%:}"|awk '$1=="inet" {print $2;}')

    # NETWORK=10.19.0.0/18
    NETWORK=$(ipcalc "${MYIP}" -b -n |grep -i Network |awk -F'[[:space:]]+|=' '{print $2}')
    printf '\nPublic IPv4:\t\t\t%s\n' "${MYPUBIP:-Unable_to_Detect}"
    printf 'Local Area Network:\t\t%s\n' "${NETWORK}"
    printf 'Interface address (%s):\t%s\n' "${MYIF%:}" "${MYIP%/*}"
  fi

}

# print binary info
print_binary_info() {

  if [[ -f ${ZITI_ROUTER}  ]]; then
    if [[ -f /opt/netfoundry/.name ]]; then
      ROUTER_NAME=$(cat /opt/netfoundry/.name)
      printf '\nRouter Name: %s\n' "${ROUTER_NAME}"
    fi
    ZITI_ROUTER_VERSION=$(${ZITI_ROUTER}  version 2> /dev/null | cut -d"v" -f 2)
    printf '\nRouter version: %s\n' "${ZITI_ROUTER_VERSION}"
    if vercomp "0.26.11" "${ZITI_ROUTER_VERSION}"; then
      LOG_COMMAND="ops log-format -a"
      PS_COMMAND="agent ps"
    else
      LOG_COMMAND="log-format -a"
      PS_COMMAND="ps"
    fi

    alias zt-router-pid="pidof ziti-router"
    alias zt-router-version="${ZITI_ROUTER} version"
    alias zt-router-logs="journalctl -u ziti-router -efo cat | ${ZITI_CLI} ${LOG_COMMAND}"
    alias zt-router-cpu="export DATE=\$(date +"%y-%m-%d-%s") ;sudo -E ${ZITI_CLI} ${PS_COMMAND} pprof-cpu \$(pidof ziti-router) > /tmp/ziti-router-cpu-\$DATE.out; echo Created /tmp/ziti-router-cpu-\$DATE.out; unset DATE"
    alias zt-router-stack="export DATE=\$(date +"%y-%m-%d-%s") ;sudo ${ZITI_CLI} ${PS_COMMAND} stack \$(pidof ziti-router) > /tmp/ziti-router-stack-\$DATE.out; echo Created /tmp/ziti-router-stack-\$DATE.out; unset DATE"
    alias zt-router-mem="export DATE=\$(date +"%y-%m-%d-%s") ;sudo ${ZITI_CLI} ${PS_COMMAND} memstats \$(pidof ziti-router) > /tmp/ziti-router-mem-\$DATE.out; echo Created /tmp/ziti-router-mem-\$DATE.out; unset DATE"
    alias zt-router-heap="export DATE=\$(date +"%y-%m-%d-%s") ;sudo ${ZITI_CLI} ${PS_COMMAND} pprof-heap \$(pidof ziti-router) > /tmp/ziti-router-heap-\$DATE.out; echo Created /tmp/ziti-router-heap-\$DATE.out; unset DATE"
    alias zt-router-restart="sudo systemctl restart ziti-router"
    alias zt-router-start="sudo systemctl start ziti-router"
    alias zt-router-stop="sudo systemctl stop ziti-router"
    alias zt-router-status="sudo systemctl status ziti-router --no-pager"
    alias zt-router-health="curl -k https://localhost:8081/health-checks"

  fi


  if [[ -f ${ZITI_CLI} ]]; then
    ZITI_CLI_VERSION=$(${ZITI_CLI} --version | cut -d"v" -f 2)
    printf '\nCLI version: %s\n' "${ZITI_CLI_VERSION}"
  fi
}

# print registration information
print_register() {

  if [[ -f /opt/netfoundry/ziti/ziti-router/.is_registered ]]; then
      printf '\n'
      echo -e $(cat /opt/netfoundry/.login-readme.registered)
    elif [[ -f /opt/netfoundry/.login-readme ]]; then
      printf '\n'
      echo -e $(cat /opt/netfoundry/.login-readme)
    fi

    echo -e  "type \033[0;31mnfhelp\033[0m for more commands"

}

# create nfhelp menu
create_nfhelp() {
  
  alias nfhelp='if [[ -f "${ZITI_ROUTER}" ]]; then echo -e "
  \033[0;31mRouter Commands:\033[0m
  router-registration - register ziti router
  zt-router-pid       - print process id of currently running ziti-router
  zt-router-version   - print ziti-router version
  zt-router-logs      - tail ziti router logs
  zt-router-restart   - restart ziti-router service
  zt-router-start     - start ziti-router service
  zt-router-stop      - stop ziti-router service
  zt-router-status    - print ziti-router system service status
  zt-router-health    - print current router healthcheck
  zt-status           - print status of all ziti services
  zt-router-cpu       - create pprof cpu of currently running ziti-router
  zt-router-stack     - create stack trace of currently running ziti-router
  zt-router-mem       - create memstats of currently running ziti-router
  zt-router-heap      - create pprof heap of currently running ziti-router\n
 \033[0;31mSupport Commands:\033[0m
  vm-support-bundle   - create a vm support bundle & upload it (requires ticket number)
  zt-logs-zip         - create a zip file of all ziti logs, cpu & stacks on the machine
  zt-tcpdump          - start a tcpdump session piped to file
  zt-firewall-rules   - print current filter table of NF-INTERCEPT chain - allow traffic inbound
  zt-intercepts       - print current mangle table of NF-INTERCEPT chain - intercept
  zt-upgrade          - upgrade the local ziti software\n
 \033[0;31mExtra Commands:\033[0m
  sar-enable          - enable sar collection
  sar-disable         - disable sar collection
  sar-status          - current status of sysstat
  geneve-enable       - enable geneve ebpf program
  geneve-disable      - disable geneve ebpf program
  geneve-status       - check if geneve ebpf program is enabled
  icmp-enable         - enable system to respond to icmp
  icmp-disable        - disable system to respond to icmp
  icmp-status         - current status of icmp
  hush-net-info       - disable ip & network information from displaying on login
  hush-ubuntu-info    - disable the Ubuntu login banner
  nfhelp-reload       - reload nfhelp menu
  nfhelp-update       - update nfhelp menu
  nfhelp-version      - display nfhelp menu version
  "; else echo -e "\033[0;31mPlease register before you try the help commands\033[0m"; fi
  '
}

# create main aliases
create_aliases() {

    alias ziti="${ZITI_CLI}"
    alias zt-tcpdump="echo Press Ctrl-C to stop dump;export DATE=\$(date +"%y-%m-%d-%s"); sudo tcpdump -w /tmp/ziti-tcpdump-\$DATE.pcap;echo Created /tmp/ziti-tcpdump-\$DATE.pcap; unset DATE"
    alias zt-firewall-rules="sudo iptables -L NF-INTERCEPT -n -t filter"
    alias zt-intercepts="sudo iptables -L NF-INTERCEPT -n -t mangle"
    alias zt-upgrade="[ -e /opt/netfoundry/zt-upgrade ] || (sudo curl -sL https://netfoundry.jfrog.io/artifactory/router-registration/zt-upgrade/release/linux/latest/zt-upgrade > /tmp/zt-upgrade && sudo mv /tmp/zt-upgrade /opt/netfoundry/zt-upgrade && sudo chmod +x /opt/netfoundry/zt-upgrade) ; sudo zt-upgrade"
    alias zt-status="sudo systemctl status ziti-router --no-pager; sudo systemctl status ziti-tunnel --no-pager"
    alias zt-logs-zip="export DATE=\$(date +"%y-%m-%d-%s") ;journalctl -u ziti-tunnel --no-pager --since '1 day ago' > /tmp/ziti-tunnel-\$DATE.log;journalctl -u ziti-router --no-pager --since '1 day ago' > /tmp/ziti-router-\$DATE.log; zip -r /home/$USER/ziti-logs-\$DATE.zip /tmp/ziti*.log /tmp/ziti*.out /tmp/ziti*.pcap; echo Created /home/$USER/ziti-logs-\$DATE.zip; unset DATE; sudo rm /tmp/ziti*"
    alias vm-support-bundle="sudo /opt/netfoundry/vm-support-bundle"
    alias sar-enable="echo 'ENABLED="true"'| sudo tee /etc/default/sysstat"
    alias sar-disable="echo 'ENABLED="false"'| sudo tee /etc/default/sysstat"
    alias sar-status="sudo cat /etc/default/sysstat"
    alias geneve-enable="sudo tc qdisc add dev ${MYIF%:} clsact && sudo tc filter add dev ${MYIF%:} ingress bpf da obj /opt/netfoundry/ebpf/geneve.o sec sk_skb"
    alias geneve-disable="sudo tc qdisc del dev ${MYIF%:} clsact"
    alias geneve-status="sudo tc filter show dev ${MYIF%:} ingress"
    alias icmp-enable="sudo sed -i '/ufw-before-input.*icmp/s/DROP/ACCEPT/g' /etc/ufw/before.rules; sudo ufw reload"
    alias icmp-disable="sudo sed -i '/ufw-before-input.*icmp/s/ACCEPT/DROP/g' /etc/ufw/before.rules; echo WARNING! This will not take affect until after reboot"
    alias icmp-status="sudo grep 'ufw-before-input.*.icmp' /etc/ufw/before.rules"
    alias hush-net-info="touch \$HOME/.hushnet; echo To re-enable this, remove the file .hushnet"
    alias hush-ubuntu-info="touch \$HOME/.hushlogin; echo To re-enable this, remove the file .hushlogin"
    alias nfhelp-reload="source /etc/profile.d/nfhelp.sh"
    alias nfhelp-update="curl -sL https://github.com/netfoundry/edge-router-nfhelp/releases/latest/download/nfhelp.tar.gz > /tmp/nfhelp.tar.gz;sudo tar Cxvfz /etc/profile.d/ /tmp/nfhelp.tar.gz ; source /etc/profile.d/nfhelp.sh; sudo rm /tmp/nfhelp.tar.gz"
    alias nfhelp-version="/etc/profile.d/nfhelp.sh -v"

}

# setup the profile
run_profile(){
    add_netfoundry_path
    print_banner
    print_net_info
    print_binary_info
    print_register
    create_nfhelp
    create_aliases
}

# print version
version(){
    echo "1.0.1"
}

### Main
case ${1} in
  -v) # display version
    version;;
  *) # run profile
    run_profile;;
esac
