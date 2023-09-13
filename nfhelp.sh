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
#  See https://github.com/netfoundry/edge-router-nfhelp/blob/main/CHANGELOG.md
#
### Export Environment variables
export CLOUD_ZITI_HOME="/opt/netfoundry"
export OPEN_ZITI_HOME="/opt/openziti"
export ZITI_HOME="${CLOUD_ZITI_HOME}/ziti"
export ZITI_CLI="${ZITI_HOME}/ziti"
export EBPF_BIN="${OPEN_ZITI_HOME}/bin"

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
    MYPUBIP=$(curl -s --connect-timeout 15 https://ipinfo.io/ | jq -r .ip)

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

  if [[ -f ${ZITI_CLI} ]]; then
    ZITI_CLI_VERSION=$(${ZITI_CLI} --version | cut -d"v" -f 2)
    if vercomp "0.26.11" "${ZITI_CLI_VERSION}"; then
      printf '\nziti version: %s' "${ZITI_CLI_VERSION}"
      LOG_COMMAND="ops log-format -a"
      STACK_COMMAND="agent"
      alias zt-router-version="${ZITI_CLI} --version 2> /dev/null | cut -d'v' -f 2"
      if vercomp "0.28.0" "${ZITI_CLI_VERSION}"; then
        PID_FLAG="-p"
      else
        PID_FLAG=""
      fi
    else
      printf '\nCLI version: %s' "${ZITI_CLI_VERSION}"
      export ZITI_ROUTER="${ZITI_HOME}/ziti-router/ziti-router"
      LOG_COMMAND="log-format -a"
      STACK_COMMAND="ps"
      alias zt-router-version="${ZITI_ROUTER} version 2> /dev/null | cut -d'v' -f 2"
    fi
  fi

  if [[ -f ${ZITI_ROUTER} ]]; then
    ZITI_ROUTER_VERSION=$(${ZITI_ROUTER}  version 2> /dev/null | cut -d"v" -f 2)
    printf '\nRouter version: %s' "${ZITI_ROUTER_VERSION}"
  fi
  if [[ -f /opt/netfoundry/.name ]]; then
    ROUTER_NAME=$(cat /opt/netfoundry/.name)
    printf '\nRouter Name: %s\n\n' "${ROUTER_NAME}"
  fi

}

# print registration information
print_register() {

  if [[ -f /opt/netfoundry/ziti/ziti-router/.is_registered ]]; then
      echo -e "$(cat /opt/netfoundry/.login-readme.registered)"
    elif [[ -f /opt/netfoundry/.login-readme ]]; then
      echo -e "$(cat /opt/netfoundry/.login-readme)"
  fi
  echo -e  "type \033[0;31mnfhelp\033[0m for more commands"
}

# create nfhelp menu
create_nfhelp() {
  
  alias nfhelp='if [[ -f "${ZITI_CLI}" ]]; then echo -e "
 \033[0;31mRouter Commands:\033[0m
  router-registration  - register ziti router
  zt-router-pid        - print process id of currently running ziti-router
  zt-router-version    - print ziti-router version
  zt-router-logs       - tail ziti router logs
  zt-router-restart    - restart ziti-router service
  zt-router-start      - start ziti-router service
  zt-router-stop       - stop ziti-router service
  zt-router-status     - print ziti-router system service status
  zt-router-health     - print current router healthcheck
  zt-erhchecker-update - download/update hc checker script that can be used by program like vrrp to evaluate the state of the edge-router
  zt-status            - print status of all ziti services
  zt-router-cpu        - create pprof cpu of currently running ziti-router
  zt-router-stack      - create stack trace of currently running ziti-router
  zt-router-mem        - create memstats of currently running ziti-router
  zt-router-heap       - create pprof heap of currently running ziti-router\n
 \033[0;31mSupport Commands:\033[0m
  vm-support-bundle   - create a vm support bundle & upload it (requires ticket number)
  zt-logs-zip         - create a zip file of all ziti logs, cpu & stacks on the machine
  zt-tcpdump          - start a tcpdump session piped to file
  zt-firewall-rules   - print current filter table of NF-INTERCEPT chain - allow traffic inbound
  zt-intercepts       - print current mangle table of NF-INTERCEPT chain - intercept
  zt-upgrade          - upgrade the local ziti software\n
 \033[0;31mDiverter Commands:\033[0m 
  diverter-enable         - enable diverter ebpf program
  diverter-disable        - disable diverter ebpf program
  diverter-status         - check if diverter ebpf program is enabled
  diverter-add-user-rules - add all user ingress rules to ebpf map configured in $EBPF_BIN/user/user_rules.sh
  diverter-update         - update the diverter ebpf bytecode to latest version
  diverter-trace          - show ebpf trace logs
  zfw                     - link to the zfw program used to manage ebpf map content\n
 \033[0;31mExtra Commands:\033[0m
  sar-enable             - enable sar collection
  sar-disable            - disable sar collection
  sar-status             - current status of sysstat
  icmp-enable            - enable system to respond to icmp
  icmp-disable           - disable system to respond to icmp
  icmp-status            - current status of icmp
  hush-net-info          - disable ip & network information from displaying on login
  hush-ubuntu-info       - disable the Ubuntu login banner
  nfhelp-reload          - reload nfhelp menu
  nfhelp-update          - update nfhelp menu
  nfhelp-version         - display nfhelp menu version
  "; else echo -e "\033[0;31mPlease register before you try the help commands\033[0m"; fi
  '
}

# Firewall Rule Check based on the tproxy mode
check_firewall() {
  CHECKMODE=`yq '.listeners[] | select(.binding == "tunnel").options.mode' $CLOUD_ZITI_HOME/ziti/ziti-router/config.yml`
  if [ $CHECKMODE == null ] || [ $CHECKMODE == "tproxy" ]; then 
    sudo iptables -L NF-INTERCEPT -n -t filter
  else  
    sudo $EBPF_BIN/zfw -L -f
  fi
}

# Intercept Rule Check based on the tproxy mode
check_intercepts() {
  CHECKMODE=`yq '.listeners[] | select(.binding == "tunnel").options.mode' $CLOUD_ZITI_HOME/ziti/ziti-router/config.yml`
  if [ $CHECKMODE == null ] || [ $CHECKMODE == "tproxy" ]; then 
    sudo iptables -L NF-INTERCEPT -n -t mangle
  else  
    sudo $EBPF_BIN/zfw -L -i
  fi
}

# Diverter update function to the latest version
diverter_update() {
  if [[ $(${ZITI_CLI} --version | cut -d"v" -f 2) > "0.27.2" ]]; then
    arch=`uname -m`
    if [ $arch == "x86_64" ]; then
      arch="amd64"
    fi
    browser_download_url=`curl -s https://api.github.com/repos/netfoundry/zfw/releases/latest | jq --arg arch $arch -r '.assets[] | select((.name | test("router")) and (.name | test($arch))).browser_download_url'`
    curl -sL $browser_download_url > /tmp/zfw.deb
    sudo dpkg -i /tmp/zfw.deb
    rm /tmp/zfw.deb
    sudo zfw -Q
    sudo systemctl restart ziti-router
  else
    echo "INFO: ebpf cannot be installed, the installed ziti version is not 0.27.3 or higher."
  fi
}

# Diverter enable function
diverter_enable() {
  status=`dpkg -s zfw-router 2>/dev/null`
  if [[ `echo $status |awk -F'[[:space:]]+|=' '{print $4}'` == "install" ]] && [[ -f $EBPF_BIN/start_ebpf_router.py ]]; then
    sudo $EBPF_BIN/start_ebpf_router.py
    sudo systemctl restart ziti-router
  else 
    echo 'INFO: ebpf not installed, run diverter-update to install it.'
  fi
}
# Diverter edisable function
diverter_disable() {
  status=`dpkg -s zfw-router 2>/dev/null`
  if [[ `echo $status |awk -F'[[:space:]]+|=' '{print $4}'` == "install" ]] && [[ -f $EBPF_BIN/revert_ebpf_router.py ]]; then
    sudo $EBPF_BIN/revert_ebpf_router.py
  else 
    echo 'INFO: ebpf not installed, run diverter-update to install it.'
  fi
}

# Health Checker Script update function to the latest version
erhchecker_update() {
  if [[ $(${ZITI_CLI} --version | cut -d"v" -f 2) > "0.28.0" ]]; then
    arch=`uname -m`
    if [ $arch == "x86_64" ]; then
      arch="amd64"
    fi
    browser_download_url=`curl -s https://api.github.com/repos/netfoundry/edge-router-health-checker/releases/latest | jq --arg arch $arch -r '.assets[] | select(.name | test($arch)).browser_download_url'`
    curl -sL $browser_download_url > /tmp/erhchecker.tar.gz
    sudo tar xzf /tmp/erhchecker.tar.gz -C $CLOUD_ZITI_HOME
    rm /tmp/erhchecker.tar.gz
  else
    echo "INFO: erhchecker script cannot be installed, the installed ziti version is not 0.28.1 or higher."
  fi
}

# create main aliases
create_aliases() {

    alias router-registration="sudo /opt/netfoundry/router-registration"
    alias ziti="${ZITI_CLI}"
    alias zt-router-pid="systemctl show --property MainPID --value ziti-router"
    alias zt-router-logs="journalctl -u ziti-router -efo cat | ${ZITI_CLI} ${LOG_COMMAND}"
    alias zt-router-cpu="export DATE=\$(date +"%y-%m-%d-%s") ;sudo -E ${ZITI_CLI} ${STACK_COMMAND} pprof-cpu ${PID_FLAG} \$(systemctl show --property MainPID --value ziti-router) > /tmp/ziti-router-cpu-\$DATE.out; echo Created /tmp/ziti-router-cpu-\$DATE.out; unset DATE"
    alias zt-router-stack="export DATE=\$(date +"%y-%m-%d-%s") ;sudo ${ZITI_CLI} ${STACK_COMMAND} stack ${PID_FLAG} \$(systemctl show --property MainPID --value ziti-router) > /tmp/ziti-router-stack-\$DATE.out; echo Created /tmp/ziti-router-stack-\$DATE.out; unset DATE"
    alias zt-router-mem="export DATE=\$(date +"%y-%m-%d-%s") ;sudo ${ZITI_CLI} ${STACK_COMMAND} memstats ${PID_FLAG} \$(systemctl show --property MainPID --value ziti-router) > /tmp/ziti-router-mem-\$DATE.out; echo Created /tmp/ziti-router-mem-\$DATE.out; unset DATE"
    alias zt-router-heap="export DATE=\$(date +"%y-%m-%d-%s") ;sudo ${ZITI_CLI} ${STACK_COMMAND} pprof-heap ${PID_FLAG} \$(systemctl show --property MainPID --value ziti-router) > /tmp/ziti-router-heap-\$DATE.out; echo Created /tmp/ziti-router-heap-\$DATE.out; unset DATE"
    alias zt-router-restart="sudo systemctl restart ziti-router"
    alias zt-router-start="sudo systemctl start ziti-router"
    alias zt-router-stop="sudo systemctl stop ziti-router"
    alias zt-router-status="sudo systemctl status ziti-router --no-pager"
    alias zt-router-health="curl -k https://localhost:8081/health-checks"
    alias zt-erhchecker-update=erhchecker_update
    alias zt-tcpdump="echo Press Ctrl-C to stop dump;export DATE=\$(date +"%y-%m-%d-%s"); sudo tcpdump -w /tmp/ziti-tcpdump-\$DATE.pcap;echo Created /tmp/ziti-tcpdump-\$DATE.pcap; unset DATE"
    alias zt-firewall-rules="check_firewall"
    alias zt-intercepts="check_intercepts"
    alias zt-upgrade="sudo /opt/netfoundry/zt-upgrade"
    alias zt-status="sudo systemctl status ziti-router --no-pager; sudo systemctl status ziti-tunnel --no-pager"
    alias zt-logs-zip="export DATE=\$(date +"%y-%m-%d-%s") ;journalctl -u ziti-tunnel --no-pager --since '1 day ago' > /tmp/ziti-tunnel-\$DATE.log;journalctl -u ziti-router --no-pager --since '1 day ago' > /tmp/ziti-router-\$DATE.log; zip -r /home/$USER/ziti-logs-\$DATE.zip /tmp/ziti*.log /tmp/ziti*.out /tmp/ziti*.pcap; echo Created /home/$USER/ziti-logs-\$DATE.zip; unset DATE; sudo rm /tmp/ziti*"
    alias vm-support-bundle="sudo /opt/netfoundry/vm-support-bundle"
    alias sar-enable="echo 'ENABLED="true"'| sudo tee /etc/default/sysstat"
    alias sar-disable="echo 'ENABLED="false"'| sudo tee /etc/default/sysstat"
    alias sar-status="sudo cat /etc/default/sysstat"
    alias diverter-enable=diverter_enable
    alias diverter-disable=diverter_disable
    alias diverter-status="if [ -f $EBPF_BIN/zfw ]; then sudo $EBPF_BIN/zfw -L -E; else echo 'INFO: ebpf not installed, run diverter-update to install it.'; fi"
    alias diverter-add-user-rules="if [ -f $EBPF_BIN/zfw ] && [ -f $EBPF_BIN/user/user_rules.sh ]; then sudo $EBPF_BIN/user/user_rules.sh; else echo 'INFO: ebpf not installed or user rules script is not configured, run diverter-update to install it or configure user rules script.'; fi"
    alias diverter-update=diverter_update
    alias diverter-trace="sudo cat /sys/kernel/debug/tracing/trace_pipe"
    alias zfw="sudo zfw"
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
    echo "1.4.4"
}

### Main
case ${1} in
  -v) # display version
    version;;
  *) # run profile
    run_profile;;
esac
``
