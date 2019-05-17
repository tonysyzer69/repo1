#!/bin/bash
###
###
###    Purpose: Lifecycle Event Driven for Device42 and Stackstorm
###
### #####3###################################################### ##

date1=`date +"%y-%m-%d-%H:%M:%S"`
stackadmin=tla@zoox.com

# help function
display_help() {
cat << EOF

Usage: !d42 [paramter1] [paramter2]

paramter1: Device42 lifecycle event
    - createdevice
    - createvm
    - playbook
    - createdhcp
    - createmachine
    - pxebootmachine

paramter2: Hostname

Command Line help:
    slack> !d42 --help
    slack> !d42 createdevice --help
    slack> !d42 createvm --help

EOF
    exit 0
}


# help createvm function
display_createvm_help() {
cat << EOF
Create Vsphere VM.

Required Parameters:
    servername
        server to create
        Type: string

Optional Parameters:
    cpu
        If no - then default is 1
        Type: integer

    memory
        If no - then default is 4096
        Type: integer

    serverip
        If yes - then skip adding ip address to device42 and PowerDNS
        Type: string

    datadisk
        If yes - then mount point(s) added to storage_map.csv, multiple
        disks are separated by space. eg: datadisk:(100 300)
        Type: integer (GB)

    mountpoint
        If yes - then disk(s) added to storage_map.csv, multiple mount
        points are separated by space.  eg: mountpoint:(data1 data2)
        Type: string

    ostemplate
        If no - then default is ubuntu 16.04
        Enum: ostemplate:ubuntu16, ostemplate:ubuntu18,
        ostemplate:windows2016, ostemplate:windows2012
        Type: string

    jira_issue
        If no - then stackstorm create jira ticket
        eg: jira_issue:ITOPS-105
        Type: string

    jira_component
        If no - then default is Automation
        Type: string

    jira_assignee
        If no - then default is svc-jira-stackstorm
        Type: string

    datastore
        If no - then default SUN-QNAS01-GP for sun-vcenter01,
        fos-qnas01-grid-ds01 for fos-gridvcenter01 and 
        fos-qnas01-esx-ds01 for fos-vcenter01.
        eg: datastore:fos-qnas01-esx-ds01
        Type: string

    resourcepool
        If no - then default PROD-A for sun-vcenter01,
        FOS-GRID for fos-gridvcenter01 and fos-prod01 for fos-vcenter01
        eg: resourcepool:fos-prod01
        Type: string

    domain
        If no - then set to zooxlabs.com
        Type: string

    host_group
        Server Type
        If no - then default is Production
        Enum: windows, Production, Development, Test
        Type: string

    owner
        If no - then set to Unknown
        eg: owner:"firstname last_initial"
        Type: string

    purpose
        If no - then set to Unknown
        eg: purpose:"3dx dev"
        Type: string

    skip-playbook
        If yes - then skip running playbook to create vm and run role

    skip-git
        If yes - then skip git commit to repo

    skip-d42
        If yes - then skip add ip to device42

    skip-pdns
        If yes - then skip add ip to powerdns

    skip-jira
        If yes - then skip create jira ticket

    add-host
        If yes - add servername/ip to local host file

EXAMPLE
    - Create a default VM (Ubuntu 16.04, sla-tst01 has DNS record)
      slack> !d42 createvm servername:sla-tst01

    - Create a default VM (Ubuntu 16.04, sla-tst01 has no DNS record)
      slack> !d42 createvm servername:sla-tst01 add-host

    - Create a Windows VM
      slack> !d42 createvm servername:sla-tst01 host_group:windows ostemplate:windows2016 remote_desktop_user:testuser

    - Create a customization specification VM
      slack> !d42 createvm servername:sla-tst01 cpu:2 memory:8092 datadisk:"100 200" mountpoint:"data storage" owner:"guest user" purpose:"test server" serverip:10.64.1.17 ostemplate:ubuntu18 jira_issue:ITOPS-1014 zooxlabs_admin:SG-Jira-Test-Admins

EOF
    exit 0
}

# help createdevice function
display_createdevice_help() {
cat << EOF
Create Device42/PowerDNS record.

Required Parameters:
    servername
        server to create
        Type: string

    type
        Server Type 
        Enum: virtual, physical, blade, gpu, storage
        Type: string

Optional Parameters:
    host_group
        Server Type 
        If no - then default is Production
        Enum: windows, Production, Development, Test
        Type: string

    add-host
        If yes - add servername/ip to local host file

EXAMPLE

    - Create virtual device
      slack> !d42 createdevice servername:sla-tst01 type:virtual

    - Create windows virtual device
      slack> !d42 createdevice servername:sun-virtual01 type:virtual host_group:windows

    - Create multiple virtual devices
      slack> !d42 createdevice servername:sla-tst01,sla-tst02 type:virtual

    - Create blade device with IP address
      slack> !d42 createdevice servername:sun-blade01 ipaddress:10.65.5.155 type:blade

    - Create blade device with IP and MAC address
      slack> !d42 createdevice servername:sun-blade01 ipaddress:10.65.5.155 mac_address:"ac:1f:6b:57:f6:65" type:blade

EOF
    exit 0
}

# help playbook function
display_playbook_help() {
cat << EOF
Run ansible playbook.

Required Parameters:
    servername
        Ansible --limit host 
        Type: string

Optional Parameters:

    role
        Ansible playbook roles. If left empty, default value will be used:
        Ubuntu: linux, pbis, sudoers
        Windows: windows, join_domain
        Type: string

    zooxlabs-admin
        Group grant sudo access to Ubuntu server.
	Type: string

    remote_desktop_user
        User add to remote desktop access list.
	Type: string

EXAMPLE

    - Run playbook with default roles.
      slack> !d42 playbook servername:sla-tst01

    - Run playbook with multiple hosts and roles.
      slack> !d42 playbook servername:sla-tst01,fos-tla01 role:sudoers zooxlabs-admin:SG-Jira-Test-Admins

    - Apply filebeat role with default log files.
      Default paths: /var/log/syslog,/var/log/auth.log
      Slack> !d42 playbook fos-tst02 role:filebeat

    - Apply filebeat role with specific log files.
      Slack> !d42 playbook fos-tst02 role:filebeat paths:/var/log/nginx/access.log,/var/log/nginx/error.log

    - Enable haproxy jira prod
      Slack> !d42 playbook sun-hapjira01-prod,sun-hapjira02-prod role:enable_haproxy_service backend:jiraprod

    - Disable haproxy jira prod
      !d42 playbook sun-hapjira01-prod,sun-hapjira02-prod role:disable_haproxy_service backend:jiraprod

EOF
    exit 0
}

# help createdhcp function
display_createdhcp_help() {
cat << EOF
Create Rebar DHCP reservation.

Required Parameters:
    servername
        Rebar machine name
        Type: string

    mac_address
        Rebar machine mac address
        Type: string

Optional Parameters:

    ipaddress
        Rebar machine ip address. If left empty, default value
        from DNS is used.
        Type: string

EXAMPLE

    - Create DHCP reservation
      slack> !d42 createdhcp servername:sla-mb14-a13 mac_address:ac:1f:6b:57:f6:6e

EOF
    exit 0
}

# help createmachine function
display_createmachine_help() {
cat << EOF
Create Rebar machine.

Required Parameters:
    servername
        Rebar machine name
        Type: string

Optional Parameters:

    profile
        Value of profile on Device. If left empty,
        default value is ZooxBox.
        Enum: ZooxBox, sla-admin01-ssh-access,
              ipmi-config, Ubuntu-sda-boot
        Type: string

    workflow
        Value of workflow on Device. If left empty,
        default value is ubuntu16-install.
        Enum: ubuntu16-install, ubuntu14.04-Install
        Type: string

EXAMPLE

    - Create default Rebar machine
      slack> !d42 createmachine servername:sla-mb14-a13

    - Create Rebar machine with profile and workflow.
      slack> !d42 createmachine servername:sla-mb14-a13 profile:ipmi-config workflow:ubuntu14.04-Install

    - Create Rebar machine with multiple profiles.
      slack> !d42 createmachine servername:sla-mb14-a13 profile:ZooxBox,Ubuntu-Raid0 workflow:ubuntu16-install

EOF
    exit 0
}

# help pxebootmachine function
display_pxebootmachine_help() {
cat << EOF
PXE boot rebar machine.

Required Parameters:
    servername
        Rebar machine name
        Type: string

Optional Parameters:
    jira_issue
        If no - then stackstorm create jira ticket
        eg: jira_issue:ITOPS-105
        Type: string

    jira_component
        If no - then default is Automation
        Type: string

    jira_assignee
        If no - then default is svc-jira-stackstorm
        Type: string

EXAMPLE

    - PXE Boot machine
      slack> !d42 pxebootmachine servername:sla-mb14-a13

EOF
    exit 0
}


# Display help if running without argument
if [ $# -eq 0 ]; then
    display_help
    exit 0
fi

# display help
if [ "$1" == "help" ] || [ "$1" == "-h" ] || [ "$1" == "-help" ] || [ "$1" == "--help" ] ; then
    display_help
    exit 0
fi

# display createvm help
if [ "$1" == "createvm" ] && [ "$2" == "--help" ]; then
    display_createvm_help
    exit 0
fi

# display createdevice help
if [ "$1" == "createdevice" ] && [ "$2" == "--help" ]; then
    display_createdevice_help
    exit 0
fi

# display playbook help
if [ "$1" == "playbook" ] && [ "$2" == "--help" ]; then
    display_playbook_help
    exit 0
fi

# display createdhcp help
if [ "$1" == "createdhcp" ] && [ "$2" == "--help" ]; then
    display_createdhcp_help
    exit 0
fi

# display createmachine help
if [ "$1" == "createmachine" ] && [ "$2" == "--help" ]; then
    display_createmachine_help
    exit 0
fi

# display pxebootmachine help
if [ "$1" == "pxebootmachine" ] && [ "$2" == "--help" ]; then
    display_pxebootmachine_help
    exit 0
fi

# Set script home directory
user_home=/home/stanley

# Set repo directory
repo=$user_home/git

# slack user
slack_user=$user_home/slack_user

# slack_log
slack_log=$user_home/audit_log/slack.log


# ITservice repo
git_dir=$repo/itservice/

# Device42 host and password
d42_host=`grep d42_host: $user_home/d42_view|awk -F":" '{print $2}'`
d42_passwd=`cat /etc/st2/keys/d42_password`

# Rebar drp host
sla_drp_server=`grep sla_drp_server: /opt/stackstorm/configs/digitalrebar.yaml|awk -F":" '{print $2}'|xargs`
sun_drp_server=`grep sun_drp_server: /opt/stackstorm/configs/digitalrebar.yaml|awk -F":" '{print $2}'|xargs`
fos_drp_server=`grep fos_drp_server: /opt/stackstorm/configs/digitalrebar.yaml|awk -F":" '{print $2}'|xargs`

# User in Device42 with view access to all script secrets
d42_view_user=`grep username: $user_home/d42_view|awk -F":" '{print $2}'`
d42_view_password=`grep password: $user_home/d42_view|awk -F":" '{print $2}'`

# PowerDNS host and API key
pdns_host=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=pdns_host&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`
pdns_password=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=pdns_password&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`
apikey=`cat /etc/st2/keys/apikey`

# Jira host and URL
jira_host=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=jira_host&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`
jira_host_url=https://$jira_host/browse

# d42 variables 
export D42_USER=admin
export D42_PWD="$d42_passwd"
export D42_URL=https://$d42_host.zooxlabs.com
export D42_SKIP_SSL_CHECK=False
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
export D42_SKIP_SSL_CHECK=False

# IPMI tools install directory
ipmi_tool=/opt/SMCIPMITool/SMCIPMITool

# Linux login for ansible playbook
linux_username=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=linux_username&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`
linux_password_tmp1=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=linux_password&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`
linux_password_tmp2=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=linux_password_sre&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`


# IPMI login
ipmi_username=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=ipmi_username&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`
ipmi_password=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=ipmi_password&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`

# Rebar login
drp_username=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=drp_username&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`
drp_password=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=drp_password&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`

# Stackstorm API key
export ST2_API_KEY=$apikey

case $1 in
    createvm)
        lifecycle=13
        ;;
    createdevice)
        lifecycle=14
        ;;
    playbook)
        lifecycle=16
        ;;
    createdhcp)
        lifecycle=17
        ;;
    createmachine)
        lifecycle=18
        ;;
    pxebootmachine)
        lifecycle=19
        ;;
    *)
        lifecycle=99
        ;;
    esac

# Lifecycle Event
lce=$user_home/slack/$lifecycle
[[ ! -d $user_home/slack/$lifecycle ]] && mkdir $user_home/slack/$lifecycle

# DO NOT PROCESS marker
#dnp=$lce/dnp

# Ansible template directory
TF_OUT_FILE_TMP=$repo/itservice/infra/ansible/host_vars

### # Starting Main

echo -e "$date1 - $1 $2 $3 $4 $5 $6 $7 $8 $9 ${10} ${11} ${12} ${13} ${14} ${15}" >> $slack_log



# Output all Device42 Notes to a file ( from slack )
echo $2|egrep -q servername: && server_all_tmp=`echo $2|awk -F":" '{print $2}'` || server_all_tmp=$2
server_all=$(echo $server_all_tmp | tr "[,:;]" "\n")
for servername in $server_all
do

    echo $servername|egrep -q zooxlabs.com &&
    (
        echo "DO NOT use FQN hostname, only short name" | tee -a $audit_log 
        echo "Slack convert FQN hostname to http://hostname" | tee -a $audit_log
        echo "...Exit" | tee -a $audit_log
    ) ||
    (
        if [ $lifecycle -eq "13" ] || [ $lifecycle -eq "14" ] || [ $lifecycle -eq "16" ] || [ $lifecycle -eq "17" ] || [ $lifecycle -eq "18" ] || [ $lifecycle -eq "19" ]; then
            # Capture all parameter from slack
            vmnotes=$lce/vmnotes-$servername
            vmnotes_tmp=$lce/vmnotes_tmp-$servername
            vmnotes_14=$user_home/slack/14/vmnotes-$servername
            vmnotes_tmp_14=$user_home/slack/14/vmnotes_tmp-$servername
            echo -e "$1\n$2\n$3\n$4\n$5\n$6\n$7\n$8\n$9\n${10}\n${11}\n${12}\n${13}\n${14}\n${15}" > $vmnotes_tmp

            # format into columns, key value
            awk -F'"' '$0=$1$2' $vmnotes_tmp > $vmnotes
            awk -F'"' '$0=$3$4' $vmnotes_tmp >> $vmnotes
            awk -F'"' '$0=$5$6' $vmnotes_tmp >> $vmnotes
            awk -F'"' '$0=$7$8' $vmnotes_tmp >> $vmnotes
            awk -F'"' '$0=$9$10' $vmnotes_tmp >> $vmnotes
            awk -F'"' '$0=$11$12' $vmnotes_tmp >> $vmnotes
            awk -F'"' '$0=$13$14' $vmnotes_tmp >> $vmnotes
            awk -F'"' '$0=$15$16' $vmnotes_tmp >> $vmnotes
            awk -F'"' '$0=$17$18' $vmnotes_tmp >> $vmnotes
            awk -F'"' '$0=$19$20' $vmnotes_tmp >> $vmnotes
            awk -F'"' '$0=$20$21' $vmnotes_tmp >> $vmnotes
            awk -F'"' '$0=$22$23' $vmnotes_tmp >> $vmnotes
            awk -F'"' '$0=$24$25' $vmnotes_tmp >> $vmnotes
            awk -F'"' '$0=$26$27' $vmnotes_tmp >> $vmnotes
            awk -F'"' '$0=$28$29' $vmnotes_tmp >> $vmnotes
        fi

        [[ $lifecycle -eq "16" ]] &&
        (
            curl -k -s -X GET -u 'admin:adm!nd42' "https://fos-d42/api/1.0/devices?name=sun-hapjira02-prod"|jshon|egrep -q $servername.zooxlabs.com && servername=$servername.zooxlabs.com  || :
            sshpass -p "$linux_password_tmp1" ssh -o "StrictHostKeyChecking=no" -l zoox $servername hostname > $lce/ssh1.log 2>&1 && echo $linux_password_tmp1 > $lce/$servername-linux-password
            sshpass -p "$linux_password_tmp2" ssh -o "StrictHostKeyChecking=no" -l zoox $servername hostname > $lce/ssh2.log 2>&1 && echo $linux_password_tmp2 > $lce/$servername-linux-password
        )


        if [ $lifecycle -eq "13" ] || [ $lifecycle -eq "16" ] || [ $lifecycle -eq "17" ] || [ $lifecycle -eq "18" ] || [ $lifecycle -eq "19" ]; then

            jira_component_tmp=`grep jira_component $vmnotes|awk -F"[:=]" '{print $2}'`
            [[ -z "$jira_component_tmp" ]] && jira_component="Automation" || jira_component=$jira_component_tmp

            jira_assignee_tmp=`grep jira_assignee $vmnotes|awk -F"[:=]" '{print $2}'`
            [[ -z "$jira_assignee_tmp" ]] && jira_assignee="tla" || jira_assignee=$jira_assignee_tmp

            slack_device_id=`curl -k -s -X GET -u "$D42_USER:$d42_passwd" "https://$d42_host/api/1.0/devices?name=$servername"| jshon |grep -A 3 $servername'",'|grep device_id|awk '{print $NF}'`
            deviceid=$slack_device_id

            # Device42 deviceid (number) for server
            server_deviceid=$lce/$servername-deviceid-$deviceid

            # Set deviceid for a server
            touch $server_deviceid

            # ansible playbook output log
            ansible_role_log=$user_home/slack/ansible_role_log-$servername
            ansible_playbook_log=$user_home/slack/ansible_playbook_log-$servername

            # User output log
            audit_log=$user_home/slack/audit-$servername

            # Output jira log
            jira_file=$user_home/slack/jira.txt-$servername
        fi
    )
done

### # Function - Add host to local /etc/hosts
add-host() {
        echo "add-host()" | tee -a $audit_log
        echo "add-host: Add $serverip $servername to local host file"| tee -a $audit_log
        egrep -q -i $servername /etc/hosts && echo "$servername already in /etc/hosts" || sudo -u root bash -c "echo $serverip $servername $servername.zooxlabs.com >> /etc/hosts"
}

### # Function - find next available IP via Device42
find-next-ip() {
    echo "find-next-ip()" | tee -a $audit_log
    echo "" | tee -a $audit_log
    #cat $vmnotes|grep type: |egrep -q virtual &&  
    if grep type: $vmnotes|egrep -q virtual || egrep -q add-host $vmnotes; then
    #(
        echo "find-next-ip: $servername is virtual $1" | tee -a $audit_log
        curl -X GET -u "$D42_USER:$d42_passwd" https://$d42_host/api/1.0/ips/subnet_id/111/ --insecure|jshon > ~/slack/10.65.4.0.tmp
        grep 10.65.4 ~/slack/10.65.4.0.tmp|awk -F"." '{print $NF}'|sed 's/"//g'|sed 's/,//g' > ~/slack/10.65.4.0
        echo 255 >> ~/slack/10.65.4.0
        pdns_next_ip=`awk '$1!=p+1{print p+1"-"$1-1}{p=$1}' ~/slack/10.65.4.0|head -1|awk -F"-" '{print $1}'`
        echo 10.65.4.$pdns_next_ip > ~/slack/pdns_next_ip-$servername
    fi
    #)

    # Compute (blade) bare metal, physical
    cat $vmnotes|grep type: |egrep -q "blade|physical" &&  
    (
        echo "find-next-ip: $servername is blade(compute) or physical $1" | tee -a $audit_log
        curl -X GET -u "$D42_USER:$d42_passwd" https://$d42_host/api/1.0/ips/subnet_id/111/ --insecure|jshon > ~/slack/10.65.5.0.tmp
        grep 10.65.5 ~/slack/10.65.5.0.tmp|awk -F"." '{print $NF}'|sed 's/"//g'|sed 's/,//g' > ~/slack/10.65.5.0
        echo 255 >> ~/slack/10.65.5.0
        pdns_next_ip=`awk '$1!=p+1{print p+1"-"$1-1}{p=$1}' ~/slack/10.65.5.0|head -1|awk -F"-" '{print $1}'`
        echo 10.65.5.$pdns_next_ip > ~/slack/pdns_next_ip-$servername
    )

    # GPU Node
    cat $vmnotes|grep type: |egrep -q gpu &&  
    (
        echo "find-next-ip: $servername is gpu node $1" | tee -a $audit_log
        curl -X GET -u "$D42_USER:$d42_passwd" https://$d42_host/api/1.0/ips/subnet_id/111/ --insecure|jshon > ~/slack/10.65.6.0.tmp
        grep 10.65.6 ~/slack/10.65.6.0.tmp|awk -F"." '{print $NF}'|sed 's/"//g'|sed 's/,//g' > ~/slack/10.65.6.0
        echo 255 >> ~/slack/10.65.6.0
        pdns_next_ip=`awk '$1!=p+1{print p+1"-"$1-1}{p=$1}' ~/slack/10.65.6.0|head -1|awk -F"-" '{print $1}'`
        echo 10.65.6.$pdns_next_ip > ~/slack/pdns_next_ip-$servername
    )

    # Storage
    cat $vmnotes|grep type: |egrep -q storage &&  
    (
        echo "find-next-ip: $servername is storage $1" | tee -a $audit_log
        curl -X GET -u "$D42_USER:$d42_passwd" https://$d42_host/api/1.0/ips/subnet_id/111/ --insecure|jshon > ~/slack/10.65.7.0.tmp
        grep 10.65.7 ~/slack/10.65.7.0.tmp|awk -F"." '{print $NF}'|sed 's/"//g'|sed 's/,//g' > ~/slack/10.65.7.0
        echo 255 >> ~/slack/10.65.7.0
        pdns_next_ip=`awk '$1!=p+1{print p+1"-"$1-1}{p=$1}' ~/slack/10.65.7.0|head -1|awk -F"-" '{print $1}'`
        echo 10.65.7.$pdns_next_ip > ~/slack/pdns_next_ip-$servername
    )
    echo "***************************************" | tee -a $audit_log
}

### # Function - Provision VM
playbook-spin() {
    echo "playbook-spin()" | tee -a $audit_log
    st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: skip-playbook"|grep value:|awk '{print $NF}'|egrep -q -i yes  && echo "playbook-spin: skip running playbook" | tee -a $audit_log || 
    (
        export PYTHONWARNINGS="ignore:Unverified HTTPS request"
        cd $repo/itservice/infra/ansible
#        ansible-playbook -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  $repo/itservice/infra/ansible/playbooks/spinup.yml --extra-vars="vcenter_password=$vsphere_password vsphere_host=$vcenter_host vsphere_user=$vcenter_user" --vault-password-file=/etc/st2/keys/.vault |tee -a $ansible_playbook_log
        echo " "
    )
    echo "****************************************" | tee -a $audit_log
}

### # Function - Base roles for new VM
apply-base-role() {
    echo "apply-base-role()" | tee -a $audit_log
    st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: skip-playbook"|grep value:|awk '{print $NF}'|egrep -q -i yes && echo "apply-base-role: skip running playbook/role" | tee -a $audit_log || 
    (

        ansible_role_tmp=`grep role: $vmnotes|awk -F":" '{print $NF}'`
        if [ -z "$ansible_role_tmp" ]; then
            st2 run device42.get_device_by_id device_id=$deviceid|egrep "service_level:"|egrep -q -i windows && ansible_role="windows,join_domain" || ansible_role="linux,pbis,sudoers"
        else
            ansible_role=$ansible_role_tmp
        fi

        export PYTHONWARNINGS="ignore:Unverified HTTPS request"

        cd $repo/itservice/infra/ansible

#        st2 run device42.get_device_by_id device_id=$deviceid|egrep "service_level:"|egrep -q -i windows && ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook_windows.yml  -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  --tags $ansible_role --vault-password-file=/etc/st2/keys/.vault |tee -a $ansible_role_log ||sshpass -p "$linux_password_tmp1"  ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook.yml -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  --ask-sudo-pass --extra-vars "ansible_user=$linux_username ansible_password=$linux_password_tmp1" --tags $ansible_role --vault-password-file=/etc/st2/keys/.vault |tee -a $ansible_role_log
        echo " " | tee -a $audit_log
    )
    echo "****************************************" | tee -a $audit_log
}

### # Function - Main playbook
run-playbook() {
    vmnotes=$lce/vmnotes-$servername
    echo $servername|egrep -q zooxlabs.com && : ||
    (
    echo "Run_playbook lifecycle event" | tee $audit_log
    echo "****************************************" | tee -a $audit_log
    echo "run-playbook()" | tee -a $audit_log 
    audit_log=$user_home/slack/audit-$servername
    # Check if device exist 
    curl -k -s -X GET -u "$D42_USER:$d42_passwd" "https://$d42_host/api/1.0/devices?name=$servername"| jshon|egrep -q $servername
    if [ $? -eq 0 ];then
        for servername in `echo $server_all`
        do
            curl -k -s -X GET -u 'admin:adm!nd42' "https://fos-d42/api/1.0/devices?name=sun-hapjira02-prod"|jshon|egrep -q $servername.zooxlabs.com && servername=$servername.zooxlabs.com  || :
            deviceid=`curl -k -s -X GET -u "$D42_USER:$d42_passwd" "https://$d42_host/api/1.0/devices?name=$servername"| jshon |grep '"device_id":'|head -1 |awk '{print $2}'`
            #nc -z $servername 22 > /dev/null 2>&1
            # Check if server is online
            ping -c 2 $servername > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                mountpoint1_tmp=`grep mountpoint1 $vmnotes|awk -F":" '{print $NF}'`
                [[ -z "$mountpoint1_tmp" ]] && mountpoint1="/data1" || mountpoint1=$mountpoint1_tmp
                mountpoint2_tmp=`grep mountpoint2 $vmnotes|awk -F":" '{print $NF}'`
                [[ -z "$mountpoint2_tmp" ]] && mountpoint2="/data2" || mountpoint2=$mountpoint2_tmp
                zooxlabs_admin_tmp=`grep zooxlabs-admin: $vmnotes|awk -F":" '{print $NF}'`
                echo $zooxlabs_admin|egrep -q -i "null|''" && zooxlabs_admin="" || zooxlabs_admin=$zooxlabs_admin_tmp

                #ansible_role_tmp=`grep role: $vmnotes|awk -F":" '{print $NF}'`
                ansible_role=`grep role: $vmnotes|awk -F":" '{print $NF}'`
           
                filebeat_paths_tmp=`grep paths: $vmnotes|awk -F":" '{print $NF}'`
                egrep -q paths: $vmnotes && 
                (
                    cat <<EOF>"$lce/$servername-filebeat"
filebeat_paths:
EOF
                    for i in $(echo $filebeat_paths_tmp | sed "s/,/ /g")
	            do
                        echo "  - $i" >> $lce/$servername-filebeat
                    done
                )
            
                export PYTHONWARNINGS="ignore:Unverified HTTPS request"
                echo "***************************************" | tee -a $audit_log
                if [ -z $ansible_role ]; then
                    st2 run device42.get_device_by_id device_id=$deviceid|egrep "service_level:"|egrep -q -i windows && ansible_role=join_domain
                elif [ $ansible_role == "enable_haproxy_service" ] || [ $ansible_role == "disable_haproxy_service" ]; then
                    backend=`grep backend: $vmnotes|awk -F":" '{print $NF}'`
                    if [ $backend  == "lookerdev" ]; then
                        server_backend=lookerdev_cluster
                        backend_host=sun-looker01-dev.zooxlabs.com
                    elif [ $backend  == "lookerprod" ]; then
                        server_backend=looker_cluster
                        backend_host=sun-looker01.zooxlabs.com
                    elif [ $backend  == "jirastg" ]; then
                        server_backend=jirastg_cluster
                        backend_host=jira-stg2.zooxlabs.com
                    elif [ $backend  == "jiraprod" ]; then
                        server_backend=jira_cluster
                        backend_host=jira.zooxlabs.com
                        backend_host2=jira-not-available.zooxlabs.com
                    fi
                fi
 
                cd $repo/itservice/infra/ansible

                if st2 run device42.get_device_by_id device_id=$deviceid|egrep "service_level:"|egrep -q -i windows; then
                    echo "run playbook_windows.yml --> $servername" | tee -a $audit_log
                    ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook_windows.yml  -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  --tags $ansible_role --vault-password-file=/etc/st2/keys/.vault |tee $lce/ansible_role_log-$servername
                else
                    [[ -f $lce/$servername-linux-password ]] &&
                    (
                        linux_password=`cat $lce/$servername-linux-password`
                        if st2 run device42.get_device_by_id device_id=$deviceid|egrep -w "type:"|egrep -q -i "physical|blade"; then
                            echo "type: physical|blade"
                            echo $ansible_role|egrep -q "pbis" && 
                            (
                                echo "run playbook.yml --> $servername" | tee -a $audit_log
                                [[ -z $ansible_role ]] && : || echo "ansible role: $ansible_role"
                                egrep -q paths: $vmnotes && sshpass -p "$linux_password"  ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook.yml -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  --ask-sudo-pass --extra-vars "ansible_user=$linux_username ansible_password=$linux_password mountpoint1=$mountpoint1 mountpoint2=$mountpoint2 zooxlabs_admin=$zooxlabs_admin server_backend=$server_backend backend_host=$backend_host backend_host2=$backend_host2" --extra-vars "@$lce/$servername-filebeat" --tags $ansible_role --vault-password-file=/etc/st2/keys/.vault |tee $lce/ansible_role_log-$servername || sshpass -p "$linux_password"  ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook.yml -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  --ask-sudo-pass --extra-vars "ansible_user=$linux_username ansible_password=$linux_password mountpoint1=$mountpoint1 mountpoint2=$mountpoint2 zooxlabs_admin=$zooxlabs_admin server_backend=$server_backend backend_host=$backend_host backend_host2=$backend_host2" --tags $ansible_role --vault-password-file=/etc/st2/keys/.vault |tee $lce/ansible_role_log-$servername
                            ) || 
                            (
                                echo "run cpu.yml --> $servername" | tee -a $audit_log
                                [[ -z $ansible_role ]] && : || echo "ansible role: $ansible_role"
                                sshpass -p "$linux_password"  ansible-playbook $repo/itservice/infra/ansible/playbooks/cpu.yml -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py --ask-sudo-pass --extra-vars "target=$servername ansible_user=$linux_username ansible_password=$linux_password mountpoint1=$mountpoint1 mountpoint2=$mountpoint2 zooxlabs_admin=$zooxlabs_admin server_backend=$server_backend backend_host=$backend_host" --vault-password-file=/etc/st2/keys/.vault |tee $lce/ansible_role_log-$servername
                            )
                        elif st2 run device42.get_device_by_id device_id=$deviceid|grep "device_sub_type:"|egrep -q gpu; then
                            echo "run gpu.yml --> $servername" | tee -a $audit_log
                            sshpass -p "$linux_password"  ansible-playbook $repo/itservice/infra/ansible/playbooks/gpu.yml -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py --ask-sudo-pass --extra-vars "target=$servername ansible_user=$linux_username ansible_password=$linux_password mountpoint1=$mountpoint1 mountpoint2=$mountpoint2 zooxlabs_admin=$zooxlabs_admin server_backend=$server_backend backend_host=$backend_host" --vault-password-file=/etc/st2/keys/.vault |tee $lce/ansible_role_log-$servername
                        elif st2 run device42.get_device_by_id device_id=$deviceid|grep virtual_subtype|egrep -q EC2; then
                            echo "run playbook-aws.yml --> $servername" | tee -a $audit_log
                            egrep -q paths: $vmnotes && ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook-aws.yml -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername --extra-vars "@$lce/$servername-filebeat"  --tags $ansible_role --vault-password-file=/etc/st2/keys/.vault |tee $lce/ansible_role_log-$servername || ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook-aws.yml -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  --tags $ansible_role --vault-password-file=/etc/st2/keys/.vault |tee $lce/ansible_role_log-$servername
                        else
                            echo "run playbook.yml --> $servername" | tee -a $audit_log
                            echo "Ansible role: $ansible_role" | tee -a $audit_log
                            egrep -q paths: $vmnotes && sshpass -p "$linux_password"  ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook.yml -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  --ask-sudo-pass --extra-vars "ansible_user=$linux_username ansible_password=$linux_password mountpoint1=$mountpoint1 mountpoint2=$mountpoint2 zooxlabs_admin=$zooxlabs_admin server_backend=$server_backend backend_host=$backend_host backend_host2=$backend_host2" --extra-vars "@$lce/$servername-filebeat" --tags $ansible_role --vault-password-file=/etc/st2/keys/.vault |tee $lce/ansible_role_log-$servername || sshpass -p "$linux_password"  ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook.yml -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  --ask-sudo-pass --extra-vars "ansible_user=$linux_username ansible_password=$linux_password mountpoint1=$mountpoint1 mountpoint2=$mountpoint2 zooxlabs_admin=$zooxlabs_admin server_backend=$server_backend backend_host=$backend_host backend_host2=$backend_host2" --tags $ansible_role --vault-password-file=/etc/st2/keys/.vault |tee $lce/ansible_role_log-$servername
                        fi

                        echo "****************************************" | tee -a $audit_log
                        echo " " | tee -a $audit_log
                        mail -s "Slack: Run playbook Status - $servername" $stackadmin < $lce/ansible_role_log-$servername
                    ) || 
                    (
                        echo "Cannot login to $servername...exit"
                        [[ -f $lce/ssh1.log ]] && cat $lce/ssh1.log | tee -a $audit_log
                        [[ -f $lce/ssh2.log ]] && cat $lce/ssh2.log | tee -a $audit_log
                    )
                fi
            else
                host $servername > /dev/null 2>&1 && : || echo "exit... $servername NOT in DNS" | tee -a $audit_log
                nc -z $servername 22 > /dev/null 2>&1 && : || echo "exit... $servername CANNOT ssh" | tee -a $audit_log
                mail -s "Slack: Run playbook Status - $servername" $stackadmin < $audit_log
            fi
        done
    else
        echo "$servername - Device not found....exit"
    fi 
    rm $lce/*linux-password* > /dev/null 2>&1
    )
}

### # Function - Create jira issue
create_jira_issue() {
    echo "create_jira_issue()" | tee -a $audit_log
    echo "*****************************" | tee -a $audit_log
    st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: skip-jira"|grep value:|awk '{print $NF}'|egrep -q -i yes && echo "skip creating jira ticket" || 
    (
        /usr/bin/st2 run jira.create_issue summary="Slack: create_jira_issue lifecycle event $servername" type=Task component=$jira_component assignee=$jira_assignee > $jira_file 2>&1
        [[ -f $jira_file ]] && 
        (
            echo "create jira ticket `grep key: $jira_file |awk '{print $NF}'` via D42" | tee -a $audit_log
            jira_issue=`grep key: $jira_file |awk '{print $NF}'`
        )
        echo "Add comment to $jira_issue" | tee -a $audit_log
        st2 run jira.comment_issue issue_key=$jira_issue comment_text="`cat $audit_log`" | tee -a $audit_log
        echo " "
        echo "*****************************" | tee -a $audit_log
        echo $jira_host_url/$jira_issue >> $audit_log
        echo "" >> $audit_log
    )
}

### # Function - Lifecycle purchasing
purchasing_lc() {
    echo "purchasing_lc()" | tee -a $audit_log
    /usr/bin/st2 run jira.create_issue summary="Slack: purchasing_lc lifecycle event - $servername " type=Task component=$jira_component assignee=$jira_assignee > $jira_file 2>&1
    echo "Create jira ticket" | tee -a $audit_log
    cat $jira_file >> $audit_log
    [[ -f $jira_file ]] && 
    (
        echo "`grep key: $jira_file |awk '{print $NF}'`" | tee -a $audit_log
        jira_issue=`grep key: $jira_file |awk '{print $NF}'`
    )
    echo "Add comment to $jira_issue" | tee -a $audit_log
    st2 run jira.comment_issue issue_key=$jira_issue comment_text="`cat $audit_log`" | tee -a $audit_log
    echo " "
    echo "*****************************" | tee -a $audit_log
    echo $jira_host_url/$jira_issue >> $audit_log
    echo "" >> $audit_log
}

### # Function - Lifecycle mounting
mounting_lc() {
    echo "mounting_lc()" | tee -a $audit_log
    /usr/bin/st2 run jira.create_issue summary="Slack: mounting_lc lifecycle event - $servername " type=Task component=$jira_component assignee=$jira_assignee > $jira_file 2>&1
    [[ -f $jira_file ]] && 
    (
        echo "create jira ticket `grep key: $jira_file |awk '{print $NF}'` via D42" | tee -a $audit_log
        jira_issue=`grep key: $jira_file |awk '{print $NF}'`
    )
    echo "Add comment to $jira_issue" | tee -a $audit_log
    st2 run jira.comment_issue issue_key=$jira_issue comment_text="`cat $audit_log`" | tee -a $audit_log
    echo " "
    echo "*****************************" | tee -a $audit_log
    echo $jira_host_url/$jira_issue >> $audit_log
    echo "" >> $audit_log
}

### # Function - Lifecycle production
production_lc() {
    echo "production_lc()" | tee -a $audit_log
    /usr/bin/st2 run jira.create_issue summary="Slack: production_lc lifecycle event - $servername" type=Task component=$jira_component assignee=$jira_assignee > $jira_file 2>&1
    [[ -f $jira_file ]] && 
    (
        echo "create jira ticket `grep key: $jira_file |awk '{print $NF}'` via D42" | tee -a $audit_log
        jira_issue=`grep key: $jira_file |awk '{print $NF}'`
    )
    echo "Add comment to $jira_issue" | tee -a $audit_log
    st2 run jira.comment_issue issue_key=$jira_issue comment_text="`cat $audit_log`" | tee -a $audit_log
    echo " "
    echo "*****************************" | tee -a $audit_log
    echo $jira_host_url/$jira_issue >> $audit_log
    echo "" >> $audit_log
    mail -s "Slack: production_lc lifecycle Status" $stackadmin < $audit_log
}

### # Function - Lifecycle provisioning
os_provisioning() {
    echo "os_provisioning()" | tee -a $audit_log
    /usr/bin/st2 run jira.create_issue summary="Slack: Provision bare metal - $servername" type=Task component=$jira_component assignee=$jira_assignee > $jira_file 2>&1
    [[ -f $jira_file ]] && 
    (
        echo "create jira ticket `grep key: $jira_file |awk '{print $NF}'` via D42" | tee -a $audit_log
        jira_issue=`grep key: $jira_file |awk '{print $NF}'`
    )
    echo "Add comment to $jira_issue" | tee -a $audit_log
    st2 run jira.comment_issue issue_key=$jira_issue comment_text="`cat $audit_log`" | tee -a $audit_log
    echo " "
    echo "*****************************" | tee -a $audit_log
    echo $jira_host_url/$jira_issue >> $audit_log
    echo "" >> $audit_log
}

### # Function - Create machine reservation
rebar.create_dhcp_reservation() {
    echo "rebar.create_dhcp_reservation()" | tee -a $audit_log
    host $servername > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        serverip=`host $servername|awk '{print $NF}'`
        if ( echo $servername|egrep -q "sla-" ); then
            rebar_server=$sla_drp_server
        elif ( echo $servername|egrep -q "sun-" ); then
            rebar_server=$sun_drp_server
        else
            rebar_server=$fos_drp_server
        fi
        mac_address=`grep mac_address: $vmnotes|awk -F":" '{print $2":"$3":"$4":"$5":"$6":"$7}'`
        echo " " | tee -a $audit_log
        cat $user_home/rebar/rebar-reservation-template.json | sed -e 's|machine_ip|'"$serverip"'|g' -e 's|machine_name|'"$servername"'|g' -e 's|machine_mac|'"$mac_address"'|g' > $user_home/rebar/rebar-reservation.json
        echo "create dhcp reservation - $servername $mac_address $serverip" |tee -a $audit_log
        curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -u $drp_username:$drp_password -d @$user_home/rebar/rebar-reservation.json https://$rebar_server:8092/api/v3/reservations --insecure | tee -a $audit_log
        echo " " | tee -a $audit_log
        echo "*****************************" | tee -a $audit_log
        echo " " | tee -a $audit_log
        echo "create device42..." |tee -a $audit_log
        curl -k -s -X POST -u "$D42_USER:$d42_passwd" -d "name=$servername&type=physical&in_service=yes&macaddress=$mac_address" "https://$d42_host/api/device/"
        echo "$servername $mac_address" |mail -s "Slack: rebar.create_dhcp_reservation lifecycle Status" $stackadmin
    else
       echo "exit...server not in DNS"
    fi
}

### # Function - Create machine, assign profile and workflow
rebar.create_machine() {
    echo "rebar.create_machine()" | tee -a $audit_log
    host $servername > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        serverip=`host $servername|awk '{print $NF}'`
        if ( echo $servername|egrep -q "sla-" ); then
        rebar_server=sla-drebar01.zooxlabs.com
        elif ( echo $servername|egrep -q "sun-" ); then
            rebar_server=sun-drebar01.zooxlabs.com
        else
            rebar_server=fos-drebar01.zooxlabs.com
        fi
        echo "rebar.create_machine" | tee -a $audit_log
        echo " " | tee -a $audit_log
        machine_workflow1=`grep workflow $vmnotes|awk -F":" '{print $NF}'`
        machine_profile1=`grep profile $vmnotes|awk -F":" '{print $NF}'`

        if [ -z "$machine_workflow1" ]; then
            machine_workflow="ubuntu16-install"
        else
            machine_workflow=$machine_workflow1
        fi

        if [ -z "$machine_profile1" ]; then
            machine_profile=\"ZooxBox\"
            cat $user_home/rebar/rebar-create-machine-template.json | sed -e 's|machine_ip|'"$serverip"'|g' -e 's|machine_name|'"$servername"'|g' -e 's|machine_workflow|'"$machine_workflow"'|g' -e 's|machine_profile|'"$machine_profile"'|g' > $user_home/rebar/rebar-create-machine.json
            echo "create Rebar machine - $servername $serverip $machine_workflow $machine_profile" |tee -a $audit_log
            cat /home/stanley/rebar/rebar-create-machine.json
            curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -u $drp_username:$drp_password -d @$user_home/rebar/rebar-create-machine.json https://$rebar_server:8092/api/v3/machines --insecure | tee -a $audit_log
            echo " " | tee -a $audit_log
            mail -s "Slack: rebar.create_machine lifecycle Status" $stackadmin < $audit_log
        else
            echo $machine_profile1| egrep -q "," &&
            (
                echo "more than one profiles..."
                for i in $(echo $machine_profile1 | sed "s/,/ /g")
                do
                    echo -n \"$i\",
                done > $lce/profile.tmp
                machine_profile=`cat $lce/profile.tmp|sed 's/.$//'`
                cat $user_home/rebar/rebar-create-machine-template.json | sed -e 's|machine_ip|'"$serverip"'|g' -e 's|machine_name|'"$servername"'|g' -e 's|machine_workflow|'"$machine_workflow"'|g' -e 's|machine_profile|'"$machine_profile"'|g' > $user_home/rebar/rebar-create-machine.json
                echo "create Rebar machine - $servername $serverip $machine_workflow $machine_profile" |tee -a $audit_log
                cat /home/stanley/rebar/rebar-create-machine.json
                curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -u $drp_username:$drp_password -d @$user_home/rebar/rebar-create-machine.json https://$rebar_server:8092/api/v3/machines --insecure | tee -a $audit_log
                echo " " | tee -a $audit_log
                mail -s "Slack: rebar.create_machine lifecycle Status" $stackadmin < $audit_log
            ) || 
            (
                echo "one profile found..."
                machine_profile=\"$machine_profile1\"
                cat $user_home/rebar/rebar-create-machine-template.json | sed -e 's|machine_ip|'"$serverip"'|g' -e 's|machine_name|'"$servername"'|g' -e 's|machine_workflow|'"$machine_workflow"'|g' -e 's|machine_profile|'"$machine_profile"'|g' > $user_home/rebar/rebar-create-machine.json
                echo "create Rebar machine - $servername $serverip $machine_workflow $machine_profile" |tee -a $audit_log
                cat /home/stanley/rebar/rebar-create-machine.json
                curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -u $drp_username:$drp_password -d @$user_home/rebar/rebar-create-machine.json https://$rebar_server:8092/api/v3/machines --insecure | tee -a $audit_log
                echo " " | tee -a $audit_log
                mail -s "Slack: rebar.create_machine lifecycle Status" $stackadmin < $audit_log
            )
        fi
    else
       echo "exit...server not in DNS"
    fi
}

### # Function - Provision machine via PXE boot
rebar.provisioning_machine() {
    echo "rebar.provisioning_machine()" | tee -a $audit_log
    ipmi_server=$servername-ipmi
    host $ipmi_server > /dev/null 2>&1
    if host $ipmi_server > /dev/null 2>&1 && ( ! ping -c 1 $servername > /dev/null 2>&1) && host $servername > /dev/null 2>&1; then
        echo " " | tee -a $audit_log
        echo "set to pxe boot" | tee -a $audit_log
        $ipmi_tool $ipmi_server $ipmi_username $ipmi_password ipmi power bootoption 1 | tee -a $audit_log
        echo "Power up $servername" | tee -a $audit_log
        $ipmi_tool $ipmi_server $ipmi_username $ipmi_password ipmi power up | tee -a $audit_log
        echo " " | tee -a $audit_log
        egrep -q skip-jira $vmnotes && echo "skip create jira issue" || 
        (
            echo "create jira ticket" >> $audit_log
            echo "*****************************" | tee -a $audit_log
            #st2 run jira.create_issue summary="Slack: rebar.provisioning_machine - $servername" type=Task component=$jira_component assignee=$jira_assignee | tee $jira_file 2>&1
            [[ -f $jira_file ]] && 
            (
                cat $jira_file >> $audit_log
                jira_issue=`grep key: $jira_file |awk '{print $NF}'`
                #echo "Comment jira ticket `grep key: $jira_file |awk '{print $NF}'` via D42" |tee -a $audit_log
                #st2 run jira.comment_issue issue_key=$jira_issue comment_text="`cat $audit_log`" | tee -a $audit_log
            )
        )
        echo "*****************************" | tee -a $audit_log
        echo $jira_host_url/$jira_issue >> $audit_log
        echo "" >> $audit_log
        mail -s "Slack: rebar.provisioning_machine lifecycle Status" $stackadmin < $audit_log
    else
        host $ipmi_server > /dev/null 2>&1 && : || echo "exit...impi not in DNS" | tee -a $audit_log
        host $servername > /dev/null 2>&1 && : || echo "exit... $servername not in DNS" | tee -a $audit_log
        ping -c 1 $servername > /dev/null 2>&1 && echo "exit... $servername is pingable" | tee -a $audit_log
        mail -s "Slack: rebar.provisioning_machine lifecycle Status" $stackadmin < $audit_log
    fi
}

### # Function - Create device42, PowerDNS recrod

create_device() {
    echo "create_device()" | tee -a $audit_log
    curl -k -s -X GET -u "$D42_USER:$d42_passwd" "https://$d42_host/api/1.0/devices?name=$servername"| jshon|egrep -q $servername
    if [ $? -eq 0 ];then
        echo "create_device: Device $service found in Device42...exit" | tee -a $audit_log
        curl -k -s -X GET -u "$D42_USER:$d42_passwd" "https://$d42_host/api/1.0/devices/name/$servername"|jshon|egrep '"ip":|"mac":|"name":' | tee -a $audit_log
        host $servername > /dev/null 2>&1 &&
        (
            echo "create_device: has DNS record: `host $servername`" | tee -a $audit_log
            serverip=`host $servername|awk '{print $NF}'`
	    device_ip=`curl -k -s -X GET -u "$D42_USER:$d42_passwd" "https://$d42_host/api/1.0/devices/name/$servername"| jshon|egrep '"ip"'|awk -F":" '{print $NF}'|sed 's/"//g'|sed 's/,//g'|xargs`
	    [[ $serverip != $device_ip ]] &&
	    (
                echo "create_device: Device IP address and DNS IP different." | tee -a $audit_log
                echo "create_device: Device IP: $device_ip  DNS IP: $serverip" | tee -a $audit_log
            )
        )

    else
        egrep -q skip-pdns $vmnotes && echo "create_device: skip adding IP address to powerdns" || 
        (
            echo $servername|egrep -q "sun-|3dx" && subnet1=10.65.4.0/22 || subnet1=172.16.3.0/24
            if ( echo $servername|egrep -q "sun-" ); then
                #servername_deviceid=`ls $lce/$servername-deviceid*|awk -F"-" '{print $NF}'`
                #find-next-ip $servername_deviceid
                find-next-ip
                host $servername &> /dev/null && serverip1=`host $servername|awk '{print $NF}'` || serverip1=`cat ~/slack/pdns_next_ip-$servername`
            elif ( echo $servername|egrep -q "fos-" ); then
                /usr/bin/st2 run device42.suggest_next_ip subnet=172.16.3.0/24|grep ip:|awk '{print $NF}' > ~/slack/pdns_next_ip-$servername
                host $servername &> /dev/null && serverip1=`host $servername|awk '{print $NF}'` || serverip1=`cat ~/slack/pdns_next_ip`
            elif ( echo $servername|egrep -q "sla-" ); then
                /usr/bin/st2 run device42.suggest_next_ip subnet=10.64.1.0/24|grep ip:|awk '{print $NF}' > ~/slack/pdns_next_ip-$servername
                host $servername &> /dev/null && serverip1=`host $servername|awk '{print $NF}'` || serverip1=`cat ~/slack/pdns_next_ip`-$servername
            else
                echo "create_device: server not in foster city, SLAC or sunnyvale" | tee -a $audit_log
            fi

            
            serverip2=`grep ipaddress $vmnotes|awk -F":" '{print $NF}'`
            [[ -z "$serverip2" ]] && serverip=$serverip1 || serverip=$serverip2

            if ping -c 1 $serverip &> /dev/null || host $servername  &> /dev/null; then
                ping -c 1 $serverip &> /dev/null && 
                (
                    echo "create_device: Skip add device.... $serverip is pingable" | tee -a $audit_log
                    echo "***************************************" | tee -a $audit_log
                ) ||
                (
                    host $servername &> /dev/null && 
                    (
                        serverip=`host $servername|awk '{print $NF}'`
                        server_type=`grep type: $vmnotes|awk -F":" '{print $2}'`
                        echo "create_device: create virtual $server_type device" | tee -a $audit_log
                        echo "" | tee -a $audit_log
                        curl -k -s -X POST -u "$D42_USER:$d42_passwd" -d "name=$servername&type=$server_type&in_service=yes&service_level=$host_group&&macaddress=$MAC" "https://$d42_host/api/device/" > $lce/add-device-$servername 2>&1
                        echo "" >> $lce/add-device-$servername
                        cat $lce/add-device-$servername
                        echo "***************************************" | tee -a $audit_log

                        echo "create_device: Create device IP" | tee -a $audit_log
                        echo "" | tee -a $audit_log
                        st2 run device42.create_or_edit_ip ipaddress=$serverip device_name=$servername | tee -a $audit_log
                        echo "***************************************" | tee -a $audit_log
                    )
                )
            else
                host_group=`grep host_group $vmnotes|awk -F":" '{print $2}'`
                MAC=`grep mac_address $vmnotes|awk -F":" '{print $2":"$3":"$4":"$5":"$6":"$7}'`
                server_type=`grep type: $vmnotes|awk -F":" '{print $2}'`
                [[ -z $server_type ]] && 
                (
                    echo "Device type not defined...exit" | tee -a $audit_log
                    echo "" | tee -a $audit_log
                    display_createdevice_help
                    echo "***************************************" | tee -a $audit_log
                ) ||
                (
                    echo "create_device: suggest_next_ip: $serverip1 for $servername" | tee -a $audit_log
                    echo "***************************************" | tee -a $audit_log
                    if echo $server_type|egrep -q "storage|gpu"; then
                        echo "create_device: create storage|gpu device" | tee -a $audit_log
                        curl -k -s -X POST -u "$D42_USER:$d42_passwd" -d "name=$servername&type=other&subtype=$server_type&in_service=yes&service_level=$host_group&macaddress=$MAC" "https://$d42_host/api/device/" > $lce/add-device-$servername 2>&1
                    else
                        echo "create_device: create $server_type device" | tee -a $audit_log
                        echo "" | tee -a $audit_log
                        curl -k -s -X POST -u "$D42_USER:$d42_passwd" -d "name=$servername&type=$server_type&in_service=yes&service_level=$host_group&&macaddress=$MAC" "https://$d42_host/api/device/" > $lce/add-device-$servername 2>&1
                        echo "" >> $lce/add-device-$servername
                        cat $lce/add-device-$servername
                        echo "***************************************" | tee -a $audit_log
                    fi
                    echo "create_device: Create device IP" | tee -a $audit_log
                    echo "" | tee -a $audit_log
                    st2 run device42.create_or_edit_ip ipaddress=$serverip device_name=$servername | tee -a $audit_log
                    echo "***************************************" | tee -a $audit_log

                    # format the IP last 2 octets to have the reverse zone name
                    reversedForZone=$(echo $serverip |awk -F "." '{print $3"."$2"."$1}')
                    # Reverse all the octets so as to have the PTR record to be added to the reverse zone
                    reversedIP=$(echo $serverip| awk -F "." '{print $4 "." $3 "." $2 "." $1 }')
                    # Calculation of the reverse Zone
                    reverseZone="${reversedForZone}.in-addr.arpa"
                    # Calculation of the reverse zone URL for PowerDNS API call
                    reverseZoneApi="http://$pdns_host:8081/api/v1/servers/localhost/zones/${reverseZone}."
                    # Calculation of the forward zone PowerDNS API
                    domainname=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: domainname"|grep value:|awk '{print $NF}'`
                    echo $domainname|egrep -q -i "null|''" && domainname="zooxlabs.com"
                    fqdn=${servername}.${domainname}
                    forwardZoneApi="http://$pdns_host:8081/api/v1/servers/localhost/zones/${domainname}."
                    # Use the JSON template for A record so as to generate a file to be used to pass as data to CURL API call
                    cat $user_home/powerdns/addArecord.template.json | sed -e 's|fqdn|'"$fqdn"'|g' -e 's|ip|'"$serverip"'|g' > $user_home/powerdns/curlfileArecord.json
                    # Use the JSON template for PTR record so as to generate the file to be used to pass as data to CURL API Call
                    cat $user_home/powerdns/addPTRrecord.template.json | sed -e 's|reversedIP|'"$reversedIP"'|g' -e 's|fqdn|'"$fqdn"'|g' > $user_home/powerdns/curlfilePTRrecord.json
                    # create pdns recrod
                    echo "create_device: add $servername.$domainname $serverip to PowerDNS"
                    echo " "
                    curl -X PATCH -H "X-API-Key: $pdns_password" $forwardZoneApi --data @$user_home/powerdns/curlfileArecord.json > /dev/null 2>&1
                    curl -X PATCH -H "X-API-Key: $pdns_password" $reverseZoneApi --data @$user_home/powerdns/curlfilePTRrecord.json > /dev/null 2>&1
                    echo "***************************************" | tee -a $audit_log
                    egrep -q add-host $vmnotes && add-host
                )
            fi
        )
    fi
    mail -s "Slack: create_device lifecycle Status" $stackadmin < $audit_log
}

### # Function - Commit new changes to ITservice repo
create_git_commit() {
    echo "create_git_commit()" | tee -a $audit_log
    # Check if skip git
    egrep -q skip-git $vmnotes && echo "create_git_commit: skip git commit to repo" || 
    (
    # Check if skip create jira ticket
        egrep -q skip-jira $vmnotes && echo "create_git_commit: skip creating jira ticket" || 
        (
    # create jira ticket and assign it to variable jira_issue1
            jira_issue1=`grep jira-issue $vmnotes|awk -F":" '{priont $NF}'`
    # if value of jira_issue1 is null
            ! egrep -q jira-issue $vmnotes &&
            ( 
                echo "create_git_commit: Create jira issue" | tee -a $audit_log
                echo ""
                #st2 run jira.create_issue summary="Slack: Create new VM $servername" type=Task component=$jira_component assignee=$jira_assignee > $jira_file 2>&1
                [[ -f $jira_file ]] && jira_issue=`grep key: $jira_file |awk '{print $NF}'` 
                echo $jira_host_url/$jira_issue >> $audit_log
                echo "" | tee -a $audit_log
                [[ ! -z $jira_issue ]] && 
                (
                    echo "create_git_commit: Add comment to $jira_issue" | tee -a $audit_log
                    #st2 run jira.comment_issue issue_key=$jira_issue comment_text="`cat $audit_log`"
                )
                echo $jira_issue|egrep -q -i ITOPS && 
                (
                    echo "create_git_commit: Git commit new changes $jira_issue $servername and push to master - $user" | tee -a $audit_log
                    cd $git_dir
                    echo "create_git_commit: run git pull" | tee -a $audit_log
                    #git pull| tee -a $audit_log
                    echo "create_git_commit: run git add . " | tee -a $audit_log
                    #git add .| tee -a $audit_log
                    echo "create_git_commit: run git commit" | tee -a $audit_log
                    #git commit -a -m "$jira_issue create new server $servername via stackstorm/D42 - $user" | tee -a $audit_log
                    echo "create_git_commit: run git push"| tee -a $audit_log
                    #git push| tee -a $audit_log
                ) || 
                (
                    echo "create_git_commit: jira ticket = null - skip git commit"| tee -a $audit_log
                )
            ) || 
            (
                # if value of jira_issue1 is not null
                jira_issue=$jira_issue1
                echo $jira_host_url/$jira_issue >> $audit_log
                echo "" | tee -a $audit_log
                echo $jira_issue|egrep -q -i ITOPS && 
                (
                    echo "create_git_commit: Git commit new changes $jira_issue $servername and push to master"| tee -a $audit_log
                    cd $git_dir
                    echo "create_git_commit: run git pull"| tee -a $audit_log
                    #git pull| tee -a $audit_log
                    echo "create_git_commit: run git add . "| tee -a $audit_log
                    #git add .| tee -a $audit_log
                    echo "create_git_commit: run git commit"| tee -a $audit_log
                    #git commit -a -m "$jira_issue create new server $servername via stackstorm/D42"| tee -a $audit_log
                    echo "create_git_commit: run git push"| tee -a $audit_log
                    #git push| tee -a $audit_log
                ) || echo "create_git_commit: jira ticket = null - skip git commit"| tee -a $audit_log
            )
        )
    )
    echo "****************************************" | tee -a $audit_log
}

### # Function - Create ansible template, jira issue, anisble base roles
vm_orchestration() {
    echo "vm_orchestration()" | tee -a $audit_log
    st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: skip-d42"|grep value:|awk '{print $NF}'|egrep -q -i yes && echo "vm_orchestration: skip adding ip to device42" || 
    (
        host $servername > /dev/null 2>&1 || egrep -q $servername /etc/hosts || egrep -q add-host $vmnotes &&
            (
                if egrep -q $servername /etc/hosts; then
                    serverip=`grep -w $servername /etc/hosts|awk '{print $1}'`
                    echo "vm_orchestration: $servername - found in local host file...adding IP $serverip to device42" | tee -a $audit_log
                    echo "***************************************" | tee -a $audit_log
                elif host $servername > /dev/null 2>&1; then
                    serverip=`host $servername|awk '{print $NF}'`
                    echo "vm_orchestration: DNS record found" | tee -a $audit_log
                    echo "***************************************" | tee -a $audit_log
                elif egrep -q add-host $vmnotes; then
                    curl -k -s -X GET -u "$D42_USER:$d42_passwd" "https://$d42_host/api/1.0/devices?name=$servername"| jshon|egrep -q $servername
                    if [ $? -eq 0 ];then
                        serverip=`curl -k -s -X GET -u "$D42_USER:$d42_passwd" "https://$d42_host/api/1.0/devices/name/$servername"| jshon|egrep '"ip"'|awk -F":" '{print $NF}'|sed 's/"//g'|sed 's/,//g'|xargs`
                        [[ -z $serverip ]] && 
                        (
                            echo "vm_orchestration:  Found Device, no IP" | tee -a $audit_log
                            echo "***************************************" | tee -a $audit_log
                        ) ||
                        (
                            echo "vm_orchestration:  Found Device IP: $serverip, add to hosts file" | tee -a $audit_log
                            add-host $servername $serverip
                            echo "***************************************" | tee -a $audit_log
                        )
                    else
                        echo "vm_orchestration: Device Not Found" | tee -a $audit_log
                        echo "***************************************" | tee -a $audit_log

                    fi
                fi

                if host $servername > /dev/null 2>&1; then
                    serverip=`host $servername|awk '{print $NF}'`
                elif egrep -q $servername /etc/hosts; then
                    serverip=`grep $servername /etc/hosts|awk '{print $1}'`
                fi
                
                host_group=`grep host_group $vmnotes|awk -F":" '{print $2}'`

                curl -k -s -X GET -u "$D42_USER:$d42_passwd" "https://$d42_host/api/1.0/devices?name=$servername"| jshon|egrep -q $servername
                if [ $? -eq 0 ];then
                    echo "vm_orchestration: Device already in Device42...skip Add device" | tee -a $audit_log
                    echo "***************************************" | tee -a $audit_log
                else
                    echo "vm_orchestration: Add Device" | tee -a $audit_log
                    echo "" | tee -a $audit_log
                    curl -k -s -X POST -u "$D42_USER:$d42_passwd" -d "name=$servername&type=virtual&in_service=yes&service_level=$host_group" "https://$d42_host/api/device/" > $lce/add-device-$servername 2>&1
                    echo "" >> $lce/add-device-$servername
                    cat $lce/add-device-$servername | tee -a $audit_log
                    echo "***************************************" | tee -a $audit_log
                    echo "vm_orchestration: Create Device IP" | tee -a $audit_log
                    st2 run device42.create_or_edit_ip ipaddress=$serverip device_name=$servername | tee -a $audit_log
                    echo "***************************************" | tee -a $audit_log
                fi
                
                

                create_vm_template $servername $serverip
                create_git_commit
                playbook-spin
                apply-base-role
                mail -s "Slack: vm_provisioning lifecycle Status" $stackadmin < $audit_log
            ) ||
            (    
                echo "vm_orchestration: $servername - DNS record not found...exit" | tee -a $audit_log
                mail -s "Slack: vm_provisioning lifecycle Status" $stackadmin < $audit_log
            )
    )
    echo "***************************************" | tee -a $audit_log
}

### # Function - Provision new VM
vm_provisioning() {
    echo "vm_provisioning()" | tee -a $audit_log
    ostemplatetemp=`grep ostemplate $vmnotes|awk -F"[:=]" '{print $2}'`
    cputemp=`grep cpu $vmnotes|awk -F"[:=]" '{print $2}'`
    memorytemp=`grep memory $vmnotes|awk -F"[:=]" '{print $2}'`


    if ( echo $servername|egrep -q "fos-grid" ); then
        subnet1=172.16.3.0/24
        gateway1=172.16.3.1
        netmask1=24
        subnet_mask=255.255.255.0
        datacenter1=FOS-GRID
        datastore1=fos-qnas01-grid-ds01
        resourcepool1=fos-gridesx02.zooxlabs.com
        cluster1=fos-gridesx02.zooxlabs.com
        esxi1=fos-gridesx02.zooxlabs.com
        vcenter01_dir=$repo/itservice/terraform-vsphere/fos-gridvcenter01
        vmdefinition=$repo/itservice/terraform-vsphere/fos-gridvcenter01/data/vm_definitions.csv
        vcenter_host=fos-gridvcenter01
        vcenter_user=administrator@vsphere.local
        vm_folder=""
        echo $ostemplatetemp|egrep -q -i ubuntu16 && ostemplate=fosgrid-tmpl-ubuntu1604-prod
        echo $ostemplatetemp|egrep -q -i ubuntu18 && ostemplate=fosgrid-tmpl-ubuntu1804-prod
        echo $ostemplatetemp|egrep -q -i 2016 && ostemplate=fosgrid-tmpl-windows2016-prod
        echo $ostemplatetemp|egrep -q -i 2012 && ostemplate=fosgrid-tmpl-windows2012-prod
	vsphere_password=ghostbuster
    elif ( echo $servername|egrep -q "fos-" ); then
        subnet1=172.16.3.0/24
        gateway1=172.16.3.1
        subnet_mask=255.255.255.0
        netmask1=24
        datacenter1=Fos
        datastore1=fos-qnas01-esx-ds01
        resourcepool1=fos-prod01
        cluster1=Fos-prod01
        esxi1=fos-esx03.zooxlabs.com
        vcenter01_dir=$repo/itservice/terraform-vsphere/fos-vcenter01
        vmdefinition=$repo/itservice/terraform-vsphere/fos-vcenter01/data/vm_definitions.csv
        vcenter_host=sun-vcenter01
        vcenter_user=svc-terraform
        vm_folder="Discovered virtual machine"
        echo $ostemplatetemp|egrep -q -i ubuntu16 && ostemplate=fos-tmpl-ubuntu1604-prod
        echo $ostemplatetemp|egrep -q -i ubuntu18 && ostemplate=fos-tmpl-ubuntu1804-prod
        echo $ostemplatetemp|egrep -q -i 2016 && ostemplate=fos-tmpl-windows2016-prod
        echo $ostemplatetemp|egrep -q -i 2012 && ostemplate=fos-tmpl-windows2012-prod
	vsphere_password=svc-terraform
    elif ( echo $servername|egrep -q "sun-|3dx" ); then
        subnet1=10.65.4.0/22
        gateway1=10.65.4.1
        netmask1=22
        subnet_mask=255.255.252.0
        datacenter1=Sunnyvale
        datastore1=SUN-QNAS01-GP
        resourcepool1=PROD-A
        cluster1=PROD-A
        esxi1=sun-q02-a.zooxlabs.com
        vcenter01_dir=$repo/itservice/terraform-vsphere/sun-vcenter01
        vmdefinition=$repo/itservice/terraform-vsphere/sun-vcenter01/data/vm_definitions.csv
        vcenter_host=sun-vcenter01
        vcenter_user=svc-terraform
        vm_folder=""
        echo $ostemplatetemp|egrep -q -i ubuntu16 && ostemplate=sun-tmpl-ubuntu1604-prod
        echo $ostemplatetemp|egrep -q -i ubuntu18 && ostemplate=sun-tmpl-ubuntu1804-prod
        echo $ostemplatetemp|egrep -q -i 2016 && ostemplate=sun-tmpl-windows2016-prod
        echo $ostemplatetemp|egrep -q -i 2012 && ostemplate=sun-tmpl-windows2012-prod
	vsphere_password=svc-terraform
    elif ( echo $servername|egrep -q "sla-" ); then
        subnet1=10.64.1.0/24
        gateway1=10.64.1.1
        netmask1=24
        subnet_mask=255.255.255.0
        datacenter1=SLAC
        datastore1=sla-q02-b-vm01
        resourcepool1=PROD
        cluster1=PROD
        esxi1=sla-q01-b.zooxlabs.com
        vcenter01_dir=$repo/itservice/terraform-vsphere/sun-vcenter01
        vmdefinition=$repo/itservice/terraform-vsphere/sun-vcenter01/data/vm_definitions.csv
        vcenter_host=sun-vcenter01
        vcenter_user=svc-terraform
        vm_folder=""
        echo $ostemplatetemp|egrep -q -i ubuntu16 && ostemplate=sla-tmpl-ubuntu1604-prod
        echo $ostemplatetemp|egrep -q -i ubuntu18 && ostemplate=sla-tmpl-ubuntu1804-prod
        echo $ostemplatetemp|egrep -q -i 2016 && ostemplate=sla-tmpl-windows2016-prod
        echo $ostemplatetemp|egrep -q -i 2012 && ostemplate=sla-tmpl-windows2012-prod
        vsphere_password=svc-terraform
    else
        echo "vm_provisioning: server does not start with naming convention: fos-/sun-/3dx,sla-...exit)" | tee -a $audit_log
        echo "vm_provisioning: server $servername does not start with naming convention: fos-/sun-/3dx,sla-...exit)"| mail -s "Slack: vm_provisioning lifecycle Status" $stackadmin
        exit 1
    fi

    owner=`grep owner $vmnotes|awk -F"[:=]" '{print $2}'`
    [[ -z "$owner" ]] && owner="Unknown"

    purpose=`grep purpose $vmnotes|awk -F"[:=]" '{print $2}'`
    [[ -z "$purpose" ]] && purpose="Unknown"

    zooxlabs_admin=`grep zooxlabs_admin $vmnotes|awk -F"[:=]" '{print $2}'`
    [[ -z "$zooxlabs_admin" ]] && zooxlabs_admin=""

    remote_desktop_user=`grep remote_desktop_user $vmnotes|awk -F":" '{print $2}'`
    [[ -z "$remote_desktop_user" ]] && remote_desktop_user="Administrator"

    serverip1=`/usr/bin/st2 run device42.suggest_next_ip subnet=$subnet1|grep ip:|awk '{print $NF}'`
   
    host $servername > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "vm_provisioning: $servername has dns entry" | tee -a $audit_log
        echo "***************************************=" | tee -a $audit_log
        serverip=`host $servername|grep address|awk '{print $NF}'`
    else
        serverip2=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: ipaddress"|grep value:|awk '{print $NF}'`
        echo $serverip2|egrep -q -i "null|''" && serverip=$serverip1
    fi

    resourcepool=`grep resourcepool $vmnotes|awk -F"[:=]" '{print $2}'`
    [[ -z "$resourcepool" ]] && resourcepool=$resourcepool1

    cluster=`grep cluster $vmnotes|awk -F"[:=]" '{print $2}'`
    [[ -z "$cluster" ]] && cluster=$cluster1

    network=`grep network $vmnotes|awk -F"[:=]" '{print $2}'`
    [[ -z "$network" ]] && network="VM Network"

    datacenter=`grep datacenter $vmnotes|awk -F"[:=]" '{print $2}'`
    [[ -z "$datacenter" ]] && datacenter=$datacenter1

    datastore=`grep datastore $vmnotes|awk -F"[:=]" '{print $2}'`
    [[ -z "$datastore" ]] && datastore=$datastore1

    domainname=`grep domainname $vmnotes|awk -F"[:=]" '{print $2}'`
    [[ -z "$domainname" ]] && domainname="zooxlabs.com"

    recursor1=`grep recursor1 $vmnotes|awk -F"[:=]" '{print $2}'`
    [[ -z "$recursor1" ]] && recursor1="172.16.3.25"

    recursor2=`grep recursor2 $vmnotes|awk -F"[:=]" '{print $2}'`
    [[ -z "$recursor2" ]] && recursor2="10.65.4.25"

    mountpoint1_tmp=`grep mountpoint1 $vmnotes|awk -F":" '{print $NF}'`
    [[ -z "$mountpoint1_tmp" ]] && mountpoint1="/data1" || mountpoint1=$mountpoint1_tmp
    mountpoint2_tmp=`grep mountpoint2 $vmnotes|awk -F":" '{print $NF}'`
    [[ -z "$mountpoint2_tmp" ]] && mountpoint2="/data2" || mountpoint2=$mountpoint2_tmp


    [[ "$cputemp" =~ ^-?[0-9]+$ ]] &&  cpu=$cputemp || cpu=1
    [[ "$memorytemp" =~ ^-?[0-9]+$ ]] &&  memory=$memorytemp || memory=4096

    if grep --quiet  ansible-role $vmnotes; then
        ansible_role=`grep ansible-role $vmnotes|awk -F"[:=]" '{print $2}'`
    else
        echo $ostemplatetemp|egrep -q -i ubuntu && ansible_role="linux,pbis,sudoers" || ansible_role="windows,join_domain"
    fi

    # windows or ubuntu
    echo $ostemplate|egrep -q -i ubuntu && filesystem=ext4 || filesystem=ntfs
    echo $ostemplate|egrep -q -i ubuntu && disk=40 || disk=100

    if [ -z "$ostemplate" ]; then
        if echo $servername |egrep -q -i  fos-grid; then
            ostemplate=fosgrid-tmpl-ubuntu1604-prod
        elif echo $servername |egrep -q -i  fos-; then
            ostemplate=fos-tmpl-ubuntu1604-prod
        elif echo $servername |egrep -q -i  sun-; then
            ostemplate=sun-tmpl-ubuntu1604-prod
        elif echo $servername |egrep -q -i  sla-; then
            ostemplate=sla-tmpl-ubuntu1604-prod
        fi
    fi 

# check if IP address same for device42 and Powerdns

    st2 run device42.get_device_by_id device_id=$deviceid|egrep "type:|device_sub_type:" > $lce/$servername-type
    device_ip=`curl -k -s -X GET -u "$D42_USER:$d42_passwd" "https://$d42_host/api/1.0/devices/name/$servername"| jshon|egrep '"ip"'|awk -F":" '{print $NF}'|sed 's/"//g'|sed 's/,//g'|xargs`
    curl -k -s -X GET -u "$D42_USER:$d42_passwd" "https://$d42_host/api/1.0/devices?name=$servername"| jshon|egrep -q $servername
    if [ $? -ne 0 ];then
        echo "Device NOT in Device42...Exit" | tee -a $audit_log
        echo "To add device:" | tee -a $audit_log
        echo "Slack>: !d42 createdevice $servername type:virtual" | tee -a $audit_log
        mail -s "Slack: vm_provisioning lifecycle Status" $stackadmin < $audit_log
    elif [ -z "$device_ip" ]; then
        echo "vm_provisioning: Device has no IP address in Device42...Exit" | tee -a $audit_log
        echo "To add device:" | tee -a $audit_log
        echo "Slack>: !d42 createdevice $servername type:virtual" | tee -a $audit_log
        mail -s "Slack: vm_provisioning lifecycle Status" $stackadmin < $audit_log
    elif [ $serverip != $device_ip ]; then
        echo "vm_provisioning: Device IP address NOT and DNS IP different...Exit" | tee -a $audit_log
        echo "Device IP: $device_ip  DNS IP: $serverip" | tee -a $audit_log
        mail -s "Slack: vm_provisioning lifecycle Status" $stackadmin < $audit_log
    elif [ -z "$serverip" ]; then
        echo "vm_provisioning: $servername no ip address....exit" | tee -a $audit_log
        mail -s "Slack: vm_provisioning lifecycle Status" $stackadmin < $audit_log
    elif [ -f "$TF_OUT_FILE_TMP/$servername.yml" ]; then
        echo "vm_provisioning: $servername found in host_vars...Exit" | tee -a $audit_log
        mail -s "Slack: vm_provisioning lifecycle Status" $stackadmin < $audit_log
    elif ! egrep -q "virtual" $lce/$servername-type; then
        echo "vm_provisioning: $servername type is not virtual in device42...Exit" | tee -a $audit_log
        mail -s "Slack: vm_provisioning lifecycle Status" $stackadmin < $audit_log
    else
        echo " "
        
        create_all
    fi
    echo "***************************************" | tee -a $audit_log
}

### # Main function
create_all() {
    echo "create_all()" | tee -a $audit_log
    if [ -z "$serverip" ]; then
        echo "create_all: serverip = null...exit" | tee -a  $audit_log
        mail -s "Slack: vm_provisioning lifecycle Status" $stackadmin < $audit_log
    elif ping -c 1 $serverip &> /dev/null; then
        echo "create_all: serverip $serverip is alive...Exit" | tee -a  $audit_log
        mail -s "Slack: vm_provisioning lifecycle Status" $stackadmin < $audit_log
    else
        vm_orchestration $servername
    fi
}

### # Function - Create ansible template
create_vm_template() {
    echo "create_vm_template()" | tee -a $audit_log
    echo "" | tee -a $audit_log
 
    TF_OUT_FILE=$TF_OUT_FILE_TMP/$servername.yml
    cat <<EOF>"$TF_OUT_FILE"
vsphere_datacenter: "$datacenter"
guest_network: "$network"
guest_custom_ip: "$serverip"
guest_netmask: "$subnet_mask"
guest_gateway: $gateway1
guest_dns_server1: $recursor1
guest_dns_server2: $recursor2
guest_domain_name: $domainname
guest_memory: $memory
guest_vcpu: $cpu
guest_template: $ostemplate
vsphere_datastore: $datastore
guest_owner: "$owner"
guest_purpose: "$purpose"
zooxlabs_admin: "$zooxlabs_admin"
remote_desktop_user: "$remote_desktop_user"
vm_folder: "$vm_folder"
vsphere_cluster: "$cluster"
EOF

    egrep -q datadisk $vmnotes && 
    (
        echo " "
        echo "create_vm_template: add data disk..."

        # root disk
        echo $ostemplate|egrep -q -i ubuntu16 && root_size=16
        echo $ostemplate|egrep -q -i ubuntu18 && root_size=40
        echo $ostemplate|egrep -q -i windows && root_size=40

        cat <<EOF>>"$TF_OUT_FILE"
guest_disksize0: $root_size
EOF

        # mount point
        egrep -q mountpoint $vmnotes && 
        (
            mountpoint=`grep mountpoint $vmnotes|awk -F":" '{print $NF}'`
            mountpoint_num=`echo $mountpoint|awk '{print NF}'`
            echo "create_vm_template: mountpoint_num: $mountpoint_num"
            count=1
            for mountpoint_count in $mountpoint
            do
                cat <<EOF>>"$TF_OUT_FILE"
mountpoint$count: "/$mountpoint_count"
EOF
                (( count++ ))
            done
        ) || 
        (
            numdisk=`st2 run device42.get_device_by_id device_id=$deviceid|grep -w hddcount:|awk '{print $2}'`
            # number of disk
            ([[ $numdisk =~ ^-?[0-9]+$ ]] && [[  "$numdisk" -gt 0 ]]) && 
            (
                mountpoint=/data
                mountpoint_size=`st2 run device42.get_device_by_id device_id=$deviceid|grep -w hddsize:|awk '{print $2}'|awk -F"." '{print $1}'`
                echo "create_vm_template: add data disk... number of secodnary disks/size: $numdisk $mountpoint_size"
                for i in $(seq 1 $numdisk)
                do
                    cat <<EOF>>"$TF_OUT_FILE"
mountpoint$i: $mountpoint$i
EOF
                done
            )
        )

        datadisk=`grep datadisk $vmnotes|awk -F":" '{print $NF}'`
        count=1
        for datadisk_count in $datadisk
        do
            cat <<EOF>>"$TF_OUT_FILE"
guest_disksize$count: $datadisk_count
EOF
            (( count++ ))
        done
    ) ||
    (
                            cat <<EOF>>"$TF_OUT_FILE"
mountpoint1: $mountpoint1
mountpoint2: $mountpoint2
EOF
    )
    cat $TF_OUT_FILE_TMP/$servername.yml
    echo "****************************************" | tee -a $audit_log

}

    


# Display help if running without argument
if [[ $# -eq 0 ]] ; then
    display_help
    exit 0
fi

# display help
if [ "$1" == "help" ] || [ "$1" == "-h" ] || [ "$1" == "-help" ] ; then
    display_help
    exit 0
fi

audit_log=$user_home/slack/audit-$servername

### # Assign Lifecycke State
case $lifecycle in
    7)
        echo "purchasing lifecycle event"| tee $audit_log
        echo "****************************************" | tee -a $audit_log
        purchasing_lc
        mail -s "Slack: purchasing_lc lifecycle Status" $stackadmin < $audit_log
	;;
    8)
        echo "mounting lifecycle"| tee $audit_log
        echo "****************************************" | tee -a $audit_log
        mounting_lc
        mail -s "Slack: mounting_lc lifecycle Status" $stackadmin < $audit_log
	;;
    9)
        echo "deploying lifecycle"| tee $audit_log
        echo "****************************************" | tee -a $audit_log
        echo "apply-base-role $1 $2"
        apply-base-role $1 $2
        mail -s "Slack: deploying lifecycle Status" $stackadmin < $ansible_role_log
	;;
    10)
        echo "production lifecycle event"| tee $audit_log
        echo "****************************************" | tee -a $audit_log
        production_lc
        ;;
    12)
        echo "os_provisioning lifecycle event"| tee $audit_log
        echo "****************************************" | tee -a $audit_log
        echo "Run ansible playbook to bring up baremetal"
        os_provisioning
        mail -s "Slack: os_provisioning lifecycle Status" $stackadmin
        ;;
    13)
        echo "vm_provisioning lifecycle"| tee $audit_log
        echo "****************************************" | tee -a $audit_log
        echo "`date` - start vm_provisioning - $servername " | tee -a $audit_log
        echo "****************************************" | tee -a $audit_log
        for servername in `echo $server_all`
        do
            vm_provisioning $servername
        done
        echo "****************************************" | tee -a $audit_log
        echo "`date` - done vm_provisioning - $servername " | tee -a $audit_log
        ;;

    14)
        echo "create_device lifecycle event" | tee $audit_log
        echo "****************************************" | tee -a $audit_log
        for servername in `echo $server_all`
        do
            create_device $servername
        done
        ;;
    16)
	run-playbook

        ;;
    17)
        echo "rebar.create_dhcp_reservation lifecycle event"| tee $audit_log
        echo "****************************************" | tee -a $audit_log
        rebar.create_dhcp_reservation
        ;;
    18)
        echo "rebar.create_machine lifecycle event"| tee $audit_log
        echo "****************************************" | tee -a $audit_log
        rebar.create_machine
        ;;
    19)
        echo "rebar.provisioning_machine lifecycle event"| tee $audit_log
        echo "****************************************" | tee -a $audit_log
        rebar.provisioning_machine
        ;;
    99)
        echo "no lifecycle event found"
        display_help
        ;;
    *)
        echo "none"
        ;;
    esac
