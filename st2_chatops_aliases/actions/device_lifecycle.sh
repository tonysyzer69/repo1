#!/bin/bash
###
###
###    Purpose: Lifecycle Event Driven for Device42 and Stackstorm
###
### #####3###################################################### ##
date1=`date +"%y-%m-%d-%H:%M:%S"`
stackadmin=tla@zoox.com

# Set script home directory
user_home=/home/stanley

# Set repo directory
repo=$user_home/git

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

# Linux login for ansible playbook
linux_username=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=linux_username&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`
linux_password=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=linux_password&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`

# IPMI login
ipmi_username=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=ipmi_username&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`
ipmi_password=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=ipmi_password&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`

# Rebar login
drp_username=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=drp_username&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`
drp_password=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=drp_password&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`

# Stackstorm API key
export ST2_API_KEY=$apikey

# Lifecycle Event
lce=$user_home/device42/$2
[[ ! -d $user_home/device42/$2 ]] && mkdir $user_home/device42/$2

# Set command line arguments
deviceid=$1
lifecycle=$2
user=$3

st2 run device42.get_device_by_id device_id=$1 > ~/log99 2>&1

# Server variables
servername=`st2 run device42.get_device_by_id device_id=$1|grep -w name:|awk '{print $2}'`
ostemplatetemp=`st2 run device42.get_device_by_id device_id=$1|grep -w os:|awk '{print $2}'`
cputemp=`st2 run device42.get_device_by_id device_id=$1|grep -w cpucount:|awk '{print $2}'`
memorytemp=`st2 run device42.get_device_by_id device_id=$1|grep -w ram:|awk '{print $2}'|awk -F"." '{print $1}'`
servernote=`st2 run device42.get_device_by_id device_id=$1|grep -w notes:`

# ansible playbook output log
ansible_role_log=$user_home/device42/ansible_role_log-$user
ansible_playbook_log=$user_home/device42/ansible_playbook_log-$user

# User output log
audit_log=$user_home/device42/audit-$user-$servername

#
d42_log=$user_home/audit_log/d42.log

# Capture Notes from Device42 
vmnotes=$lce/vmnotes-$servername
vmnotes_tmp=$lce/vmnotes_tmp-$servername
vmnotes_14=$user_home/device42/14/vmnotes-$servername
vmnotes_tmp_14=$user_home/device42/14/vmnotes_tmp-$servername

# Output jira log
jira_file=$user_home/device42/jira.txt-$servername

# Device42 deviceid (number) for server
server_deviceid=$lce/$servername-deviceid-$deviceid

# Ansible template directory
TF_OUT_FILE_TMP=$repo/itservice/infra/ansible/host_vars

# D42 custom fields
jira_component_tmp=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: jira-component"|grep value:|awk '{print $NF}'`
echo $jira_component_tmp|egrep -q -i "null|''" && jira_component="Automation" || jira_component=$jira_component_tmp

jira_assignee_tmp=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: jira-assignee"|grep value:|awk '{print $NF}'`
echo $jira_assignee_tmp|egrep -q -i "null|''" && jira_assignee=$user || jira_assignee=$jira_assignee_tmp

### # Starting Main
echo "$date1 - $1 $2 $3" >> $d42_log

# echo all parameters from device42 notes:
echo $servernote > $vmnotes_tmp

# format into columns, key value
echo $servernote |sed 's/notes://g'|sed 's/null//g'| sed -e 's/^[ \t]*//' > $vmnotes_tmp
awk -F'"' '$0=$1$2' $vmnotes_tmp >> $vmnotes
awk -F'"' '$0=$3$4' $vmnotes_tmp >> $vmnotes
awk -F'"' '$0=$5$6' $vmnotes_tmp >> $vmnotes
awk -F'"' '$0=$6$7' $vmnotes_tmp >> $vmnotes
awk -F'"' '$0=$8$9' $vmnotes_tmp >> $vmnotes
awk -F'"' '$0=$10$11' $vmnotes_tmp >> $vmnotes

# Set deviceid for a server
touch $server_deviceid

[[ $lifecycle -eq "16" ]] &&
(
    sshpass -p "$linux_password_tmp1" ssh -o "StrictHostKeyChecking=no" -l zoox $servername hostname > $lce/ssh1.log 2>&1 && echo $linux_password_tmp1 > $lce/$servername-linux-password
    sshpass -p "$linux_password_tmp2" ssh -o "StrictHostKeyChecking=no" -l zoox $servername hostname > $lce/ssh2.log 2>&1 && echo $linux_password_tmp2 > $lce/$servername-linux-password
)

### # Function - find next available IP via Device42
find-next-ip() {
    echo "find-next-ip()" | tee -a $audit_log
    # VM
    st2 run device42.get_device_by_id device_id=$deviceid|egrep "type:|device_sub_type:"|egrep -q "virtual" &&  
    (
        echo "$servername is virtual" | tee -a $audit_log
        curl -X GET -u "$D42_USER:$d42_passwd" https://$d42_host/api/1.0/ips/subnet_id/111/ --insecure|jshon > ~/device42/10.65.4.0.tmp
        grep 10.65.4 ~/device42/10.65.4.0.tmp|awk -F"." '{print $NF}'|sed 's/"//g'|sed 's/,//g' > ~/device42/10.65.4.0
        echo 255 >> ~/device42/10.65.4.0
        pdns_next_ip=`awk '$1!=p+1{print p+1"-"$1-1}{p=$1}' ~/device42/10.65.4.0|head -1|awk -F"-" '{print $1}'`
        echo 10.65.4.$pdns_next_ip > ~/device42/pdns_next_ip-$servername
    )

    # Compute (blade) bare metal, physical
    st2 run device42.get_device_by_id device_id=$deviceid|egrep "type:|device_sub_type:"|egrep -q "blade|physical" &&  
    (
        echo "$servername is blade(compute) or physical" | tee -a $audit_log
        curl -X GET -u "$D42_USER:$d42_passwd" https://$d42_host/api/1.0/ips/subnet_id/111/ --insecure|jshon > ~/device42/10.65.5.0.tmp
        grep 10.65.5 ~/device42/10.65.5.0.tmp|awk -F"." '{print $NF}'|sed 's/"//g'|sed 's/,//g' > ~/device42/10.65.5.0
        echo 255 >> ~/device42/10.65.5.0
        pdns_next_ip=`awk '$1!=p+1{print p+1"-"$1-1}{p=$1}' ~/device42/10.65.5.0|head -1|awk -F"-" '{print $1}'`
        echo 10.65.5.$pdns_next_ip > ~/device42/pdns_next_ip-$servername
    )

    # GPU Node
    st2 run device42.get_device_by_id device_id=$deviceid|egrep "type:|device_sub_type:"|egrep -q "gpu" &&  
    (
        echo "$servername is gpu node" | tee -a $audit_log
        curl -X GET -u "$D42_USER:$d42_passwd" https://$d42_host/api/1.0/ips/subnet_id/111/ --insecure|jshon > ~/device42/10.65.6.0.tmp
        grep 10.65.6 ~/device42/10.65.6.0.tmp|awk -F"." '{print $NF}'|sed 's/"//g'|sed 's/,//g' > ~/device42/10.65.6.0
        echo 255 >> ~/device42/10.65.6.0
        pdns_next_ip=`awk '$1!=p+1{print p+1"-"$1-1}{p=$1}' ~/device42/10.65.6.0|head -1|awk -F"-" '{print $1}'`
        echo 10.65.6.$pdns_next_ip > ~/device42/pdns_next_ip-$servername
    )

    # Storage
    st2 run device42.get_device_by_id device_id=$deviceid|egrep "type:|device_sub_type:"|egrep -q "storage" &&  
    (
        echo "$servername is storage" | tee -a $audit_log
        curl -X GET -u "$D42_USER:$d42_passwd" https://$d42_host/api/1.0/ips/subnet_id/111/ --insecure|jshon > ~/device42/10.65.7.0.tmp
        grep 10.65.7 ~/device42/10.65.7.0.tmp|awk -F"." '{print $NF}'|sed 's/"//g'|sed 's/,//g' > ~/device42/10.65.7.0
        echo 255 >> ~/device42/10.65.7.0
        pdns_next_ip=`awk '$1!=p+1{print p+1"-"$1-1}{p=$1}' ~/device42/10.65.7.0|head -1|awk -F"-" '{print $1}'`
        echo 10.65.7.$pdns_next_ip > ~/device42/pdns_next_ip-$servername
    )

}


add_pdns() {
    echo "add_pdns()" | tee -a $audit_log

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
            echo "add_pdns(): add $servername.$domainname $serverip to powerdns" | tee -a $audit_log
            echo " "
            curl -X PATCH -H "X-API-Key: $pdns_password" $forwardZoneApi --data @$user_home/powerdns/curlfileArecord.json > /dev/null 2>&1
            curl -X PATCH -H "X-API-Key: $pdns_password" $reverseZoneApi --data @$user_home/powerdns/curlfilePTRrecord.json > /dev/null 2>&1
            echo "======================================"
            mail -s "D42: update_dns lifecycle Status - $servername" $user@zoox.com,$stackadmin < $audit_log

}

### # Function - create pdns A/PTR records
update_dns() {
    echo "update_dns()" | tee -a $audit_log
    st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: skip-pdns"|grep value:|awk '{print $NF}'|egrep -q -i yes && echo "skip adding IP address to powerdns" | tee -a $audit_log || 
    (

        device_ip=`curl -k -s -X GET -u "$D42_USER:$d42_passwd" "https://$d42_host/api/1.0/devices/name/$servername"| jshon|egrep '"ip"'|awk -F":" '{print $NF}'|sed 's/"//g'|sed 's/,//g'|xargs`          
        serverip1=`host $servername|awk '{print $NF}'`
        serverip2=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: ipaddress"|grep value:|awk '{print $NF}'`
        echo $serverip2|egrep -q -i "null|''" && serverip=$serverip1 || serverip=$serverip2

        host $servername  &> /dev/null && 
        (
            echo "update_dns: DNS record found `host $servername` ..Exit" | tee -a $audit_log 
            serverip=`host $servername|awk '{print $NF}'`
            [[ $serverip != $device_ip ]] && 
            (
                echo "update_dns: Device IP address and DNS IP different" | tee -a $audit_log
                echo "update_dns: Device IP: $device_ip  DNS IP: $serverip" | tee -a $audit_log
            )   
            mail -s "D42: update_dns: lifecycle Status - $servername" $stackadmin < $audit_log
        ) ||
        (
            echo "update_dns: DNS record NOT found" | tee -a $audit_log 

            echo $servername|egrep -q "sun-|3dx" && subnet1=10.65.4.0/22 || subnet1=172.16.3.0/24
            if ( echo $servername|egrep -q "sun-" ); then
                servername_deviceid=`ls $lce/$servername-deviceid*|awk -F"-" '{print $NF}'`
                [[ -z $device_ip ]] &&
                (
                    echo "update_dns: NO IP in Device42" | tee -a $audit_log
                    echo "update_dns: sun- $subnet1" | tee -a $audit_log
                    find-next-ip $servername_deviceid
                    serverip=`cat ~/device42/pdns_next_ip-$servername`
                    echo "update_dns: suggest_next_ip: $serverip for $servername" | tee -a $audit_log
                    echo "update_dns: adding $servername $serverip to Device42" | tee -a $audit_log
                    st2 run device42.create_or_edit_ip ipaddress=$serverip device_name=$servername | tee -a $audit_log
                    add_pdns $serverip
                ) ||
                (
                    echo "update_dns: Found IP in Device42" | tee -a $audit_log
                    serverip=`curl -k -s -X GET -u "$D42_USER:$d42_passwd" "https://$d42_host/api/1.0/devices/name/$servername"| jshon|egrep '"ip"'|awk -F":" '{print $NF}'|sed 's/"//g'|sed 's/,//g'|xargs`
                    add_pdns $serverip
                )
            
            elif ( echo $servername|egrep -q "fos-" ); then
                curl -X GET -u "$D42_USER:$d42_passwd" https://$d42_host/api/1.0/devices/id/$deviceid --insecure|jshon |grep '"ip":' > /dev/null 2>&1 && : ||
                (
                    serverip=`/usr/bin/st2 run device42.suggest_next_ip subnet=172.16.3.0/24|grep ip:|awk '{print $NF}'`
                    st2 run device42.create_or_edit_ip ipaddress=$serverip device_name=$servername | tee -a $audit_log
                )
            elif ( echo $servername|egrep -q "sla-" ); then
                curl -X GET -u "$D42_USER:$d42_passwd" https://$d42_host/api/1.0/devices/id/$deviceid --insecure|jshon |grep '"ip":' > /dev/null 2>&1 && : || 
                (
                    serverip=`/usr/bin/st2 run device42.suggest_next_ip subnet=10.64.1.0/24|grep ip:|awk '{print $NF}'`
                    st2 run device42.create_or_edit_ip ipaddress=$serverip device_name=$servername | tee -a $audit_log
                )
            else
                echo "update_dns: server not in foster city, SLAC or sunnyvale" | tee -a $audit_log
            fi
        )
    )
}


### # Function - Add host to local /etc/hosts
add-host() {
    echo "add-host()" | tee -a $audit_log
    host $servername > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "$servername not in DNS"| tee -a $audit_log
        egrep -q -i $servername /etc/hosts && echo "$servername already in /etc/hosts" || sudo -u root bash -c "echo $serverip $servername $servername.zooxlabs.com >> /etc/hosts"
    fi
}

### # Function - Provision VM
playbook-spin() {
    echo "playbook-spin()" | tee -a $audit_log
    st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: skip-playbook"|grep value:|awk '{print $NF}'|egrep -q -i yes  && echo "skip running playbook" || 
    (
        export PYTHONWARNINGS="ignore:Unverified HTTPS request"
        echo "provisioning $servername ..." | tee -a $audit_log
        echo "Running playbook-spin" | tee $ansible_playbook_log
        cd $repo/itservice/infra/ansible
        ansible-playbook -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  $repo/itservice/infra/ansible/playbooks/spinup.yml --extra-vars="vcenter_password=$vsphere_password vsphere_host=$vcenter_host vsphere_user=$vcenter_user" --vault-password-file=/etc/st2/keys/.vault |tee -a $ansible_playbook_log
        echo "======================================"
        echo " "
    )
}

### # Function - Base roles for new VM
apply-base-role() {
    echo "apply-base-role()" | tee -a $audit_log
    export PYTHONWARNINGS="ignore:Unverified HTTPS request"
    st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: skip-playbook"|grep value:|awk '{print $NF}'|egrep -q -i yes && echo "skip running playbook/role" || 
    (
        ansible_role_tmp=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: ansible_role"|grep value:|awk '{print $NF}'`
        if echo $ansible_role_tmp|egrep -q -i "null|''"; then
            st2 run device42.get_device_by_id device_id=$deviceid|egrep "service_level:"|egrep -q -i windows && ansible_role="windows,join_domain" || ansible_role="linux,pbis,sudoers"
            
        else
            ansible_role=$ansible_role_tmp
        fi

        echo "Apply base role: $ansible_role for $servername" | tee -a $audit_log
        echo "Running apply-base-role" | tee $ansible_role_log

	cd $repo/itservice/infra/ansible
        st2 run device42.get_device_by_id device_id=$deviceid|egrep "service_level:"|egrep -q -i windows && ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook_windows.yml  -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  --tags $ansible_role --vault-password-file=/etc/st2/keys/.vault |tee -a $ansible_role_log || sshpass -p "$linux_password"  ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook.yml -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  --ask-sudo-pass --extra-vars "ansible_user=$linux_username ansible_password=$linux_password" --tags $ansible_role --vault-password-file=/etc/st2/keys/.vault |tee -a $ansible_role_log

        echo "======================================" | tee -a $audit_log
        echo " " | tee -a $audit_log
    )
}

### # Function - Main playbook
run-playbook() {
    echo "run-playbook()" | tee -a $audit_log
    #nc -z $servername 22 > /dev/null 2>&1
    ping -c 2 $servername > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        mountpoint1_tmp=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: mountpoint1"|grep value:|awk '{print $NF}'`
        echo $mountpoint1_tmp|egrep -q -i "null|''" && mountpoint1="/data1" || mountpoint1=$mountpoint1_tmp
        mountpoint2_tmp=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: mountpoint2"|grep value:|awk '{print $NF}'`
        echo $mountpoint2_tmp|egrep -q -i "null|''" && mountpoint2="/data2" || mountpoint2=$mountpoint2_tmp
        zooxlabs_admin_tmp=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: zooxlabs-admin"|grep value:|awk '{print $NF}'`
        echo $zooxlabs_admin|egrep -q -i "null|''" && zooxlabs_admin="" || zooxlabs_admin=$zooxlabs_admin_tmp


        ansible_role=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: ansible_role"|grep value:|awk '{print $NF}'`

        filebeat_paths_tmp=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: filebeat_paths"|grep value:|awk '{$1=""; print $0}'`

        echo $filebeat_paths_tmp |egrep -q -i "null|''" && echo "filebeat_paths_tmp is null" ||
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
        echo "======================================" | tee -a $audit_log
        if [ -z $ansible_role ]; then
            st2 run device42.get_device_by_id device_id=$deviceid|egrep "service_level:"|egrep -q -i windows && ansible_role=join_domain
        elif [ $ansible_role == "enable_haproxy_service" ] || [ $ansible_role == "disable_haproxy_service" ]; then
            backend=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: backend"|grep value:|awk '{print $NF}'`
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
                    egrep -q paths: $vmnotes && sshpass -p "$linux_password"  ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook.yml -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  --ask-sudo-pass --extra-vars "ansible_user=$linux_username ansible_password=$linux_password mountpoint1=$mountpoint1 mountpoint2=$mountpoint2 zooxlabs_admin=$zooxlabs_admin server_backend=$server_backend backend_host=$backend_host backend_host2=$backend_host2" --extra-vars "@$lce/$servername-filebeat" --tags $ansible_role --vault-password-file=/etc/st2/keys/.vault |tee $lce/ansible_role_log-$servername || sshpass -p "$linux_password"  ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook.yml -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  --ask-sudo-pass --extra-vars "ansible_user=$linux_username ansible_password=$linux_password mountpoint1=$mountpoint1 mountpoint2=$mountpoint2 zooxlabs_admin=$zooxlabs_admin server_backend=$server_backend backend_host=$backend_host backend_host2=$backend_host2" --tags $ansible_role --vault-password-file=/etc/st2/keys/.vault |tee $lce/ansible_role_log-$servername
                fi

                echo "****************************************" | tee -a $audit_log
                echo " " | tee -a $audit_log
                mail -s "D42: Run playbook Status - $servername" $stackadmin < $lce/ansible_role_log-$servername
            ) || 
            (
                echo "Cannot login to $servername...exit"
                [[ -f $lce/ssh1.log ]] && cat $lce/ssh1.log | tee -a $audit_log
                [[ -f $lce/ssh2.log ]] && cat $lce/ssh2.log | tee -a $audit_log
            )
        fi

            cat $ansible_role_log >> $audit_log
            echo "======================================" | tee -a $audit_log
            echo " " | tee -a $audit_log
            mail -s "D42: Run playbook Status - $servername" $user@zoox.com,$stackadmin < $audit_log
    else
        host $servername > /dev/null 2>&1 && : || echo "exit... $servername NOT in DNS" | tee -a $audit_log
        nc -z $servername 22 > /dev/null 2>&1 && : || echo "exit... $servername CANNOT ssh" | tee -a $audit_log
        mail -s "D42:Run playbook Status - $servername" $user@zoox.com,$stackadmin < $audit_log
    fi
}

### # Function - Create jira issue
create_jira_issue() {
    echo "create_jira_issue()" | tee -a $audit_log
    echo "create_jira_issue lifecycle event" | tee $audit_log
    echo "*****************************" | tee -a $audit_log
    st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: skip-jira"|grep value:|awk '{print $NF}'|egrep -q -i yes && echo "skip creating jira ticket" || 
    (
        /usr/bin/st2 run jira.create_issue summary="D42: create_jira_issue lifecycle event $servername" type=Task component=$jira_component assignee=$jira_assignee > $jira_file 2>&1
        echo "create jira ticket `grep key: $jira_file |awk '{print $NF}'` via D42" | tee -a $audit_log
        jira_issue=`grep key: $jira_file |awk '{print $NF}'`
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
    st2 run jira.create_issue summary="D42: purchasing_lc lifecycle event - $servername " type=Task component=$jira_component assignee=$jira_assignee > $jira_file 2>&1
    echo "Create jira ticket" | tee -a $audit_log
    cat $jira_file >> $audit_log
    echo "`grep key: $jira_file |awk '{print $NF}'`" | tee -a $audit_log
    jira_issue=`grep key: $jira_file |awk '{print $NF}'`
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
    /usr/bin/st2 run jira.create_issue summary="D42: mounting_lc lifecycle event - $servername " type=Task component=$jira_component assignee=$jira_assignee > $jira_file 2>&1
    echo "create jira ticket `grep key: $jira_file |awk '{print $NF}'` via D42" | tee -a $audit_log
    jira_issue=`grep key: $jira_file |awk '{print $NF}'`
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
    /usr/bin/st2 run jira.create_issue summary="D42: production_lc lifecycle event - $servername" type=Task component=$jira_component assignee=$jira_assignee > $jira_file 2>&1
    echo "create jira ticket `grep key: $jira_file |awk '{print $NF}'` via D42" | tee -a $audit_log
    jira_issue=`grep key: $jira_file |awk '{print $NF}'`
    echo "Add comment to $jira_issue" | tee -a $audit_log
    st2 run jira.comment_issue issue_key=$jira_issue comment_text="`cat $audit_log`" | tee -a $audit_log
    echo " "
    echo "*****************************" | tee -a $audit_log
    echo $jira_host_url/$jira_issue >> $audit_log
    echo "" >> $audit_log
    mail -s "D42:production_lc lifecycle Status - $servername" $user@zoox.com,$stackadmin < $audit_log
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
        mac_address=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "mac_addresses:"|grep mac:|awk '{print $NF}'|sed "s/'//g"`
        echo " " | tee -a $audit_log
        cat $user_home/rebar/rebar-reservation-template.json | sed -e 's|machine_ip|'"$serverip"'|g' -e 's|machine_name|'"$servername"'|g' -e 's|machine_mac|'"$mac_address"'|g' > $user_home/rebar/rebar-reservation.json
        echo "create dhcp reservation - $servername $mac_address $serverip" |tee -a $audit_log
        curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -u $drp_username:$drp_password -d @$user_home/rebar/rebar-reservation.json https://$rebar_server:8092/api/v3/reservations --insecure | tee -a $audit_log
        mail -s "D42: rebar.create_dhcp_reservation lifecycle Status - $servername" $user@zoox.com,$stackadmin < $audit_log
    else
       echo "exit...server not in DNS"
    fi
}

### # Function - Create machine, assign profile and workflow
rebar.create_machine() {
    echo "rebar.create_machine()" | tee -a $audit_log
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
        machine_workflow1=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: machine_workflow"|grep value:|awk '{print $NF}'`
        echo $machine_workflow1|egrep -q -i "null|''" && machine_workflow="ubuntu16-install" || machine_workflow=$machine_workflow1
        machine_profile1=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: machine_profile"|grep value:|awk '{print $NF}'`
        echo $machine_profile1|egrep -q -i "null|''" && machine_profile="ZooxBox" || machine_profile=$machine_profile1

        if [ -z "$machine_profile1" ]; then
            machine_profile=\"ZooxBox\"
            cat $user_home/rebar/rebar-create-machine-template.json | sed -e 's|machine_ip|'"$serverip"'|g' -e 's|machine_name|'"$servername"'|g' -e 's|machine_workflow|'"$machine_workflow"'|g' -e 's|machine_profile|'"$machine_profile"'|g' > $user_home/rebar/rebar-create-machine.json
            echo "create Rebar machine - $servername $serverip $machine_workflow $machine_profile" |tee -a $audit_log
            cat /home/stanley/rebar/rebar-create-machine.json
            curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -u $drp_username:$drp_password -d @$user_home/rebar/rebar-create-machine.json https://$rebar_server:8092/api/v3/machines --insecure | tee -a $audit_log
            echo " " | tee -a $audit_log
            mail -s "D42: rebar.create_machine lifecycle Status - $servername" $user@zoox.com,$stackadmin < $audit_log
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
                mail -s "D42: rebar.create_machine lifecycle Status - $servername" $user@zoox.com,$stackadmin < $audit_log
            ) ||
            (
                echo "one profile found..."
                machine_profile=\"$machine_profile1\"
                cat $user_home/rebar/rebar-create-machine-template.json | sed -e 's|machine_ip|'"$serverip"'|g' -e 's|machine_name|'"$servername"'|g' -e 's|machine_workflow|'"$machine_workflow"'|g' -e 's|machine_profile|'"$machine_profile"'|g' > $user_home/rebar/rebar-create-machine.json
                echo "create Rebar machine - $servername $serverip $machine_workflow $machine_profile" |tee -a $audit_log
                cat /home/stanley/rebar/rebar-create-machine.json
                curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -u $drp_username:$drp_password -d @$user_home/rebar/rebar-create-machine.json https://$rebar_server:8092/api/v3/machines --insecure | tee -a $audit_log
                echo " " | tee -a $audit_log
                mail -s "D42: rebar.create_machine lifecycle Status - $servername" $user@zoox.com,$stackadmin < $audit_log
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
    if host $ipmi_server > /dev/null 2>&1 && ( ! ping -c 1 $servername > /dev/null 2>&1) && host $servername> /dev/null 2>&1; then
        echo " " | tee -a $audit_log
        echo "set to pxe boot" | tee -a $audit_log
        $ipmi_tool $ipmi_server $ipmi_username $ipmi_password ipmi power bootoption 1 | tee -a $audit_log
        echo "power up $servername" | tee -a $audit_log
        $ipmi_tool $ipmi_server $ipmi_username $ipmi_password ipmi power up | tee -a $audit_log
        echo " " | tee -a $audit_log
        echo "create jira ticket" >> $audit_log
        /usr/bin/st2 run jira.create_issue summary="D42: rebar.provisioning_machine - $servername" type=Task component=$jira_component assignee=$jira_assignee > $jira_file 2>&1
        cat $jira_file >> $audit_log
        jira_issue=`grep key: $jira_file |awk '{print $NF}'`
        echo "Comment jira ticket `grep key: $jira_file |awk '{print $NF}'` via D42" |tee -a $audit_log
        st2 run jira.comment_issue issue_key=$jira_issue comment_text="`cat $audit_log`" | tee -a $audit_log
        echo "*****************************" | tee -a $audit_log
        echo $jira_host_url/$jira_issue >> $audit_log
        echo "" >> $audit_log
        mail -s "D42: rebar.provisioning_machine lifecycle Status - $servername" $user@zoox.com,$stackadmin < $audit_log
    else
        host $ipmi_server > /dev/null 2>&1 && : || echo "exit...impi not in DNS" | tee -a $audit_log
        host $servername > /dev/null 2>&1 && : || echo "exit... $servername not in DNS" | tee -a $audit_log
        ping -c 1 $servername > /dev/null 2>&1 && echo "exit... $servername is pingable" | tee -a $audit_log
        mail -s "D42: rebar.provisioning_machine lifecycle Status - $servername" $user@zoox.com,$stackadmin < $audit_log
    fi
}

### # Function - Create device42, ansible template, powerdns records, jira issue, anisble base roles
vm_orchestration() {
    echo "vm_orchestration()" | tee -a $audit_log
    st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: add-host"|grep value:|awk '{print $NF}'|egrep -q -i yes &&
    (
        echo "found add-host...add $serverip $servername to local host file"
        add-host $servername $serverip
    )
  

    st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: skip-d42"|grep value:|awk '{print $NF}'|egrep -q -i yes && echo "skip adding ip to device42" ||
    (
        host $servername > /dev/null 2>&1 || egrep -q $servername /etc/hosts &&
            (
                if egrep -q $servername /etc/hosts; then
                    serverip=`grep -w $servername /etc/hosts|awk '{print $1}'`
                    echo "$servername - found in local host file...adding IP $serverip to device42" | tee -a $audit_log
                elif host $servername > /dev/null 2>&1; then
                    serverip=`host $servername|awk '{print $NF}'`
                    echo "$servername - DNS record found...adding IP $serverip to device42" | tee -a $audit_log
                fi

                echo "Create DNS record" | tee -a $audit_log
                update_dns
                st2 run device42.create_or_edit_ip ipaddress=$serverip device_name=$servername | tee -a $audit_log
                create_vm_template
                create_git_commit
                playbook-spin $servername $ansible_role
                apply-base-role $1 $2
                echo "Create host inventory: $servername" | tee -a $audit_log
                echo "=====================================" | tee -a $audit_log
                cat $TF_OUT_FILE_TMP/$servername.yml | tee -a $audit_log
                echo "=====================================" | tee -a $audit_log
                cat $ansible_playbook_log |tee -a $audit_log
                echo "=====================================" | tee -a $audit_log
                cat $ansible_role_log |tee -a $audit_log
                echo "" | tee -a $audit_log
                echo "=====================================" | tee -a $audit_log
                mail -s "D42: vm_provisioning lifecycle Status - $servername" $stackadmin < $audit_log
            ) ||
            (
                echo "$servername - DNS record not found...exit" | tee -a $audit_log
                echo "Otion 1: Use Update_dns or Ipam to create DNS record" | tee -a $audit_log
                echo "Otion 2: Enable add-host: Device --> Edit --> Other --> Yes (check box) " | tee -a $audit_log
                mail -s "D42: vm_provisioning lifecycle Status - $servername" $stackadmin < $audit_log
            )
    )
}

### # Function - Commit new changes to ITservice repo
create_git_commit() {
    echo "create_git_commit()" | tee -a $audit_log
    # Check if skip git
    st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: skip-git"|grep value:|awk '{print $NF}'|egrep -q -i yes && echo "skip git commit to repo" || 
    (
    # Check if skip create jira ticket
        st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: skip-jira"|grep value:|awk '{print $NF}'|egrep -q -i yes && echo "skip creating jira ticket" || 
        (
    # create jira ticket and assign it to variable jira_issue1
            jira_issue1=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: jira-issue"|grep value:|awk '{print $NF}'`
    # if value of jira_issue1 is null
            echo $jira_issue1|egrep -q -i "null|''" && 
            ( 
                /usr/bin/st2 run jira.create_issue summary="D42: Create new VM $servername" type=Task component=$jira_component assignee=$jira_assignee > $jira_file 2>&1
                echo "create jira ticket `grep key: $jira_file |awk '{print $NF}'` via D42" | tee -a $audit_log
                jira_issue=`grep key: $jira_file |awk '{print $NF}'`
                echo "Add comment to $jira_issue" | tee -a $audit_log
                st2 run jira.comment_issue issue_key=$jira_issue comment_text="`cat $audit_log`"
                echo $jira_host_url/$jira_issue >> $audit_log
                echo "" | tee -a $audit_log
                echo "======================================" | tee -a $audit_log
                echo $jira_issue|egrep -q -i ITOPS && 
                (
                    echo "Git commit new changes $jira_issue $servername and push to master - $user" | tee -a $audit_log
                    cd $git_dir
                    echo "run git pull" | tee -a $audit_log
                    #git pull| tee -a $audit_log
                    echo "run git add . " | tee -a $audit_log
                    #git add .| tee -a $audit_log
                    echo "run git commit" | tee -a $audit_log
                    #git commit -a -m "$jira_issue create new server $servername via stackstorm/D42 - $user" | tee -a $audit_log
                    echo "run git push"| tee -a $audit_log
                    #git push| tee -a $audit_log
                    echo "======================================"| tee -a $audit_log
                ) || echo "jira ticket = null - skip git commit"| tee -a $audit_log
            ) || 
            (
                # if value of jira_issue1 is not null
                jira_issue=$jira_issue1
                echo $jira_host_url/$jira_issue >> $audit_log
                echo "" | tee -a $audit_log
                echo "======================================"| tee -a $audit_log
                echo $jira_issue|egrep -q -i ITOPS && 
                (
                    echo "Git commit new changes $jira_issue $servername and push to master"| tee -a $audit_log
                    cd $git_dir
                    echo "run git pull"| tee -a $audit_log
                    #git pull| tee -a $audit_log
                    echo "run git add . "| tee -a $audit_log
                    #git add .| tee -a $audit_log
                    echo "run git commit"| tee -a $audit_log
                    #git commit -a -m "$jira_issue create new server $servername via stackstorm/D42"| tee -a $audit_log
                    echo "run git push"| tee -a $audit_log
                    #git push| tee -a $audit_log
                    echo "======================================"| tee -a $audit_log
                ) || echo "jira ticket = null - skip git commit"| tee -a $audit_log
            )
        )
    )
}

### # Function - Provision new VM
vm_provision() {
    echo "vm_provision()" | tee -a $audit_log
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
        echo "server $servername does not start with naming convention: fos-/sun-/3dx,sla-...exit)"
        echo "server $servername does not start with naming convention: fos-/sun-/3dx,sla-...exit)"| mail -s "D42: vm_provisioning lifecycle Status - $servername" $user@zoox.com,$stackadmin
        exit 1
    fi

    serverip1=`/usr/bin/st2 run device42.suggest_next_ip subnet=$subnet1|grep ip:|awk '{print $NF}'`

    host $servername > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "$servername has dns entry" | tee -a $audit_log
        serverip=`host $servername|grep address|awk '{print $NF}'`
    else
        serverip2=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: ipaddress"|grep value:|awk '{print $NF}'`
        echo $serverip2|egrep -q -i "null|''" && serverip=$serverip1
    fi

    owner=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: owner"|grep value:|awk '{$1=""; print $0}'`
    echo $owner|egrep -q -i "null|''" && owner="Unknown"

    purpose=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: purpose"|grep value:|awk '{$1=""; print $0}'`
    echo $purpose|egrep -q -i "null|''" && purpose="Unknown"


    zooxlabs_admin=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: zooxlabs-admin"|grep value:|awk '{print $NF}'`
    echo $zooxlabs_admin|egrep -q -i "null|''" && zooxlabs_admin=""

    remote_desktop_user=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: remote-desktop-user"|grep value:|awk '{print $NF}'`
    echo $remote_desktop_user|egrep -q -i "null|''" && remote_desktop_user="Administrator"

    resourcepool=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: resourcepool"|grep value:|awk '{print $NF}'`
    echo $resourcepool|egrep -q -i "null|''" && resourcepool=$resourcepool1

    cluster=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: vsphere_cluster"|grep value:|awk '{print $NF}'`
    echo $cluster|egrep -q -i "null|''" && cluster=$cluster1

    network=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: network"|grep value:|awk '{$1=""; print $0}'`
    echo $network|egrep -q -i "null|''" && network="VM Network"

    datacenter=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: vsphere_datacenter"|grep value:|awk '{print $NF}'`
    echo $datacenter|egrep -q -i "null|''" && datacenter=$datacenter1

    datastore=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: datastore"|grep value:|awk '{print $NF}'`
    echo $datastore|egrep -q -i "null|''" && datastore=$datastore1

    domainname=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: domainname"|grep value:|awk '{print $NF}'`
    echo $domainname|egrep -q -i "null|''" && domainname="zooxlabs.com"

    recursor1=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: recursor1"|grep value:|awk '{print $NF}'`
    echo $recursor1|egrep -q -i "null|''" && recursor1="172.16.3.25"

    recursor2=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: recursor2"|grep value:|awk '{print $NF}'`
    echo $recursor2|egrep -q -i "null|''" && recursor2="10.65.4.25"


    [[ "$cputemp" =~ ^-?[0-9]+$ ]] &&  cpu=$cputemp || cpu=1
    [[ "$memorytemp" =~ ^-?[0-9]+$ ]] &&  memory=$memorytemp || memory=4096

    # windows or ubuntu
    echo $ostemplate|egrep -q -i ubuntu && filesystem=ext4 || filesystem=ntfs
    echo $ostemplate|egrep -q -i ubuntu && disk=40 || disk=100

    if [[ -z "$ostemplate" ]]; then
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

    st2 run device42.get_device_by_id device_id=$deviceid|egrep "type:|device_sub_type:" > $lce/$servername-type

    if [[ -z "$serverip" ]]; then
        echo "no ip address...exit" | tee -a $audit_log
        mail -s "D42: vm_provisioning lifecycle Status - $servername" $user@zoox.com,$stackadmin < $audit_log
    elif [ -f "$TF_OUT_FILE_TMP/$servername.yml" ]; then
        echo "$servername found in host_vars...skip" | tee -a $audit_log
        mail -s "D42: vm_provisioning lifecycle Status - $servername" $user@zoox.com,$stackadmin < $audit_log
    elif ! egrep -q "virtual" $lce/$servername-type; then
        echo "$servername type is not "virtual" in device42...skip" | tee -a $audit_log
        mail -s "D42: vm_provisioning lifecycle Status - $servername" $user@zoox.com,$stackadmin < $audit_log
    else
        echo " "
        create_all
    fi

}

### # Main function
create_all() {
    echo "create_all()" | tee -a $audit_log
    if [[ -z "$serverip" ]]; then
        echo "serverip = null...exit" | tee -a  $audit_log
        mail -s "D42: vm_provisioning lifecycle Status - $servername" $user@zoox.com,$stackadmin < $audit_log
    elif ping -c 1 $serverip &> /dev/null; then
        echo "serverip $serverip is alive...skip adding $servername to pdns/jira/device42" | tee -a  $audit_log
        mail -s "D42: vm_provisioning lifecycle Status - $servername" $user@zoox.com,$stackadmin < $audit_log
    else
        vm_orchestration
    fi
}

### # Function - Create ansible template
create_vm_template() {
    echo "create_vm_template()" | tee -a $audit_log
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

    # root disk
    echo $ostemplate|egrep -q -i ubuntu16 && root_size=16
    echo $ostemplate|egrep -q -i ubuntu18 && root_size=40
    echo $ostemplate|egrep -q -i windows && root_size=40

    # mount point
    egrep -q mountpoint $vmnotes && 
    (
        mountpoint=`grep mountpoint $vmnotes|awk -F":" '{print $NF}'`
        mountpoint_num=`echo $mountpoint|awk '{print NF}'`
        echo "mountpoint_num: $mountpoint_num"
        count=1
        for mountpoint_count in $mountpoint
        do
            cat <<EOF>>"$TF_OUT_FILE"
mountpoint$count: $mountpoint_count
EOF
            (( count++ ))
        done
     
    ) || 
    (
        numdisk=`st2 run device42.get_device_by_id device_id=$deviceid|grep -w hddcount:|awk '{print $2}'`
        echo "number of disks: $numdisk $deviceid"
        # number of disk
        ([[ $numdisk =~ ^-?[0-9]+$ ]] && [[  "$numdisk" -gt 0 ]]) && 
        (
            echo " "
            mountpoint1_tmp=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: mountpoint1"|grep value:|awk '{print $NF}'`
            echo $mountpoint1_tmp|egrep -q -i "null|''" && mountpoint1="/data1" || mountpoint1=$mountpoint1_tmp

            mountpoint2_tmp=`st2 run device42.get_device_by_id device_id=$deviceid|grep -A 2 "key: mountpoint2"|grep value:|awk '{print $NF}'`
            echo $mountpoint2_tmp|egrep -q -i "null|''" && mountpoint2="/data2" || mountpoint2=$mountpoint2_tmp

            if [ $numdisk -eq 1 ]; then
                cat <<EOF>>"$TF_OUT_FILE"
mountpoint1: $mountpoint1
EOF
            elif [ $numdisk -eq 2 ]; then
                cat <<EOF>>"$TF_OUT_FILE"
mountpoint1: $mountpoint1
EOF
                cat <<EOF>>"$TF_OUT_FILE"
mountpoint2: $mountpoint2
EOF
             else
	         echo "more than 2 disks....not supported"
             fi
      
        )
    )

    # disk size

    egrep -q datadisk $vmnotes && 
    (
        # disk size
        datadisk=`grep datadisk $vmnotes|awk -F":" '{print $NF}'`
        datadisk_num=`echo $datadisk|awk '{print NF}'`
        echo "datadisk_num: $datadisk_num"
        [[  "$datadisk_num" -gt 0 ]] && 
        (
        echo " "
        cat <<EOF>>"$TF_OUT_FILE"
guest_disksize0: $root_size
EOF
        )

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
        numdisk=`st2 run device42.get_device_by_id device_id=$deviceid|grep -w hddcount:|awk '{print $2}'`
        echo "number of disks: $numdisk $deviceid"
        # number of disk
        ([[ $numdisk =~ ^-?[0-9]+$ ]] && [[  "$numdisk" -gt 0 ]]) && 
        (
            echo " "
            cat <<EOF>>"$TF_OUT_FILE"
guest_disksize0: $root_size
EOF
            mountpoint_size=`st2 run device42.get_device_by_id device_id=$deviceid|grep -w hddsize:|awk '{print $2}'|awk -F"." '{print $1}'`
            echo "add data disk... number of secodnary disks/size: $numdisk $mountpoint_size"

            datadisk_size=`st2 run device42.get_device_by_id device_id=$deviceid|grep -w hddsize:|awk '{print $2}'|awk -F"." '{print $1}'`
            for i in $(seq 1 $numdisk)
            do
                cat <<EOF>>"$TF_OUT_FILE"
guest_disksize$i: $datadisk_size
EOF
            done

        )
    )

}

### # Assign Lifecycke State
case $lifecycle in
    7)
        echo "purchasing lifecycle event"| tee $audit_log
        echo "===============================" | tee -a $audit_log
        purchasing_lc
        mail -s "D42: purchasing_lc lifecycle Status - $servername" $user@zoox.com,$stackadmin < $audit_log
	;;
    8)
        echo "mounting lifecycle"| tee $audit_log
        echo "===============================" | tee -a $audit_log
        mounting_lc
        mail -s "D42: mounting_lc lifecycle Status - $servername" $user@zoox.com,$stackadmin < $audit_log
	;;
    9)
        echo "deploying lifecycle"| tee $audit_log
        echo "===============================" | tee -a $audit_log
        echo "apply-base-role $1 $2"
        apply-base-role $1 $2
        mail -s "D42: deploying lifecycle Status - $servername" $user@zoox.com,$stackadmin < $ansible_role_log
	;;
    10)
        echo "production lifecycle event"| tee $audit_log
        echo "===============================" | tee -a $audit_log
        production_lc
        ;;
    13)
        echo "vm_provisioning lifecycle"| tee $audit_log
        echo "===============================" | tee -a $audit_log
        echo "`date` - start vm_provisioning - $servername " | tee -a $audit_log
        echo "===============================" | tee -a $audit_log
        vm_provision
        echo "===============================" | tee -a $audit_log
        echo "`date` - done vm_provisioning - $servername " | tee -a $audit_log
        ;;
    14)
        echo "update_dns lifecycle event" | tee $audit_log
        echo "===============================" | tee -a $audit_log
	update_dns
        ;;
    16)
	run-playbook
        ;;
    17)
        echo "rebar.create_dhcp_reservation lifecycle event"| tee $audit_log
        echo "===============================" | tee -a $audit_log
        rebar.create_dhcp_reservation
        ;;
    18)
        echo "rebar.create_machine lifecycle event"| tee $audit_log
        echo "===============================" | tee -a $audit_log
        rebar.create_machine
        ;;
    19)
        echo "rebar.provisioning_machine lifecycle event"| tee $audit_log
        echo "===============================" | tee -a $audit_log
        rebar.provisioning_machine
        ;;
    *)
        echo "none"
        ;;
    esac
