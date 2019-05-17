#!/bin/bash

#set -e

user_home=/home/stanley
repo=$user_home/git
d42_passwd=`cat /etc/st2/keys/d42_password`

export D42_USER=admin
export D42_PWD="$d42_passwd"
export D42_URL=https://fos-d42.zooxlabs.com
export D42_SKIP_SSL_CHECK=False
#

d42_view_user=`grep username: $user_home/d42_view|awk -F":" '{print $2}'`
d42_view_password=`grep password: $user_home/d42_view|awk -F":" '{print $2}'`
view_user=`grep user: $user_home/d42_view|awk -F":" '{print $2}'`
d42_host=`grep host: $user_home/d42_view|awk -F":" '{print $2}'`

user1=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=$view_user&plain_text=yes"| jshon |grep username|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`
pass1=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=$view_user&plain_text=yes"| jshon |grep password|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`

# expire 90m
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
export D42_SKIP_SSL_CHECK=False

# itservice variable
git_dir=$repo/itservice/
storage_map=$repo/itservice/terraform-vsphere/Bootstrap/storage_map.csv
vmnotes=$user_home/vmnotes
vmnotes_tmp=$user_home/vmnotes_tmp
apikey=`cat /etc/st2/keys/apikey`
apihost=fos-tla01


# export variable
export ST2_API_KEY=$apikey

#
servername=`st2 run device42.get_device_by_id device_id=$1|grep -w name:|awk '{print $2}'`
ostemplatetemp=`st2 run device42.get_device_by_id device_id=$1|grep -w os:|awk '{print $2}'`
cputemp=`st2 run device42.get_device_by_id device_id=$1|grep -w cpucount:|awk '{print $2}'`
memorytemp=`st2 run device42.get_device_by_id device_id=$1|grep -w ram:|awk '{print $2}'|awk -F"." '{print $1}'`
servernote=`st2 run device42.get_device_by_id device_id=$1|grep -w notes:`
deviceid=$1
lifecycle=$2


# output all arguments to file
echo $servernote > $vmnotes_tmp
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

TF_OUT_FILE=$repo/itservice/infra/ansible/host_vars/$servername.yml

# help function
display_help() {
cat << EOF
Create Vsphere VM, currently support fos-vcenter01, fos-gridvcenter01 and sun-vcenter01.

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
        If yes - then mount point(s) added to storage_map.csv, multiple disks are separated by space
        eg: datadisk:(100 300)
        Type: integer (GB)

    mountpoint
        If yes - then disk(s) added to storage_map.csv, multiple mount points are separated by space
        eg: mountpoint:(data1 data2)
        Type: string

    ostemplate
        If no - then default is ubuntu 18.04
        eg: ostemplate:ubuntu16, ostemplate:ubuntu18, ostemplate:windows2016, ostemplate:windows2012
        Type: string

    jira_issue
        If no - then stackstorm create jira ticket
        eg: jira_issue:ITOPS-105
        Type: string

    datastore
        If no - then default SUN-QNAS01-GP for sun-vcenter01, 
        fos-qnas01-grid-ds01 for fos-gridvcenter01 and fos-qnas01-esx-ds01 for fos-vcenter01
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

EXAMPLE
    The following example create VM with two extra disks and two mount points:
        createvm fos-secret01 cpu:1 memory:4096 datadisk:"30 40" mountpoint:"data storage" 
        owner:"Firstname Last" purpose:"thycotic tst" serverip:172.16.3.60 ostemplate:ubuntu16 jira_issue:ITOPS-1014 

EOF
    exit 0
}

run-playbook() {
echo $servernote|egrep -q -i skip-playbook && echo "skip running playbook" || (
export PYTHONWARNINGS="ignore:Unverified HTTPS request"
echo "provisioning $servername ..."
ansible-playbook -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  $repo/itservice/infra/ansible/playbooks/spinup.yml
if grep --quiet  ansible-role $vmnotes; then
    ansible_role=`grep ansible-role $vmnotes|awk -F"[:=]" '{print $2}'`
else
    echo $ostemplatetemp|egrep -q -i ubuntu && ansible_role="linux,pbis,sudoers" || ansible_role="windows,join_domain"
fi
echo "run playbook role: $ansible_role"
echo $ansible_role |egrep -q windows && ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook_windows.yml  -i $inventory -l $servername  --tags $ansible_role ||sshpass -p "$pass1"  ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook.yml -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  --ask-sudo-pass --extra-vars "ansible_user=$user1 ansible_password=$pass1" --tags $ansible_role
echo "======================================"
echo " "
)
}

run-ansible-role() {
echo $servernote|egrep -q -i skip-playbook && echo "skip running playbook" || (
export PYTHONWARNINGS="ignore:Unverified HTTPS request"
if grep --quiet  ansible-role $vmnotes; then
    ansible_role=`grep ansible-role $vmnotes|awk -F"[:=]" '{print $2}'`
else
    echo $ostemplatetemp|egrep -q -i ubuntu && ansible_role="linux,pbis,sudoers" || ansible_role="windows,join_domain"
fi
echo "run playbook role: $ansible_role"
echo $ansible_role |egrep -q windows && ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook_windows.yml  -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  --tags $ansible_role ||sshpass -p "$pass1"  ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook.yml -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  --ask-sudo-pass --extra-vars "ansible_user=$user1 ansible_password=$pass1" --tags $ansible_role
echo "======================================"
echo " "
)
}

create_jira_issue() {
echo $servernote|egrep -q -i "skip-jira|jira_issue" && echo "skip creating jira ticket" || (
# create jira ticket
/usr/bin/st2 run jira.create_issue summary="D42: Create new VM $servername" type=Task > $user_home/jira.txt 2>&1
echo "create jira ticket `grep key: $user_home/jira.txt |awk '{print $NF}'` via D42"
echo " "
)
}

create_jira_issue_purchasing() {
# create jira ticket
/usr/bin/st2 run jira.create_issue summary="D42: Create PO for hardware procurement - $servername " type=Task > $user_home/jira.txt 2>&1
echo "create jira ticket `grep key: $user_home/jira.txt |awk '{print $NF}'` via D42"
echo " "
}

create_jira_issue_mounting() {
# create jira ticket
/usr/bin/st2 run jira.create_issue summary="D42: Create request for servers to be rack/mount/cabling - $servername " type=Task > $user_home/jira.txt 2>&1
echo "create jira ticket `grep key: $user_home/jira.txt |awk '{print $NF}'` via D42"
echo " "
}

create_jira_issue_production() {
# create jira ticket
/usr/bin/st2 run jira.create_issue summary="D42: Create request for servers to be monitored via nagios/pagerduty - $servername" type=Task > $user_home/jira.txt 2>&1
echo "create jira ticket `grep key: $user_home/jira.txt |awk '{print $NF}'` via D42"
echo " "
}

create_device42() {
echo $servernote|egrep -q -i "skip-d42|ipaddress" && echo "skip adding device/ip to device42" || (
# add ip to device42
echo "add $servername $serverip to device42"
echo " "
st2 run device42.create_or_edit_ip ipaddress=$serverip device_name=$servername
echo "======================================"
)
}

create_pdns() {
echo $servernote|egrep -q -i "skip-pdns|ipaddress" && echo "skip adding IP address to powerdns" || (
# format the IP last 2 octets to have the reverse zone name
reversedForZone=$(echo $serverip |awk -F "." '{print $3"."$2"."$1}')

# Reverse all the octets so as to have the PTR record to be added to the reverse zone
reversedIP=$(echo $serverip| awk -F "." '{print $4 "." $3 "." $2 "." $1 }')

# Calculation of the reverse Zone
reverseZone="${reversedForZone}.in-addr.arpa"

# Calculation of the reverse zone URL for PowerDNS API call
reverseZoneApi="http://$apihost:8081/api/v1/servers/localhost/zones/${reverseZone}."

#echo $reverseZoneApi

# Calculation of the forward zone PowerDNS API
domainname=$domain
forwardZoneApi="http://$apihost:8081/api/v1/servers/localhost/zones/${domainname}."
#echo $forwardZoneApi

# Use the JSON template for A record so as to generate a file to be used to pass as data to CURL API call
cat $user_home/addArecord.template.json | sed -e 's|fqdn|'"$fqdn"'|g' -e 's|ip|'"$serverip"'|g' > $user_home/curlfileArecord.json

# Use the JSON template for PTR record so as to generate the file to be used to pass as data to CURL API Call
cat $user_home/addPTRrecord.template.json | sed -e 's|reversedIP|'"$reversedIP"'|g' -e 's|fqdn|'"$fqdn"'|g' > $user_home/curlfilePTRrecord.json

# create pdns recrod
echo "add $servername $serverip to powerdns"
echo " "
curl -X PATCH -H 'X-API-Key: changeme' $forwardZoneApi --data @/home/stanley/curlfileArecord.json > /dev/null 2>&1
curl -X PATCH -H 'X-API-Key: changeme' $reverseZoneApi --data @/home/stanley/curlfilePTRrecord.json > /dev/null 2>&1
echo "======================================"
)
}

create_git_commit() {
echo $servernote|egrep -q -i skip-git && echo "skip git commit to repo" || (
# git commit
jira_issue=`grep key: $user_home/jira.txt |awk '{print $NF}'`
egrep -q jira_issue $vmnotes && jira_issue=`grep jira_issue $vmnotes|awk -F":" '{print $2}'` || jira_issue=`grep key: $user_home/jira.txt |awk '{print $NF}'`
echo "======================================"
echo $jira_issue|egrep -q -i ITOPS && (
echo "Git commit new changes $jira_issue and push to master"
cd $git_dir
echo "run git pull"
git pull
echo "run git add . "
git add .
echo "run git commit"
git commit -a -m "$jira_issue create new server $servername via stackstorm/D42"
echo "run git push"
git push
echo "======================================") || echo "jira ticket = null - skip git commit"
#
)
}


create_all() {
# ipam add ip to device42 and pdns, jira
domain=zooxlabs.com
fqdn=${servername}.${domain}
if [[ -z "$serverip" ]]; then
   echo "serverip = null...exit"
elif ping -c 1 $serverip &> /dev/null; then
  echo "serverip $serverip is alive...skip addingto pdns/jira/device42"
else
host -al zooxlabs.com $apihost|egrep -q -w $serverip && echo "$serverip exist in powerdns..skip update device42/powerdns/jira" || (

create_vm_template
create_jira_issue
create_device42
create_pdns
create_git_commit
run-playbook $1 $2 $3
)
fi
}

if [[ $# -eq 0 ]] ; then
    display_help
    exit 0
fi

create_vm_template() {
  echo "Create host inventory: $servername"
  if [ $memorytemp -eq 2 ]; then
      memory=2048
  elif [ $memorytemp -eq 4 ]; then
      memory=4096
  elif [ $memorytemp -eq 8 ]; then
      memory=8192
  elif [ $memorytemp -eq 16 ]; then
      memory=16384
  elif [ $memorytemp -eq 32 ]; then
      memory=32768
  elif [ $memorytemp -eq 64 ]; then
      memory=65536
  else
      memory=4096
  fi
cat <<EOF>"$TF_OUT_FILE"
vsphere_host: "$vcenter_host"
vsphere_user: "$vcenter_user"
esxi_host: "$esxi1"
vsphere_datacenter: "$datacenter"
guest_network: "$network"
guest_custom_ip: "$serverip"
guest_netmask: "$subnet_mask"
guest_gateway: $gateway1
guest_dns_server1: 172.16.3.25
guest_dns_server2: 172.16.3.26
guest_domain_name: zooxlabs.com
guest_memory: $memorytemp
guest_vcpu: $cpu
guest_template: $ostemplate
vsphere_datastore: $datastore
guest_owner: "$owner"
guest_purpose: "$purpose"
zooxlabs_admin: "$zooxlabs_admin"
vm_folder: "$vm_folder"
vsphere_cluster: "$cluster"
EOF

# root disk
echo $ostemplate|egrep -q -i ubuntu16 && root_size=16
echo $ostemplate|egrep -q -i ubuntu18 && root_size=40
echo $ostemplate|egrep -q -i windows && root_size=40

#
egrep -q datadisk $vmnotes && (
datadisk=`grep datadisk $vmnotes|awk -F":" '{print $NF}'`
datadisk_num=`echo $datadisk|awk '{print NF}'`
echo "datadisk_num: $datadisk_num"
[[  "$datadisk_num" -gt 0 ]] && (
echo " "
cat <<EOF>>"$TF_OUT_FILE"
guest_disksize0: $root_size
EOF
)

#
count=1
for datadisk_count in $datadisk
do
cat <<EOF>>"$TF_OUT_FILE"
guest_disksize$count: $datadisk_count
EOF
  (( count++ ))
done
) || (
numdisk=`st2 run device42.get_device_by_id device_id=$deviceid|grep -w hddcount:|awk '{print $2}'`
#echo "numdisk: $numdisk"
([[ $numdisk =~ ^-?[0-9]+$ ]] && [[  "$numdisk" -gt 0 ]]) && (
echo " "
cat <<EOF>>"$TF_OUT_FILE"
guest_disksize0: $root_size
EOF
#
datadisk_size=`st2 run device42.get_device_by_id device_id=$deviceid|grep -w hddsize:|awk '{print $2}'|awk -F"." '{print $1}'`
for i in $(seq 1 $numdisk)
do
cat <<EOF>>"$TF_OUT_FILE"
guest_disksize$i: $datadisk_size
EOF
done
)
)

#
egrep -q mountpoint $vmnotes && (
mountpoint=`grep mountpoint $vmnotes|awk -F":" '{print $NF}'`
mountpoint_num=`echo $mountpoint|awk '{print NF}'`
echo "mountpoint_num: $mountpoint_num"

#
count=1
for mountpoint_count in $mountpoint
do
cat <<EOF>>"$TF_OUT_FILE"
mountpoint$count: $mountpoint_count
EOF
  (( count++ ))
done
) || (
numdisk=`st2 run device42.get_device_by_id device_id=$deviceid|grep -w hddcount:|awk '{print $2}'`
#echo "numdisk: $numdisk"
([[ $numdisk =~ ^-?[0-9]+$ ]] && [[  "$numdisk" -gt 0 ]]) && (
echo " "
cat <<EOF>>"$TF_OUT_FILE"
mountpoint0: $root_size
EOF
#
mountpoint_size=`st2 run device42.get_device_by_id device_id=$deviceid|grep -w hddsize:|awk '{print $2}'|awk -F"." '{print $1}'`
echo "add data disk... number of secodnary disks/size: $numdisk $mountpoint_size"
for i in $(seq 1 $numdisk)
do
cat <<EOF>>"$TF_OUT_FILE"
mountpoint$i: $mountpoint_size
EOF
done
)
)


}

# display help
if [ "$1" == "help" ] || [ "$1" == "-h" ] || [ "$1" == "-help" ] ; then
    display_help
    exit 0
fi

# cat content of inventory manage by terraform
if [ "$1" == "inventory" ]; then
    ls -1 $repo/itservice/infra/ansible/host_vars|sed 's/.yml//g'
    exit 0
fi

case $lifecycle in
    7)
        echo "purchasing lifecycle event"
        create_jira_issue_purchasing
	;;
    8)
        echo "mounting lifecycle"
        create_jira_issue_mounting
	;;
    9)
        echo "deploying lifecycle"
        run-ansible-role $1 $2
	;;
    13)
        echo "vm_provisioning lifecycle"
# main - run script if server not in definition file

# datacenter setting
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
    elif ( echo $servername|egrep -q "help" )
    then
      display_help
    else
        echo "server does not start with naming convention: fos-/sun-/3dx...exit)"
        exit 1
    fi


    serverip1=`/usr/bin/st2 run device42.suggest_next_ip subnet=$subnet1|grep ip:|awk '{print $NF}'`

    egrep -q owner $vmnotes && owner=`grep owner $vmnotes|awk -F":" '{print $2}'` || owner="Unknown"

    egrep -q purpose $vmnotes && purpose=`grep purpose $vmnotes|awk -F":" '{print $2}'` || purpose="Unknown"

    egrep -q ipaddress $vmnotes && serverip=`grep ipaddress $vmnotes|awk -F":" '{print $2}'` || serverip=$serverip1

    egrep -q zooxlabs-admin $vmnotes && zooxlabs_admin=`grep zooxlabs-admin $vmnotes|awk -F":" '{print $2}'` || zooxlabs_admin=""

    egrep -q resourcepool $vmnotes && resourcepool=`grep resourcepool $vmnotes|awk -F":" '{print $2}'` || resourcepool=$resourcepool1

    egrep -q cluster $vmnotes && cluster=`grep cluster $vmnotes|awk -F":" '{print $2}'` || cluster=$cluster1

    egrep -q network $vmnotes && network=`grep network $vmnotes|awk -F":" '{print $2}'` || network="VM Network"

    egrep -q datacenter $vmnotes && datacenter=`grep datacenter $vmnotes|awk -F":" '{print $2}'` || datacenter=$datacenter1

    egrep -q datastore $vmnotes && datastore=`grep datastore $vmnotes|awk -F":" '{print $2}'` || datastore=$datastore1

    [[ -z "$cputemp" ]] && cpu=1 ||  cpu=$cputemp

# windows or ubuntu
    echo $ostemplate|egrep -q -i ubuntu && filesystem=ext4 || filesystem=ntfs
    echo $ostemplate|egrep -q -i ubuntu && disk=40 || disk=100

    if [[ -z "$ostemplate" ]]; then
       ostemplate=TMPL-ubuntu1804-2018dec
    fi

#
    if [[ -z "$serverip" ]]; then
        echo "no ip address...exit"
    else
        if [ -f "$TF_OUT_FILE" ]; then
            echo "$servername found in host_vars"
            echo "skip..."
        else
            echo " "
            create_all
        fi
    fi
    ;;

    10)
        echo "production lifecycle event"
        create_jira_issue_production
        ;;
    12)
        echo "os_provisioning lifecycle event"
	echo "Run ansible playbook to bring up baremetal"
        ;;
    *)
        echo "none"
        ;;
    esac
