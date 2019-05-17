#!/bin/bash
#
# help function
display_help() {
cat << EOF

Usage: !restart-app-service [paramter1]

paramter1: app_name
    - pdns-staging
    - pdns-production

Command Line help:
    slack> !restart-app-service --help

EXAMPLE

    - Restart pdns staging
      Slack> !restart-app-service pdns-staging

EOF

}


# display help
if [ "$1" == "help" ] || [ "$1" == "-h" ] || [ "$1" == "-help" ] || [ "$1" == "--help" ] ; then
    display_help
    exit 0
fi

# Set script home directory
user_home=/home/stanley

# Set repo directory
repo=$user_home/git

lce=$user_home/slack/16

# Device42 host and password
d42_host=`grep d42_host: $user_home/d42_view|awk -F":" '{print $2}'`

# User in Device42 with view access to all script secrets
d42_view_user=`grep username: $user_home/d42_view|awk -F":" '{print $2}'`
d42_view_password=`grep password: $user_home/d42_view|awk -F":" '{print $2}'`


linux_username=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=linux_username&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`
linux_password=`curl -k -s -X GET -u "$d42_view_user:$d42_view_password" "https://$d42_host/api/1.0/passwords/?username=linux_password&plain_text=yes"| jshon |grep '"password":'|awk '{print $2}'|sed 's/"//g'|sed 's/,//g'`

#
echo -e "$1\n$2\n" > /home/stanley/.app_service.log

app_name=`grep mode /home/stanley/.app_service.log|awk -F"=" '{print $NF}'`

#
echo $mode|egrep -q enable && ansible_role=enable_haproxy_service || ansible_role=disable_haproxy_service

#
if [ $backend  == "lookerdev" ]; then
    server_backend=lookerdev_cluster
    backend_host=sun-looker01-dev.zooxlabs.com
    servername=fos-haproxy01,fos-haproxy02
elif [ $backend  == "lookerprod" ]; then
    server_backend=looker_cluster
    backend_host=sun-looker01.zooxlabs.com
    servername=fos-haproxy01,fos-haproxy02
elif [ $backend  == "jirastg" ]; then
    server_backend=jirastg_cluster
    backend_host=jira-stg2.zooxlabs.com
    servername=fos-haproxy01,fos-haproxy02
elif [ $backend  == "jiraprod" ]; then
    server_backend=jira_cluster
    server_backend_restapi=backend_restapi
    backend_host=jira.zooxlabs.com
    backend_host2=jira-not-available.zooxlabs.com
    servername=sun-hapjira01-prod,sun-hapjira02-prod
fi

echo "$mode $backend $servername"
#
sshpass -p "$linux_password"  ansible-playbook $repo/itservice/infra/ansible/playbooks/playbook.yml -i $repo/itservice/infra/ansible/d42_ansible_dynamic_inventory.py -l $servername  --ask-sudo-pass --extra-vars "ansible_user=$linux_username ansible_password=$linux_password mountpoint1=$mountpoint1 mountpoint2=$mountpoint2 zooxlabs_admin=$zooxlabs_admin server_backend=$server_backend server_backend_restapi=$server_backend_restapi backend_host=$backend_host backend_host2=$backend_host2" --tags $ansible_role --vault-password-file=/etc/st2/keys/.vault |tee $lce/ansible_role_log-$backend
