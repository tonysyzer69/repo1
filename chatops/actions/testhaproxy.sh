#!/bin/bash
tail -50 /var/log/st2/st2rulesengine.log |grep "chatops:testhaproxy"|tail -1|awk -F"u'user':" '{print $2}'|awk -F"'}" '{print $1}'|awk -F"u'" '{print $2}' > /home/stanley/log3
echo "`date` -1 $1" > /home/stanley/log1
echo "`date` -2 $2" >> /home/stanley/log1
echo "`date` -3 $3" >> /home/stanley/log1
echo "----------------" >> /home/stanley/log1
#st2 run chatops.post_message channel=chatops message=$1
echo "$1 $2 $3" > /home/stanley/log2
# Set script home directory
user_home=/home/stanley

# slack_log
slack_log=$user_home/audit_log/slack.log

date1=`date +"%y-%m-%d-%H:%M:%S"`
stackadmin=`grep stackadmin $user_home/.stackadmin|awk -F":" '{print $NF}'`
stackadmin_user=$user_home/.stackadmin
out1=`cat /home/stanley/log3`
#st2 run chatops.post_message channel=chatops message=$out1
echo "$1 $2 $3 $out1"

#if egrep -q $user $stackadmin_user; then
#  cat /home/stanley/slack/16/ansible_role_log-sun-stackstorm01
#else
#        echo "update_dns: Permission Denied... $1"
#        st2 run chatops.post_message channel=chatops message="update_dns: Permission Denied... $1"
#fi


