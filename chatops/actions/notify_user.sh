#!/bin/bash
date1=`date +"%y-%m-%d-%H:%M:%S"`
echo "$1 $2 - $date1" >> /home/stanley/audit_log/notify_user.log
