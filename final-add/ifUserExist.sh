#!/bin/bash

# Judge if user is exist

user=$1

id $user >& /dev/null
if [ $? -eq 0 ];then
	echo "$user is exist."
else
	echo "There is no user $user."
fi
