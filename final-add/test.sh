#!/bin/bash


user=$1

id $user >& /dev/null
if [ $? -eq 0 ];then
	exit 0  # 相当于return返回值
else
	exit 3
fi
