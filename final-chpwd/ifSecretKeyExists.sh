#!/bin/bash

if [ $# -ne 1 ];then
	echo "One argument should be given: secretKeySerialNum"
	exit 
else
	file="/root/.ssh/id_rsa$1"
	echo $file
	if [ ! -f $file ];then
		exit 2
	else
		exit 0
	fi
fi
