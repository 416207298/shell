#!/bin/bash

# $1--user, $2--IP, $3--old_key_timeStamp, $4--new_key_timeStamp, $5---SPVIp

spvRootPwd="62960909"
spvPath="/home/spv/bin/chAuthKey"

if [ $# -ne 5 ]; then                                                                                                         
    echo "Five arguments are needed." 
    echo "1. username   2. IP   3. old_key_timeStamp  4. new_key_timeStamp  5.SPVIp" 
    exit                                                                                                                      
else 
	expect <<- EOF
	set timeout 10
	spawn ssh -i /root/.ssh/id_rsa$3 $1@$2
	expect {
		"*password*" { send "\n"; exp_continue }
		"*try again." { exit 2 }
		"*]*" { send "cd ~/.ssh/\r" }
		timeout { exit 2 }
		eof { exit 2 }
	}
	expect "*]*"
	send "scp root@$5:~/.ssh/id_rsa$4.pub .\r"
	expect {
		"*(yes/no)?*" { send "yes\r"; exp_continue }
		"password"	{ send "$spvRootPwd\r" }
	 }

	expect "*]*"
	send -- "cat id_rsa$4.pub >> authorized_keys\r"
	expect "*]*"
	send "echo authorized done.\r"
	expect "done."
	send "exit\r"
	expect eof
	EOF
fi

result=$?
if [ $result -ne 0 ]; then
	exit $result
else	
	$spvPath/Newclean.sh $3 $1 $2 $4 $5
fi
