#!/bin/bash

# $1---deleteKeySeiralNum, $2--user, $3--IP，4--new_pub_key_num, $5---SPV'sIP

spvRootPwd="62960909"

if [ $# -ne 5 ]; then
    echo "Five arguments are needed."
	echo 1、deleteKeySeiralNum， 2、user，3、IP，4、new_pub_keyNUM, 5.SPVIp
    exit
else
	# 删除authorized_keys中oldKey、删除oldKey、删除本地私钥,需先上传slash
	spvPath="/home/spv/bin/chAuthKey"
	echo executing cleaning remote server public_key...
	expect <<- EOF
	spawn ssh -i /root/.ssh/id_rsa$1 $2@$3
	expect {
		"*password*" { send "\n"; exp_continue }
        "*try again." { exit 2 }
        "*]*" { send "cd ~/.ssh/\r" }
        timeout { exit 2 }
        eof { exit 2 }	
	}
	expect "*]*"

	send "scp root@$5:$spvPath/slash ~/.ssh/slash\r"
	expect {
        "*(yes/no)*" { send "yes\r";expect_continue }
        "password:" { send "$spvRootPwd\r" }
    }		

	expect "*]*"
	send "~/.ssh/slash id_rsa$1.pub $2\r"
	expect "done."
	send "rm -f ~/.ssh/id_rsa$1.pub\r"
	expect "*]*"
	send "exit\r"
	expect eof
	EOF
		
	if [ $? -ne 0 ]; then
		exit 2
	else
		echo "removing local old keys(old_pk and new_pub)..."
		rm -f /root/.ssh/id_rsa$4.pub 
		rm -f /root/.ssh/id_rsa$1
		echo "clean done." 
	fi
fi
