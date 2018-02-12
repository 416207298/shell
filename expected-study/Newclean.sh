#!/bin/bash

# $1---deleteKeySeiralNum, $2--user, $3--IP，4--new_pub_key_num
if [ $# -ne 4 ]; then
    echo "Three arguments are needed."
	echo 1、deleteKeySeiralNum， 2、user，3、IP，4、new_pub_keyNUM
    exit
else
	# 删除authorized_keys中oldKey、删除oldKey、删除本地私钥,需先上传slash
	echo executing cleaning remote server public_key...
	expect <<- EOF
	spawn ssh -i id_rsa$1 $2@$3
	expect "*]*"

	send "scp root@172.16.1.133:/root/codes/expected-study/slash ~/.ssh/slash\r"
	expect {
        "*(yes/no)?*" {
        send "yes\r"
        expect "password:"
        send " \r"
     }
        "*password:*" { send " \r" }
    }		

	expect "*]*"
	send "~/.ssh/slash ~/.ssh/id_rsa$1.pub\r"
	expect "done."
	send "rm -f ~/.ssh/id_rsa$1.pub\r"
	expect "*]*"
	send "exit\r"
	expect eof
	EOF
		
	echo "removing local old keys(two old and one new)..."
	rm -f id_rsa$4.pub 
	rm -f id_rsa$1.pub
	rm -f id_rsa$1
	echo "clean done." 
fi
