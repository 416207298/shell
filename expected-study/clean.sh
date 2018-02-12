#!/bin/bash

# $1---keySeiralNum, $2--user, $3--IP
if [ $# -ne 3 ]; then
    echo "Three arguments are needed."
	echo 1、keySeiralNum， 2、user，3、IP
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
	send "rm  -f ~/.ssh/id_rsa$1*\r"
	expect "*]*"
	send "exit\r"
	expect eof
	EOF
		
	echo removing local private key...
	rm -f ~/codes/expected-study/id_rsa$1
	echo "clean done." 
fi
