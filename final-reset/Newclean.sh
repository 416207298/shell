#!/bin/bash

# $1---deleteKeySeiralNum, $2--user, $3--IP，4--new_pub_key_num, $5---SPV'sIP, 6---rootPwd

rootPwd=" "
spvPath="/root/gitlearn/final-reset"
if [ "$2" == "root" ];then
	devicePath="/root/.ssh"
else
	devicePath="/home/$2/.ssh"
fi

if [ $# -ne 6 ]; then
    echo "Six arguments are needed."
	echo 1、deleteKeySeiralNum， 2、user，3、IP，4、new_pub_keyNUM, 5.SPVIp, 6.rootPwd
    exit
else
	echo "executing cleaning remote server public_key..."
	# 首先把判断公钥是否存在的脚本传到远程服务器
	# 然后删除authorized_keys中oldKey、删除oldKey、删除本地新公钥和旧私钥,需先上传slash
	expect <<- EOF
	spawn ssh root@$3
	expect "password:" { send "$6\r" }

	expect "*]*"
	send "scp root@$5:$spvPath/ifPubkeyExists.sh ~/.ssh\r"
	expect {
		"*(yes/no)?*" { send "yes\r";exp_continue }
		"password:" { send "$rootPwd\r" }
	}

	expect "*]*"
	send "~/.ssh/ifPubkeyExists.sh $2 $1\r"
	expect {
		"yes" {
			send "scp root@$5:$spvPath/slash $devicePath/slash\r"
			expect "password:"
			send "$rootPwd\r"
			expect "*]*"
			send "$devicePath/slash id_rsa$1.pub $2\r"
			expect "*]*"
			send "rm -f $devicePath/id_rsa$1.pub\r"
			expect "*]*"
			send "exit\r"
			expect eof
		}
		"no" {
			send "rm -f $devicePath/id_rsa$1.pub\r"
			expect "*]*"
			send "exit\r"
			expect eof
		}
	}

	EOF
		
	echo "removing local old keys(old_pk and new_pub)..."
	rm -f /root/.ssh/id_rsa$4.pub 
	rm -f /root/.ssh/id_rsa$1
	echo "clean done." 
fi
