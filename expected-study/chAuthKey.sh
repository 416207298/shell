#!/bin/bash

# $1--user, $2--IP, $3--old_key_pair_name_num, $4--new_key_pair_name_num
if [ $# -ne 4 ]; then
	echo "three arguments are needed."
	echo "1. username   2. IP	3. old_key_num	4. new_key_num" 
	exit
else
	expect <<- EOF
	proc generate_keys {} {
		send "ssh-keygen\r"
		expect "ssh/id_rsa):"
		send "/$1/.ssh/id_rsa$4\r"
		expect "passphrase):"
		send "\r"
		expect "passphrase again:"
		send "\r"
		expect "The key fingerprint is:"
		send "echo key generate done.\r"
	}
	
	proc authorize_pub_key { } {
		expect "done"
		send "cd ~/.ssh/\r"
		expect "*]*"
		send -- "cat id_rsa$4.pub >> authorized_keys\r"
		expect "*]*"
		send "echo authorized done.\r"
	
	}
	
	proc copy_pk_to_local { } {
		expect "done"
		send "scp id_rsa$4 root@172.16.1.133:~/codes/expected-study/\r"
		expect {
			"*(yes/no)?*" {
				send "yes\r"
				expect "password"
				send " \r"
			}
			"password" { send " \r" }
	}
	
	}
	
	
	spawn ssh -i id_rsa$3 $1@$2
	
	
	# ---------------------------------------------------#
	# 更新生成密钥对
	expect {
		"*(yes/no)?*" {
				send "yes\r"
				expect "*]*"
				generate_keys
			}
		"*]*" { generate_keys }
	}
	
	# 授权给authorized_keys
	authorize_pub_key 
	
	# 拷贝私钥到本地
	copy_pk_to_local 
	
	expect "*]*"
	# 删除服务器上的私钥
	send "rm -f id_rsa$4\r"
	expect "*]*"
	send "exit\r"
	
	expect eof
	EOF

fi

echo "User $1's Authorized keys has been updated."

./clean.sh $3 $1 $2
