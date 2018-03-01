#!/bin/bash

# $1--user, $2--IP, $3--old_key_timeStamp, $4--new_key_timeStamp, $5---SPVIp,	$6--rootPwd

spvPath="/home/spv/bin/addAuthUser"
devicePath=/home/$1/.ssh
spvRootPwd="62960909"

if [ $# -ne 6 ]; then                                                                                          
    echo "Six arguments are needed." 
    echo "1. username   2. IP   3. old_key_timeStamp  4. new_key_timeStamp  5.SPVIp   6.rootPwd"  
    exit                                                                                                                     
else 
	$spvPath/genNewKey.sh $4
	expect <<- EOF
	spawn ssh root@$2
	expect {
		"*(yes/no)?*" { send "yes\r";exp_continue }
		"password" { send "$6\r" }
	 }
	expect "*]*"
	send "scp root@$5:$spvPath/ifUserExist.sh .\r"
	expect {
        "*(yes/no)?*" { send -- "yes\r";exp_continue }
        "*password*" { send -- "$spvRootPwd\r" }
    }

	expect "*]*" { send -- "./ifUserExist.sh $1\r" } 
	expect {
		"*no user $1" {
			
			send "useradd $1\r"
			expect "*]*" { send -- "su $1\r" }
			expect "*]*" { send "mkdir -p /home/$1/.ssh\r" }
			expect "*]*" { send "chmod 700 /home/$1/.ssh\r" }
			expect "*]*" { send "cd /home/$1/.ssh/\r" }
			expect "*]*" { send "touch authorized_keys\r" }
			expect "*]*" { send "chmod 600 authorized_keys\r" }

			expect "*]*"
			send "scp root@$5:/root/.ssh/id_rsa$4.pub .\r"
			expect {
				"*(yes/no)?*" { send -- "yes\r";exp_continue }
				"*password*" { send -- "$spvRootPwd\r" }
			}
			expect "*]*"
			send -- "cat id_rsa$4.pub >> authorized_keys\r"
			expect "*]*"
			send "echo authorized done.\r"
			expect "done."
			send "exit\r"
			expect "*]*"
			send "exit\r"
			expect eof
		}
		"exist." { exit 3 }
	}
	
	EOF

fi
rm -f /root/.ssh/id_rsa$4.pub
