#!/bin/bash

# $1--user, $2--IP, $3--old_key_pair_name_num, $4--new_key_pair_name_num                                                      
if [ $# -ne 4 ]; then                                                                                                         
    echo "three arguments are needed."                                                                                        
    echo "1. username   2. IP   3. old_key_num  4. new_key_num"                                                               
    exit                                                                                                                      
else 
	expect <<- EOF
	proc generate_keys{ } {
		spawn ssh-keygen
		expect "ssh/id_rsa):"
		send "/root/.ssh/id_rsa$4\r"
		expect "passphrase):"
		send "\r"
		expect "passphrase again:"
		send "\r"
		expect eof
	}



	proc scp_and_authorize_pub_key { } {
		spawn ssh -i id_rsa$3 $1@$2
		expect "*]*"
		send "cd ~/.ssh/\r"
		expect "*]*"
		send "scp root@172.16.1.133:~/.ssh/id_rsa$4.pub .\r"
		expect {
			"*(yes/no)?*" {
				send "yes\r"
				expect "password"
				send " \r"
				}
			"password" { send " \r" }
		 }

		expect "*]*"
		send -- "cat id_rsa$4.pub >> authorized_keys\r"
		expect "*]*"
		send "echo authorized done.\r"
		expect "done."
		send "exit\r"
		expect eof
	}

	generate_keys
	scp_and_authorize_pub_key

EOF

fi

./Newclean.sh $3 $1 $2 $4
