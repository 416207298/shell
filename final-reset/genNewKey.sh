#!/bin/bash

key_timeStamp=$1 
expect <<- EOF
	spawn ssh-keygen
	expect "ssh/id_rsa):"
	send "/root/.ssh/id_rsa$key_timeStamp\r"

	expect {
		"Overwrite (y/n)?" { send "y\r";exp_continue }
		"passphrase):" { send "\r" }
	}
	expect "passphrase again:"
	send "\r"
	expect eof

EOF
chmod 600 /root/.ssh/id_rsa$key_timeStamp
