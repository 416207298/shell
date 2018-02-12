#!/bin/bash
# 输入用户名、IP和密码，即可把特定机器上的操作口令和审批全部关闭
# 第一个参数user，第二个IP，第三个pwd
if [ $# -ne 3 ]; then
	echo "3 arguments are needed:"
	echo "1-user	2-IP	3-password"
	exit
else
	expect <<- EOF
	spawn ssh $1@$2
	expect {
		"*(yes/no)?*" {
		send "yes\r"
		expect "password"
		send "$3\r"
			}
		"password" { send "$3\r" }
	}
	expect "*]*"
	send "mysql -uroot -pp@s\#0fSPV\r"
	expect ">"
	send "update pvault.approval set status=0;\r"
	expect ">"
	send "update pvault.worknoteoperate set needOperatePwd=0;\r"
	expect ">"
	send "exit;\r"
	expect "*]*"
	send "exit\r"
	expect eof
	EOF
fi

echo "operation check workflow has been all turned off."
