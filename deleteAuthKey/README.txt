用法：slash [公钥全名] [用户名]

作用：在authorized_keys中删除指定的公钥

注意：公钥名不用绝对路径

步骤：
	1、先把公钥中需要转义的字符转义后，存到另一文件out.txt中；
	2、根据out.txt中的内容，用sed命令删除authorized_keys中对应的公钥。
