添加了ifPubkeyExists.sh
	作用：判断远程服务器上是否存在要删除的公钥
	位置：添加到Newclean.sh中，在传slash到远程服务器前，先用ifPubkeyExists.sh判断是否有公钥，
		若无，则无需传slash，也无法删除authorized_keys中的公钥。
