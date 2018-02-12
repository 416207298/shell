#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 输入一个公钥文件名，在'/'前加上'\',把修改后的输出放到out.txt中
void addSlashBeforeSlash(char *pubkey)
{
	int i = 0;
    char ch,slash = '/';
    FILE *fin = fopen(pubkey,"r");
    FILE *fout = fopen("out.txt","w");
    while((ch = getc(fin))!=EOF)
    {
		i++;
        if(ch == '/')
        {
            putc('\\',fout);
            putc(ch,fout);
        }
        else
            putc(ch,fout);
    }
    fclose(fin);
    fclose(fout);
}


// 获取文件内容并返回到字符串
char *getFileContent(char *file, char *out)
{
    int i=0;
    char ch;
    FILE *fp = fopen(file,"r");
    while((ch=getc(fp))!=EOF)
    {
        out[i] = ch;
        i+=1;
    }
    fclose(fp);
    return out;
}

int main(int argc, char *argv[])
{
	char output[1000] = {0}, output1[1000]; // 存放加上转义符后的(out.txt)公钥信息，
    char cmd[1000]; // 执行命令语句
    if (argc != 2)
	{
        printf("one input argument is needed.\n");
		return -1;
	}
    else
	{
	// 把公钥转化成转义后的，存到out.txt中
		addSlashBeforeSlash(argv[1]);
		printf("output success!\n");
	}

	// 把out.txt中的内容赋到output中
	strcpy(output,getFileContent("out.txt", output));
	//printf("%s",output);

	
	// 执行命令
	snprintf(output1,strlen(output),"%s",output);  // 去掉output结尾的换行符
	sprintf(cmd,"sed -i -e '/%s/d' ~/.ssh/authorized_keys",output1);
	//printf("%s\n",cmd);
	system(cmd);
	printf("done.\n");
	memset(cmd,0,sizeof(1000));
	sprintf(cmd,"rm -f out.txt");
	system(cmd);


    return 0;    
}
