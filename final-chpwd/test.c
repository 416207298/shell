#include<stdio.h>
#include<string.h>
#include<stdlib.h>

char* ReadSpeacialLine(char* filename, int whichLine)
{
    if (whichLine < 0 || NULL == filename)
    {
        return NULL;
    }
    FILE *fp = fopen(filename, "r");
    if (NULL == fp) {
        return NULL;
    }
    int reachWhichLine = 0;
    int curLine = 1;
#define LINE_SIZE 256
    char *data = NULL;
    data = (char*) malloc(LINE_SIZE);
    while (!feof(fp))//文件未结束
    {
        memset(data, 0, LINE_SIZE);
        fgets(data, LINE_SIZE - 1, fp);
        curLine++;
        if (curLine > whichLine)
        {
            reachWhichLine = 1; //已经读取到whichLine行
            break;
        }
    }
    fclose(fp);

    return 0 == reachWhichLine ? NULL : data;
}


void GetLocalIP(char *IP) 
{
    char *ip = calloc(1, 50); 
    char *cmd = (char *)calloc(1,128);
    strcpy(cmd, "ip addr | grep inet | awk '{ print $2; }' | sed 's/\\/.*$//' >> /home/spv/log/IP.txt");
    system(cmd);
    strcpy(ip, ReadSpeacialLine("/home/spv/log/IP.txt", 3)); 
    snprintf(IP, strlen(ip), "%s", ip); // 去掉ip结尾的换行符
    system("rm -f /home/spv/log/IP.txt");
    free(cmd);
	free(ip);
}
int main()
{
	char spvip[60];
	GetLocalIP(spvip);
	printf("spvip = %s\n", spvip);
}
