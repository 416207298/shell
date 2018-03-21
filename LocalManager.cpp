#include <stdio.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include "unionerror.h"
#include "uniondb.h"
#include "AccStat.h"
#include "unionbox.h"
#include "unionbncomm.h"
#include <string.h>
#include <string>
#include <vector>
#include <map>
#include <sys/stat.h>
#include <fcntl.h>
#include <semaphore.h>
#include "unionlog.h"
#include "UnionIPC.h"
#include "unionenc.h"
#include "unioncommonser.h"
#define TEST 1
#define test 2
#define one
#define DBNAME "pvault"
#define UNION_ACC_ERROR 1
#define UNION_GENPWD_ERR 2
#define UNION_AUTH_ERROR 102
static int DevPort = 0;
//信号灯用于控制帐户进程、设备进程不同四操作数据库。
//但是他们可以同时调用比较耗时的ssh脚本。
//注意此信号量必须放在共享内存中。
static sem_t *mutex = NULL;
extern "C"
{
#include "unionlic.h"
}
struct UnionLicense SKVLic;
using std::string;
using std::vector;
using std::map;
using std::pair;
//声明
extern "C" int UnionLocalAccManage(char *WorkNote, char *OperSN);
extern "C" int UnionDelAccCompare(int type, int devid, char *account);
extern "C" int UnionAccLog(int accountID,int result, int accountType, char *msg);
extern "C" int UnionConnectServerEx( char *server, int port, int timeout);
extern "C" int UnionReadLicInfo(struct UnionLicense *SKVLicData, int reload);
#ifdef T
#undef T
#endif
#ifndef T
#define T(str) UnionGetText(2, (char*)str)
#endif


extern "C" int associated;
extern "C" {
#define printf(format, args...) UnionLog(__FILE__, __LINE__, UNION_LOG_DEBUG, "/home/spv/log/AccMananger.log", format, ##args)
}

static int GetAccInfo(char *worknote, char *sn, int accid);

typedef struct {
	int authlimit;
	int authlock;
	int id;
	int devid;
	int trust;
	int Istelnet;
	char *ip;
	char *account;
	char *pwd;
	char *worknote;
	char *sn;
	char *script;
	char *en;
	char *keyid;
	int updateFlag;
	int ossort;
	int worknotetype;
	int NoTTY;
	char *pwd2;//account表的密码
}DevInfo;
typedef struct {
	int accid;
	int trust;
	char *account;
	char *pwd;
	int status;
	char *supwd;
	char *keyid;
	char *tempwd;
	char *tempsupwd;
	char *script;
	int waterid;
	char *tempkeyid;
	int level;
	char *errmsg;
	int nologin;
	int userType;  // //添加的账户类型，0口令，1密钥
}AccInfo;
static DevInfo g_devinfo;
static AccInfo g_accinfo;


void GetLocalIP(char *IP);

static char *UnionExpectError(int err, const char *ExpectMsg, int addroot = 0)
{
	char file[512];
	static char msg[1024];
	msg[0] = 0;
	snprintf(file, sizeof(file), "%s/SSOScripts/error", UnionGetHomeDir());
	{
		FILE *fp = fopen(file, "r");
		if (fp)
		{
			char buff[1024];
			char pre[1024];
			pre[0] = 0;
			buff[0] = 0;
			while (fgets(buff, sizeof(buff), fp) != NULL)
			{
				if (strncmp(buff, "set", 3) != 0)
				{
					strcpy(pre, buff);
					continue;
				}
				char what[128];
				int num;
				sscanf(buff, "set %s %d",  what, &num);
				if (num == err)
				{
					strcpy(msg, pre+1);
				}
			}
			fclose(fp);
		}
	}
	if (strlen(msg) > 0 && msg[strlen(msg)-1] == '\n')
	{
		msg[strlen(msg)-1] = 0;
		strcpy(msg, T(msg));
	}
	if (addroot != 0 && g_devinfo.account && strlen(g_devinfo.account))
	{
		snprintf(msg+strlen(msg), sizeof(msg)-strlen(msg)-1, T(" 特权/管理帐户%s"), g_devinfo.account);
	}
	if (g_accinfo.errmsg && strlen(g_accinfo.errmsg))
	{
		snprintf(msg+strlen(msg), sizeof(msg)-strlen(msg)-1, " %s ", g_accinfo.errmsg);
	}
	if (ExpectMsg && err != 0)
	{
		snprintf(msg+strlen(msg), sizeof(msg)-strlen(msg)-1, ":\n%s", ExpectMsg);
	}
	printf("expect msg[%s]\n", msg);
	return msg;
}
static long long  InsertHisPwd(long long int hisid, const int accid, const char *pwd, const int result, const int trust = -1)
{ 
	char sql[1024];
	char *msg;
	int row;
	if (hisid == 0)//插入
	{
		//写入帐户表的改密时间
		UnionDBPrintf(sql, sizeof(sql),"insert into account_historypwd(accountID,pwd,updateTime,result) "
				"VALUES(%d, '%s', %ld, '%s')"
				,accid, pwd, time(NULL),  T("初始状态"));
		UnionDBInsertEx(sql, &row, &msg, &hisid);
		printf("his sql1[%s] row[%d] \n", sql, row);
	}
	else if (hisid > 0)
	{
		UnionDBPrintf(sql, sizeof(sql),
				"update account set lastChgPwdTime=%ld,lastChgPwdResult='%s',clrDrawTime=0,"
				"cryDrawTime=0,repDrawTime=0 where id=%d"
				,time(NULL), result==0?T("成功"):T("失败"),accid
				);
		UnionDBUpdate(sql, &row, &msg);
		printf("his sql1[%s] row[%d] \n", sql, row);
		UnionDBPrintf(sql, sizeof(sql),
				"update account set trustFlag=%d "
				"where id=%d AND trustFlag=0"
				,trust == -1?g_accinfo.trust:trust,accid
				);
		printf("trust sql[%s]\n", sql);
		UnionDBUpdate(sql, &row, &msg);
		UnionDBPrintf(sql, sizeof(sql), "update account_historypwd set "
				"updateTime=%ld, result='%s' WHERE id=%lld"
				,time(NULL), result==0?T("成功"):T("失败"), hisid);
		UnionDBUpdate(sql, &row, &msg);

	}
	
	return hisid;
}

/* added by luhg */
static long long  InsertHisKey(long long int hisid, const int accid, const char *tempSecretKey, const int result, const int trust = -1)
{
	char sql[6000];
	char *msg;
	int row;
	if (hisid == 0)//插入
	{
		//写入帐户表的改密时间
		UnionDBPrintf(sql, sizeof(sql),"insert into account_historypwd(accountID,secretKey,updateTime,result) "
				"VALUES(%d, '%s', %ld, '%s')"
				,accid, tempSecretKey, time(NULL),  T("初始状态"));
		//UnionLogDebugEx("chpwd.log", "sql =\n %s\n", sql);
		UnionDBInsertEx(sql, &row, &msg, &hisid);
		printf("his sql1[%s] row[%d] \n", sql, row);
	}    
	else if (hisid > 0) //更新状态
	{    
		UnionDBPrintf(sql, sizeof(sql),
				"update account set lastChgPwdTime=%ld,lastChgPwdResult='%s',clrDrawTime=0,"
				"cryDrawTime=0,repDrawTime=0 where id=%d"
				,time(NULL), result==0?T("成功"):T("失败"),accid
				);   
		UnionDBUpdate(sql, &row, &msg);
		printf("his sql1[%s] row[%d] \n", sql, row);
		UnionDBPrintf(sql, sizeof(sql),
				"update account set trustFlag=%d "
				"where id=%d AND trustFlag=0"
				,trust == -1?g_accinfo.trust:trust,accid
				);   
		printf("trust sql[%s]\n", sql);
		UnionDBUpdate(sql, &row, &msg);
		UnionDBPrintf(sql, sizeof(sql), "update account_historypwd set "
				"updateTime=%ld, result='%s' WHERE id=%lld"
				,time(NULL), result==0?T("成功"):T("失败"), hisid);
		UnionDBUpdate(sql, &row, &msg);
	}
	return hisid;

}
static void *GetSharedMem(int size)
{
	int fd = open("/dev/zero", O_RDWR);
	if (fd < 0)
		return NULL;
	void *ptr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd,0);
	close(fd);
	if (ptr!= MAP_FAILED)
		return ptr;
	return NULL;
}
static void UnionSemCreate()
{
	//直接返回，则管理帐户不使用多进程
	//return;
	mutex = (sem_t*)GetSharedMem(sizeof(sem_t));
	if (mutex != NULL)
	{
		if (sem_init(mutex,1,0) == -1)
		{
			mutex = NULL;
		}
	}

}
static void UnionSemPost()
{
	if (mutex) sem_post(mutex);
}
static void UnionSemWait()
{
	if (mutex)
	{
		while (sem_wait(mutex) == 11);
	}
}
static int CreateIPC(key_t *key)
{
	char name[1024];
	sprintf(name, "%s/log/%d", UnionGetHomeDir(), getpid());
	int fd = open(name, O_RDWR|O_CREAT, 0666);
	if (fd < 0) return -1;
	close(fd);
	*key = ftok(name, getpid()%255);
	fd = msgget(*key, 0400|0200|IPC_CREAT);
	if (fd == -1)
	{
		printf("失败一次\n");
		*key = ftok(name, random());
		fd = msgget(*key, 0400|0200|IPC_CREAT);
		if (fd == -1)
		{
			printf("无法创建队列\n");
			return 0;
		}
	}
	return fd;
}
extern "C" void PrintError(const char *msg);
static int IPCRead(const int fd, char *account, char *pwd, int* type, int nowait = 0, 
const int Way = 2)
{
	signal(SIGPIPE, SIG_IGN);
	IPC_MSG msg;
	//msg.mtype = 2;//AccManager发送1，接受2
	memset(&msg,0,sizeof(msg));
	int num = msgrcv(fd, &msg, UNION_IPC_LEN,Way, nowait);
	if (num == -1)
	{
		PrintError("IPC ");
	}
	printf("manager ipc recv %d[%ld:%s]\n", num, msg.type, msg.account);
	if (type) *type = msg.type;
	if (account) strcpy(account, msg.account);
	if (pwd) strcpy(pwd, msg.pwd);
	return num;
}
static int IPCWrite(const int fd, const char *account, const char *pwd, const int type,
		const int nowait = 0, const int Way = 1, int level = 0)
{
	//记录log
	IPC_MSG msg;
	memset(&msg,0,sizeof(msg));
	msg.mtype=Way;
	strcpy(msg.account, account);
	strcpy(msg.pwd, pwd);
	msg.type = type;
	msg.level = level;
	int num = msgsnd(fd, &msg, UNION_IPC_LEN, nowait);
	printf("manager ipc send %d:%s\n", type, account);
	return num;
}
static char *GetScript(const char *accid)
{
	if (accid == NULL || strlen(accid) == 0) accid = "-1";
	static char file[1024];
	sprintf(file, "%s/SSOScripts/scripts/", UnionGetHomeDir());
	chdir(file);
	char sql[1024];
	UnionDBPrintf(sql, sizeof(sql), 
			"select script.id,script.time from script_account,script WHERE script_account.accID='%s'"
			" AND script_account.scriptID=script.id", accid);
	char **result, *msg;
	int nrow,ncol;
	int flag;
	flag = UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
	printf("scriptsql1[%s][%d]\n", sql, nrow);
	if (nrow <= 0)
	{
		UnionDBPrintf(sql, sizeof(sql), 
				"select script.id,script.time from script,script_os, device, os WHERE "
				" device.id='%d' AND device.osID=os.id AND script_os.osID=os.id AND script_os.scriptID=script.id"
				, g_devinfo.id);
		flag = UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
		printf("scriptsql2[%s][%d]\n", sql, nrow);
		if (nrow <= 0)
		{
			UnionDBPrintf(sql, sizeof(sql), 
					"select script.id,script.time from script,script_ostype, device, os,ostype WHERE "
					" device.id='%d' AND device.osID=os.id AND os.ostypeID=ostype.id AND "
					" script_ostype.ostypeID=ostype.id AND script_ostype.scriptID=script.id"
					, g_devinfo.id);
			flag = UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
			printf("scriptsql3[%s][%d]\n", sql, nrow);
		}
		if (nrow <= 0)
		{
			UnionDBPrintf(sql, sizeof(sql), 
					"select script.id,script.time from script,script_template,template,template_ostype "
					",device,os,ostype WHERE device.id='%d' AND device.osID=os.id AND os.ostypeID=ostype.id"
					" AND template_ostype.ostypeID=ostype.id AND template_ostype.templateID=template.id  AND "
					"script.id=script_template.scriptID AND script_template.templateID=template.id "
					,g_devinfo.devid);
			flag = UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
			printf("scriptsql4[%s][%d]\n", sql, nrow);
		}
	}
	if (flag != 0 && msg)
	{
		printf("acc [%s]error[%s]\n", sql, msg);
	}
	if (nrow > 0)
	{
		strcat(file, result[0]);
		int fileOK = 0;
		if (access(file, X_OK) == 0)
		{
			//检查时间
			struct stat st = {0};
			if (stat(file, &st) == 0)
			{
				fileOK = 1;
				if (st.st_mtime < atol(result[1]))
				{
					fileOK = 0;
				}
			}
		}
		if (fileOK == 0)
		{
			unlink(file);
			umask(0);
			int fd = open(file, O_WRONLY|O_CREAT, 0777);
			if (fd < 0)
			{
				printf("文件%s打开失败\n", file);
			}
			else
			{
				UnionDBPrintf(sql, sizeof(sql), "select content FROM script where id=%s", 
						result[0]);
				char **script;
				UnionDBQuery(sql, &script, &nrow, &ncol, &msg);
				if (nrow == 1)
				{
					write(fd, script[0], strlen(script[0]));
				}
				else
				{
					printf("脚本%s查询失败\n", result[0]);
				}
				UnionDBFree(script, nrow*ncol);
				close(fd);
			}
		}
	}
	else
	{
		printf("帐户%s 无脚本\n", accid);
		return NULL;
	}
	printf("script file[%s]\n", file);
	return file;
}
static int CheckFailTime(int accid)
{
	return 0;
	int flag = 0;
	char sql[1024];
	UnionDBPrintf(sql, sizeof(sql), 
			"SELECT failedLogin FROM account where id=%d", accid);
	char **result, *msg;
	int row, col;
	UnionDBQuery(sql, &result, &row, &col, &msg);
	if (row > 0)
	{
		int times = atoi(result[0]);
		if (times >= g_devinfo.authlock && g_devinfo.authlock != 0)
		{
			printf("fail times exceeds %d\n", times);
			flag = ACCMAN_BEYOND_FAILS;
		}
		UnionDBFree(result, row*col);
	}
	return flag;
}
static int SetFailTime(int accid, int add = 0)
{
	char sql[1024];
	if (add != 0)
	{
		UnionDBPrintf(sql, sizeof(sql),
				"UPDATE account set failedLogin=failedLogin+1 WHERE id=%d", accid);
	}
	else
	{
		UnionDBPrintf(sql, sizeof(sql),
				"UPDATE account set failedLogin=0 WHERE id=%d", accid);
	}
	int row;
	char *msg;
	UnionDBUpdate(sql, &row, &msg);
	return 0;
}
static int GetRandomFd()
{
	int fd = -1;
	char file[1024];
	sprintf(file, "%s/log/%d_%ld.rand", UnionGetHomeDir(), getpid(), random()%100);
	fd = open(file, O_RDWR|O_CREAT, 0666);
	if (fd > 0)
	{
		unlink(file);
	}
	return fd;
}

static char *UnionDumpLoginKey(char *keyid)
{
	if (keyid == NULL || atoi(keyid) <= 0)
	{
		return NULL;
	}
	char sql[1024];
	UnionDBPrintf(sql, sizeof(sql), "select value from authSecretKey where id='%s'", keyid);
	char **result, *msg;
	int nrow,ncol;
	UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
	char file[512];
	if (nrow > 0)
	{
		snprintf(file, sizeof(file), "%s/log/id_%s_pid_%d.keys", 
				UnionGetHomeDir(), keyid, getpid());
		unlink(file);
		//密钥权限
		int fd = open(file, O_WRONLY|O_CREAT, 0600);
		if (fd >= 0)
		{
			write(fd, result[0], strlen(result[0]));
			close(fd);
		}
		UnionDBFree(result, nrow*ncol);
	}
	printf("key file[%s]\n", file);
	return strdup(file);
}
//unionbncommon.so
extern "C" const char UnionLetterType[];
static void EraseUnSeen(char *src)
{
	if (src == NULL || UnionLetterType == NULL) printf("UnionLetterType is null\n");
	char *temp = strdup(src);
	int j = 0;
	for (unsigned int i = 0; i < strlen(temp); ++i)
	{
		if (temp[i] > 0 && UnionLetterType[(int)temp[i]] == 0)continue;//不可见字符
		src[j++] = temp[i];
	}
	free(temp);
	src[j] = 0;
}
//参数：
//ExpectMsg，执行expect脚本的输出信息，最多只有200字节
//Expectfd，执行expect脚本的输出文件描述符。可以读取完整的输出
//ip,登录IP。type：操作类型。script：脚本路径。
//loginname：登录用户名。loginpass：登录密码。loginkey：登录密钥
//plusname：被操作/新用户名。pluspass：新密码。pluskey：新密钥（暂未使用）
//ExpectMsg：操作留下的信息。Expectfd：操作留下的描述符，可以读取操作信息。
//level：帐户等级
static int CallSSH(const char *ip, const char *type, const char *script, const char *loginname, 
		char *loginpass = NULL,char *loginkey = NULL,
		char *plusname = NULL, char *pluspass = NULL, char *pluskey = NULL,
		char **ExpectMsg = NULL, int *Expectfd = NULL, int level = 0, int nologin = 0,
		char *switchuser = NULL, char *switchpass = NULL)
{
	//if (DevPort <= 0) return -1;
	//调用脚本比较耗时，释放资源后，不要操作数据库
	loginkey = UnionDumpLoginKey(loginkey);
	printf("%d: SemPost at CallSSH\n", getpid());
	int flag;
	if ((flag = CheckFailTime(g_accinfo.accid)) != 0)
	{
		if (ExpectMsg) *ExpectMsg = strdup("帐户登录超过失败次数");
		return flag;
	}
	if (ExpectMsg) *ExpectMsg = NULL;
	UnionSemPost();
	char x[] = "x";
	if (loginpass == NULL||strlen(loginpass) == 0) loginpass = x;
	if (loginkey == NULL||strlen(loginkey)==0 ) loginkey = x;
	if (plusname == NULL||strlen(plusname)==0 ) plusname = x;
	if (pluspass == NULL||strlen(pluspass)==0 ) pluspass = x;
	if (pluskey == NULL||strlen(pluskey)==0 ) pluskey = x;
	if (g_devinfo.en == NULL||strlen(g_devinfo.en)==0 ) g_devinfo.en = x;
	if (switchuser == NULL ||strlen(switchuser)==0 ) switchuser = x;
	if (switchpass == NULL ||strlen(switchpass)==0 ) switchpass = x;
	static char cmd[1024];
	snprintf(cmd, sizeof(cmd),
			"%s/bin/ssh %s -f %d -t %s -s %s -u %s -p %s -k %s -U %s -P %s -K %s -e %s -l %d -n %d -z %s -Z %s",
			UnionGetHomeDir(),ip, DevPort, type, script, loginname,loginpass,loginkey,plusname,pluspass,pluskey, g_devinfo.en, level, nologin, switchuser, switchpass);
	if (g_devinfo.Istelnet)
	{
		strcat(cmd, " -0 ");
	}
	if (g_devinfo.NoTTY)
	{
		strcat(cmd, " -T");
	}
	printf("%s cmd[%s]\n", type, cmd);
	
	//获取ssh expect脚本打印信息，作为操作详情
	int rfd = GetRandomFd();
	int fd_stderr;
	int fd_stdout;
	if (rfd > 0)
	{
		fd_stderr = dup(STDERR_FILENO);
		fd_stdout = dup(STDOUT_FILENO);
		dup2(rfd, STDOUT_FILENO);
		dup2(rfd, STDERR_FILENO);
	}
	flag = UnionSystem(cmd);
	flag = WEXITSTATUS(flag);
	printf("%s cmd res[%d]\n", type, flag);
	if (rfd > 0)
	{
		dup2(fd_stderr,STDERR_FILENO);
		dup2(fd_stdout,STDOUT_FILENO);
		if (ExpectMsg != NULL && (*ExpectMsg == NULL || strlen(*ExpectMsg) == 0))
		{
			int flag = lseek(rfd, -200, SEEK_END);
			if (flag == -1)//文件太小
			{
				lseek(rfd, 0, SEEK_SET);
			}
			*ExpectMsg  = (char*)calloc(1, 201);
			read(rfd, *ExpectMsg , 200);
			EraseUnSeen(*ExpectMsg);
		}
		if (Expectfd != NULL)
		{
			*Expectfd = dup(rfd);
		}
		close(rfd);
	}
	UnionSemWait();
	SetFailTime(g_accinfo.accid, flag);
	return flag;
}

static int DupCallSSH(const char *ip, const char *type, const char *script, 
		const char *name, char *pwd, const int devid, UNION_ACC_ATTR *AccAttr,
		char *worknote, char *sn)
{
	if (AccAttr!= NULL)
	{
		//使用消息队列发送被管理帐户
		int fd;key_t key;
		if ((fd = CreateIPC(&key)) < 0) return 0;
		char *keyfile = UnionDumpLoginKey(g_devinfo.keyid);
		if (keyfile == NULL) keyfile = strdup("x");
		char cmd[1024];
		snprintf(cmd, sizeof(cmd),
				"%s/bin/ssh %s -f %d -t %s -s %s -u %s -p %s -k %s -m %d -e %s ",
				UnionGetHomeDir(),ip, DevPort, type, script, name,pwd,keyfile,
				key, g_devinfo.en);
		if (g_devinfo.Istelnet)
		{
			strcat(cmd, " -0 ");
		}
		if (g_devinfo.NoTTY)
		{
			strcat(cmd, " -T");
		}
		printf("msg cmd[%s]\n", cmd);
		pid_t sshpid = 0;
		//为了记录expect信息，重定向
		int log_fd = GetRandomFd();
		int fd_stderr;
		int fd_stdout;
		if (log_fd > 0)
		{
			fd_stderr = dup(STDERR_FILENO);
			fd_stdout = dup(STDOUT_FILENO);
			dup2(log_fd, STDERR_FILENO);
			dup2(log_fd, STDOUT_FILENO);
		}
		if ((sshpid = fork()) == 0)
		{
			execl("/bin/sh", "sh", "-c", cmd, NULL);
			exit(0);
		}
		//还原重定向
		if (log_fd > 0)
		{
			dup2(fd_stderr, STDERR_FILENO);
			dup2(fd_stdout, STDOUT_FILENO);
		}
		pid_t sendpid = 0;
		if ((sendpid = fork()) == 0)
		{
			//耗时过程，释放资源
			UnionSemPost();
			int it;
			for (it = 0;AccAttr[it].id > 0;++it)
			{
				if (AccAttr[it].lock != 0) continue;
				if (AccAttr[it].name == NULL) AccAttr[it].name = strdup("noname");
				if (AccAttr[it].tempwd == NULL) AccAttr[it].tempwd = strdup("nopwd");
				//开始管理
				IPCWrite(fd, AccAttr[it].name,AccAttr[it].tempwd,  IPC_TYPE_ACC, 0,1,AccAttr[it].level);
				char res[2][512];
				int status[2];
				//等待结果
				memset(res, 0, sizeof(res));
				//读取expect的执行结果
				IPCRead(fd, res[0], NULL, status);
				if (status[0] == IPC_TYPE_MSG)
				{
					AccAttr[it].errno = atoi(res[0]);
				}
				//获取提示信息
				if (log_fd > 0)
				{
					int flag = lseek(log_fd, -200, SEEK_END);
					if (flag == -1)//文件太小
					{
						lseek(log_fd, 0, SEEK_SET);
					}
					AccAttr[it].msg = (char*)calloc(1, 201);
					read(log_fd, AccAttr[it].msg, 200);
					EraseUnSeen(AccAttr[it].msg);
				}
				//如果ssh启动错误，我们能从父进程得知
				if (status[0] == IPC_TYPE_END)
				{
					UnionSemWait();
					return atoi(res[0]);
				}
			}
			UnionSemWait();
			//ssh can stop
			IPCWrite(fd, "", "", IPC_TYPE_END,IPC_NOWAIT);
			return 0;
		}
		//让子进程退出，并返回管理结果
		//主进程直接退出
		int status;
		pid_t waited;
		while((waited = waitpid(-1, &status, 0)))
		{
			status = WEXITSTATUS(status);
			if (waited == sendpid)
			{
				printf("waited send ipc %d res %d\n", sendpid, status);
				kill(sshpid,SIGKILL);
				break;
			}
			if (waited == sshpid)
			{
				printf("waited ssh ipc %d res %d\n", sshpid, status);
				char buff[16];
				snprintf(buff, sizeof(buff), "%d", status);
				//通知IPC子进程
				IPCWrite(fd, buff, "", IPC_TYPE_END, IPC_NOWAIT, 2);
			}
		}
		msgctl(fd, IPC_RMID, NULL);
		status = WEXITSTATUS(status);
		exit (status);
	}
	return UNION_ARGU_ERR;
}

static int UNLockAccount(int accid)
{
	char sql[1024];
	UnionDBPrintf(sql, sizeof(sql), 
			"UPDATE account set lockPID=-1,lockDev='' where id=%d", accid
			);
	int nrow;
	char *msg;
	printf("unlock %s\n", sql);
	UnionDBUpdate(sql, &nrow, &msg);
	return 0;
}

//返回值0成功
//1帐户状态错误
//2锁定失败
//3不允许的操作
static int LockAccount(int accid, int oper, int *succ, int*fail, char *msg)
{
	msg[0] = 0;
	char sql[1024],lock[1024];
	unsigned char devinfo[128];
	memset(devinfo,0,sizeof(devinfo));
	UnionGetDevSign(devinfo);
	UnionDBPrintf(lock, sizeof(lock), "UPDATE account set lockPID=%d, lockDev='%s' "
			"WHERE id=%d and (lockPID < 0 OR lockDev is null) ", getpid(), devinfo, accid);
	UnionDBPrintf(sql, sizeof(sql),"select a.curStatusID,a.protocolID,ostype.id "
			"FROM account a,device d,os,ostype,ostype_business where a.id=%d AND a.deviceID=d.id AND "
			"d.osID=os.id AND os.ostypeID=ostype.id AND ostype.id=ostype_business.ostypeID AND "
			"ostype_business.businessID='%d'", accid, g_devinfo.worknotetype & 0x000000FF);
	char **result, *info;
	int nrow, ncol;
	int flag = UnionDBUpdate(lock, &nrow, &info);
	if (flag != 0 || nrow != 1)
	{
		printf("lock[%s]\n", lock);
		strcpy(msg, T("帐户锁定失败"));
		return 2;
	}
	flag = UnionDBQuery(sql, &result, &nrow, &ncol, &info);
	printf("business sql[%s] row [%d]\n", sql, nrow);
	if (flag != 0)
	{
		if (info) strcpy(msg, info);
		return UNION_ARGU_ERR;
	}
	if (nrow == 0)
	{
		strcpy(msg, T("此类帐户不允许此操作"));
		UNLockAccount(accid);
		return 3;
	}
	else if (nrow == 1)
	{
		int stat = atoi(result[0]);
		UnionDBFree(result, nrow*ncol);
		if (g_devinfo.updateFlag == 1)
		{
			*succ = UnionAccStat(stat, SORegUpdate, 0);
			*fail = UnionAccStat(stat, SORegUpdate, 1);
		}
		else
		{
			*succ = UnionAccStat(stat, oper, 0);
			*fail = UnionAccStat(stat, oper, 1);
		}
	}
	if (*succ == SOAccError || *fail == SOAccError)
	{
		strcpy(msg, T("帐户状态检查错误"));
		UNLockAccount(accid);
		return 1;
	}
	return 0;
}
static int LockAndSet(UNION_ACC_ATTR *attr, int oper, int DoAll = 0)
{
	if (attr == NULL) return 0;
	if (DoAll != 0)
	{
		for (int i = 0; attr[i].id > 0; ++i)
		{
			LockAndSet(attr+i, oper);
		}
		return 0;
	}
	char sql[1024];
	char msg[512];
	attr[0].lock = LockAccount(attr[0].id, oper, &attr[0].succ, &attr[0].fail, msg);
	printf("lock res %d\n", attr[0].lock);
	if (attr[0].lock != 0)
	{
		UnionDBPrintf(sql, sizeof(sql),
				"update worknote_account set errno=%d ,detailInfo='%s',operateTime=%ld "
				"WHERE worknote='%s' AND operSN='%s' AND accountID='%d'",
				1, msg, time(NULL), g_devinfo.worknote, g_devinfo.sn, attr[0].id
				);
		int row;
		UnionDBUpdate(sql, &row, &attr[0].msg);
	}
	return attr[0].lock;
}
static int UNLockAndUNSet(UNION_ACC_ATTR *attr, int DoAll = 0)
{
	if (attr == NULL) return 0;
	if (DoAll != 0)
	{
		for (int i = 0; attr[i].id > 0; ++i)
		{
			if (attr[i].lock == 0)
				UNLockAndUNSet(attr+i);
		}
		return 0;
	}
	UNLockAccount(attr[0].id);
	return attr[0].lock;
}

static int SetOperByDevice(const char *worknote, const char *sn, const char *msg, 
		int devid, UNION_ACC_ATTR*AccMap)
{
	int i;
	for (i = 0; AccMap != NULL && AccMap[i].id > 0; ++i)
	{
		char sql[1024];
		UnionDBPrintf(sql, sizeof(sql),
				"UPDATE worknote_account set errno=%d, detailInfo='%s',operateTime='%ld' WHERE "
				"worknote='%s' AND operSN='%s' and accountID=%d", 
				-1, msg, time(NULL), worknote, sn, AccMap[i].id);
		int nrow;
		char *buff;
		UnionDBUpdate(sql, &nrow, &buff);
		printf("device oper [%s]\n", sql);
	}
	return 0;
}
int SetOperByAccount(const char *worknote, const char *sn, const char *msg, 
		int accid)
{
	char sql[1024];
	UnionDBPrintf(sql, sizeof(sql),
			"UPDATE worknote_account set errno=%d, detailInfo='%s',operateTime='%ld' WHERE "
			"worknote='%s' AND operSN='%s' and accountID=%d", 
			-1, msg, time(NULL), worknote, sn, accid);
	int nrow;
	char *buff;
	UnionDBUpdate(sql, &nrow, &buff);
	return 0;
}
static int DoReset(const char *ip, const char *type, const char *script, 
		const char *name, char *pwd, const int devid, UNION_ACC_ATTR* AccMap,
		char *worknote, char *sn)
{
	if (AccMap == NULL)
	{
		printf("无被管理帐户\n");
		return 0;
	}
	if (name == NULL || pwd == NULL || strlen(pwd) == 0 || strlen(name) == 0)  // 参数是管理账户名和密码
	{
		printf("没有管理/特权帐户\n");
		SetOperByDevice(worknote, sn, T("没有管理/特权帐户"), devid, AccMap);
		return UNION_ARGU_ERR;
	}
	UNION_ACC_ATTR *attr = AccMap;  // AccMap是账户信息的结构体数组,为什么要用结构体呢？
	int i;
	for (i = 0; AccMap[i].id > 0; ++i)
	{
		char sql[1024];
		UnionDBPrintf(sql, sizeof(sql),
				"SELECT a.name,w_a.tmpPwd,a.accountLevelID,w_a.trustFlag FROM account a, worknote_account w_a"
				" WHERE  a.id='%d' AND w_a.accountID=a.id AND w_a.worknote='%s'"
				" AND w_a.operSN='%s'", attr[i].id, worknote, sn
				);
		char **result, *why;
		int nrow, ncol;
		int flag = UnionDBQuery(sql, &result, &nrow, &ncol, &why);
		printf("reset sql[%s]\n",sql);
		if (flag == 0 && nrow> 0)
		{
			attr[i].name = strdup(result[0]);
			attr[i].tempwd = strdup(result[1]);
			attr[i].level = atoi(result[2]);
			attr[i].trust = atoi(result[3]);

			//提前记录密码
			attr[i].hisid = InsertHisPwd(0, attr[i].id, attr[i].tempwd, -1);
			UnionDBFree(result, nrow*ncol);
		}
		UnionLogDebugEx("mainten.log", "attr[%d].name=%s", i,attr[i].name);
	}
	

	char sql1[1024] = {0};
	char **result, *errmsg;
	int nrow, ncol;
	UnionDBPrintf(sql1, sizeof(sql1),
				"select authSecretKeyID from account where id=%d", attr[0].id);
	UnionDBQuery(sql1, &result, &nrow, &ncol, &errmsg);
	UnionLogDebugEx("mainten.log", "authSecretKeyID = %s", result[0]);


	if (!strcmp(result[0], ""))  // 口令账户
	{
		UnionLogDebugEx("mainten.log","%s","execute password update!!!!!!");
		int flag = DupCallSSH(ip, type, script, name, pwd, devid, attr, worknote, sn);
		for (i = 0; attr[i].id > 0; ++i)
		{
			if (attr[i].lock != 0 || attr[i].tempwd == NULL || attr[i].hisid == 0) continue;
			if (flag != 0)
			{
				attr[i].errno = flag;
			}
			if (attr[i].msg == NULL) attr[i].msg = strdup("");
			printf("DoReset accountid[%d] errno [%d]msg[%s]\n", 
					attr[i].id,attr[i].errno,attr[i].msg);
			char sql[1024];
			UnionDBPrintf(sql, sizeof(sql),
					"UPDATE worknote_account set errno=%d,detailInfo='%s',operateTime='%ld' WHERE "
					"worknote='%s' AND operSN='%s' AND accountID=%d"
					,attr[i].errno,UnionExpectError(attr[i].errno,attr[i].msg,1), time(NULL), worknote,sn,attr[i].id);
			int row;
			char *msg= NULL;
			UnionDBUpdate(sql, &row, &msg);

			//维护帐户表
			InsertHisPwd(attr[i].hisid, attr[i].id, attr[i].tempwd, attr[i].errno, attr[i].trust);
			{
				if (attr[i].errno == 0)
				{
					UnionDBPrintf(sql, sizeof(sql),
							"update account set password='%s',pwdTime='%ld', curStatusID=%d where id=%d",
							attr[i].tempwd,time(NULL),4,attr[i].id);
					UnionDBUpdate(sql, &row, &msg);
				}
				else
				{
					UnionDBPrintf(sql, sizeof(sql),
							"update account set curStatusID=%d where id=%d",
							3,attr[i].id);
				}
				printf("reset pwdsql[%s]\n", sql);
			}
		}
		UnionLogDebugEx("mainten.log", "flag = %d", flag);
		return flag;
	}

	/* added by luhg */
	else  // 密钥账户 
	{
		UnionLogDebugEx("mainten.log","%s","execute Authorized keys update!!!!!!");
		int flag = 0;
        char sql[5000];
		int row = 0, col = 0;
		char *errmsg = NULL; 
        char **result;
        int hispwdid = 0;
        char cmd[100];
        char spv_ip[50]; // 当前SPV的ip	
		int pid = getpid();
		char newPubName[32]; // 存放新公钥的名字(即时间戳+pid）
		int authKeyLen;

		// 先在口令策略中查询密钥长度
		memset(sql, 0, sizeof(sql));
		UnionDBPrintf(sql, sizeof(sql), "select pwdPolicyID from account where id=%d", attr[0].id);	
		UnionLogDebugEx("mainten.log", "sql=%s",sql);
		UnionDBQuery(sql, &result, &row, &col, &errmsg);
		if (atoi(result[0]) == 0){
			memset(sql, 0, sizeof(sql));
			UnionDBPrintf(sql, sizeof(sql), "select authKeyLen from pwdpolicy where policyDefault=1");
			UnionLogDebugEx("mainten.log", "sql=%s",sql);
			UnionDBQuery(sql, &result, &row, &col, &errmsg);
		}
		else{
			memset(sql, 0, sizeof(sql));
			UnionDBPrintf(sql, sizeof(sql), "select authKeyLen from pwdpolicy pp, account a where a.pwdPolicyID=pp.id and a.id=%d", attr[0].id);
			UnionLogDebugEx("mainten.log", "sql=%s",sql);
			UnionDBQuery(sql, &result, &row, &col, &errmsg);
		}
		authKeyLen = atoi(result[0]);
		UnionLogDebugEx("mainten.log", "authKeyLen=%d", authKeyLen);

		
		// 执行脚本，根据时间戳生成一对新密钥
		time_t now = 0;
		time(&now);
		sprintf(newPubName, "%ld%c%d", now, '_', pid);
		memset(cmd,0,100);
		sprintf(cmd,"%s %s %d","/home/spv/bin/pwdReset/genNewKey.sh ", newPubName, authKeyLen);
		UnionLogDebugEx("mainten.log", "gen_cmd=%s", cmd);
		system(cmd);
	
		// 把公钥名和私钥value插入到authSecretKey表中
		int f;
		char buf[5000] = {0};
		long long authSecretKeyId = 0; // 新密钥的ID
		char *authSecretKeyPath = (char *)calloc(1, 128); // 存放新密钥的路径
		char oldPubName[64]; // 旧公钥名字(时间戳+进程号)


		sprintf(authSecretKeyPath,"%s%s","/root/.ssh/id_rsa", newPubName);
		f = open(authSecretKeyPath, O_RDWR);
		if (f)
		{
			read(f, buf, 4500);

			UnionDBPrintf(sql, 5000, "insert into authSecretKey (value) values('%s')", buf); 
			UnionLogDebugEx("AccMananger.log","sql=[%s]", sql); 
			UnionDBInsertEx(sql, &row, &errmsg, &authSecretKeyId); 
			
		}
		memset(sql,0,1024);
		sprintf(sql,"update authSecretKey set pubKeyName='%s' where id=%lld ", newPubName, authSecretKeyId);
		UnionLogDebugEx("AccMananger.log", "sql=[%s]", sql);
		errmsg = NULL;
		UnionDBUpdate(sql, &row, &errmsg);

		// 改密前写入新密钥
		hispwdid = InsertHisKey(hispwdid, attr[0].id, buf, -1);

		// 执行脚本更新服务器公钥并删除authorized_keys中的旧公钥
		// 先找出旧公钥的名字
		memset(sql, 0, sizeof(sql));
		sprintf(sql, "select pubKeyName from account a,authSecretKey ak where a.id=%d and ak.id=a.authSecretKeyID;"
					,attr[0].id);	
		errmsg = NULL;
		UnionDBQuery(sql, &result, &row, &col, &errmsg);
		strcpy(oldPubName, result[0]);
		UnionLogDebugEx("mainten.log", "oldPubName = %s", oldPubName);

		// 获取SPV的IP
		GetLocalIP(spv_ip); 
		UnionLogDebugEx("mainten.log", "SPV's IP = %s", spv_ip);	
		
		// 把管理员root密码解密
		unsigned char *rootPwd = (unsigned char *)pwd;
		unsigned char clearpwd[100] = {0};
		char clearpwd_with_mark[100] = {0};
		int pwdlen = 0;
		UnionPswdDecrypt(rootPwd, strlen(pwd), clearpwd, 1000, &pwdlen);
		sprintf(clearpwd_with_mark, "%c%s%c", '"', clearpwd, '"');
		UnionLogDebugEx("mainten.log", "rootPwd=%s", clearpwd_with_mark);


		// 执行脚本更新公钥
		memset(cmd, 0, 100);
		sprintf(cmd, "/home/spv/bin/pwdReset/newChAuthKey.sh %s %s %s %s %s %s", attr[0].name, ip, oldPubName, 
					newPubName, spv_ip, clearpwd_with_mark);
		UnionLogDebugEx("mainten.log","cmd = %s",cmd);
		flag = system(cmd);
		flag = WEXITSTATUS(flag);
		UnionLogDebugEx("mainten.log", "Exe_flag = %d", flag);

		if (flag != 0)
			attr[0].errno = flag;
		UnionLogDebugEx("mainten.log", "attr[0].errno = %d", attr[0].errno);

		// 返回错误信息
		attr[0].msg = (char *)calloc(1, 256);
		if (flag != 0){
			if (flag == 1)
				strcpy(attr[0].msg, "设备上不存在此账户");
			else if (flag == 2)
				strcpy(attr[0].msg, "管理员密码错误");
			else if (flag == 3)
				strcpy(attr[0].msg, "操作超时");
		}
		else{
			attr[0].msg = (char *)calloc(1, 256);
			strcpy(attr[0].msg, " ");
		}

		//改密后写入历史表更新状态
		hispwdid = InsertHisKey(hispwdid, attr[0].id, buf, flag);
		
		int check_flag = 0;
		if (flag != 0)//改密失败后，重新进行校验                                                                         
        {   
            memset(cmd, 0, 100);
            sprintf(cmd, "/home/spv/bin/chAuthKey/check.exp %s %s %s", attr[0].name, ip, oldPubName);  
            UnionLogDebugEx("mainten.log", "cmd = %s", cmd);  
            check_flag = system(cmd);
            if (attr[0].msg){
                strcat(attr[0].msg, T(",密钥更新失败")); 
                printf("attr[0].msg[%s]\n", attr[0].msg); 
			}
        }                                                                                                                
        else                                                                  
        {    
        	if (attr[0].msg){
				strcat(attr[0].msg, T("密钥更新成功"));
                printf("attr[0].msg[%s]\n", attr[0].msg); 
			}
        } 

		UnionLogDebugEx("mainten.log", "attr[0].msg=%s", attr[0].msg/*UnionExpectError(attr[0].errno,attr[0].msg,1)*/);
		UnionLogDebugEx("mainten.log", "check_flag = %d", check_flag);
		int status = check_flag == 0? 4:3;

		// 修改工单信息
		memset(sql, 0, 1024);
		UnionDBPrintf(sql, sizeof(sql),
				"UPDATE worknote_account set errno=%d, detailInfo='%s', operateTime='%ld' WHERE "
				"worknote='%s' AND operSN='%s' AND accountID=%d"
				,attr[0].errno, attr[0].msg, time(NULL), worknote,sn,attr[0].id);
		UnionLogDebugEx("mainten.log", "update--sql=%s", sql);
		UnionDBUpdate(sql, &row, &errmsg);

		// 把账户改密状态写表
		if (attr[0].errno == 0)
		{
			memset(sql,0,1024);
			UnionDBPrintf(sql, sizeof(sql),
				"update account set authSecretKeyID='%lld',pwdTime='%ld', curStatusID=%d where id=%d",
				authSecretKeyId, time(NULL), status, attr[0].id);
			UnionDBUpdate(sql, &row, &errmsg);	
		}
		else
		{
			memset(sql,0,1024);
			UnionDBPrintf(sql, sizeof(sql),
				"update account set curStatusID=%d where id=%d", status, attr[0].id);
			UnionDBUpdate(sql, &row, &errmsg);
		}
		free(authSecretKeyPath);
		free(attr[0].msg);
		UnionLogDebugEx("mainten.log", "flag = %d", flag);
		return flag;
		/* End added by luhg */
	}
}
static int GetNameByNoLogin(char **loginname, char **loginpass, char **loginkey, int devid)
{
	if (loginname && loginpass && devid > 0 && loginkey)
	{
		*loginname = NULL;
		*loginpass = NULL;
		*loginkey = 0;
		//非linux模板，不能切换用户
		if (g_devinfo.ossort != 2)
			return 1;
		char sql[1024];
		snprintf(sql, sizeof(sql), "select account.name, account.password,account.authSecretKeyID from account where account.deviceID=%d and account.nologin=0 and account.curStatusID=4 limit 1", 
		devid);
		char **result, *msg;
		int nrow, ncol;
		UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
		printf("nologin sql[%s][%d]\n", sql, nrow);
		if (nrow > 0)
		{
			*loginname = strdup(result[0]);
			*loginpass = strdup(result[1]);
			*loginkey = strdup(result[2]);
			UnionDBFree(result, nrow*ncol);
		}
	}
	return 0;
}
char* ReadSpeacialLine(const char* filename, int whichLine)  // added by luhg
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

void GetLocalIP(char *IP)  // added by luhg
{
    char *ip = (char *)calloc(1, 50); 
    char *cmd = (char *)calloc(1,128);
    strcpy(cmd, "ip addr | grep inet | awk '{ print $2; }' | sed 's/\\/.*$//' >> /home/spv/log/IP.txt");
    system(cmd);
    strcpy(ip, ReadSpeacialLine("/home/spv/log/IP.txt", 3)); 
    snprintf(IP, strlen(ip), "%s", ip); // 去掉ip结尾的换行符
    system("rm -f /home/spv/log/IP.txt");
    free(cmd);
    free(ip);
}

int power(int num, int powNum) // added by luhg
{   
    int n = 1; 
    int result = 1;
    while(n<=powNum){
        result *= num; 
        n++; 
    }
    return result;  
}

int GenerateRandomNum()
{
	int randomNum = 0;
	int tem = 0;
	int n;
	srand(time(0));
	for(n=0; n<4; n++){
		tem = rand() % 10;
		randomNum += tem * power(10, n);
	}
	return randomNum;
}

static int DoChange(const char *script)
{
	//首先判断改密账户类型：口令，密钥
	if (!strcmp(g_accinfo.keyid,""))  // 口令型
	{
		UnionLogDebugEx("chpwd.log","keyid=%s",g_accinfo.keyid);
		int accid = g_accinfo.accid;
		int nrow, flag;
		char sql[1024], *msg, *ExpectMsg;
		int hispwdid = 0;
		//改密前写入历史密码
		hispwdid = InsertHisPwd(hispwdid, accid, g_accinfo.tempwd, -1);
		char *loginname = NULL, *loginpass = NULL, *loginkey = NULL;
		if (g_accinfo.nologin == 1)
		{
			GetNameByNoLogin(&loginname, &loginpass, &loginkey, g_devinfo.devid);
		}
		if (g_accinfo.level == 3) //特权帐户
		{
			if (g_accinfo.nologin == 1 && loginname && (loginpass||loginkey) &&
					strlen(loginname) && (strlen(loginpass) || strlen(loginkey)))
			{
				flag = CallSSH(g_devinfo.ip, "reset", script, 
						loginname,loginpass,loginkey,
						g_accinfo.account,g_accinfo.tempwd,NULL, &ExpectMsg, NULL, g_accinfo.level,
						g_accinfo.nologin, g_accinfo.account,g_accinfo.pwd);
			}
			else
			{
				flag = CallSSH(g_devinfo.ip, "reset", script, 
						g_devinfo.account,g_devinfo.pwd,g_accinfo.keyid,
						g_accinfo.account,g_accinfo.tempwd,NULL, &ExpectMsg, NULL, g_accinfo.level);
			}
			if (flag == 0)
			{
				//替换特权帐户
				g_devinfo.en = strdup(g_accinfo.tempwd);
			}
		}
		else
		{
			//先使用其他帐户登录，再切换帐户
			if (g_accinfo.nologin == 1 && loginname && (loginpass||loginkey)
					&& strlen(loginname) && (strlen(loginpass) || strlen(loginkey)))
			{
				//loginname,loginpass登录
				//g_accinfo.account是被操作帐户，g_accinfo.tempwd是新密码。旧密码存在en中。
				flag = CallSSH(g_devinfo.ip, "change", script, 
						loginname,loginpass,g_accinfo.keyid,
						g_accinfo.account/*这个参数可为NULL*/,g_accinfo.tempwd,NULL, &ExpectMsg, NULL, g_accinfo.level, 
						g_accinfo.nologin,g_accinfo.account,g_accinfo.pwd);
				free(loginname);
				free(loginpass);
			}
			else
			{
				flag = CallSSH(g_devinfo.ip, "change", script, 
						g_accinfo.account,g_accinfo.pwd,g_accinfo.keyid,
						NULL,g_accinfo.tempwd,NULL, &ExpectMsg, NULL, g_accinfo.level);
			}
		}
		//改密后更新历史密码
		hispwdid = InsertHisPwd(hispwdid, accid, g_accinfo.tempwd, flag);
		if (flag == 0)
		{
			UnionDBPrintf(sql, sizeof(sql),
					"update account set password='%s',pwdTime='%ld' where id=%d",
					g_accinfo.tempwd,time(NULL),accid);
			printf("pwdsql[%s]\n", sql);
			UnionDBUpdate(sql, &nrow, &msg);
		}
		int status = flag == 0? 4:3;
		if (flag != 0)//改密失败后，重新进行校验
		{
			int flag = CallSSH(g_devinfo.ip, "check", script, 
					g_accinfo.account,g_accinfo.pwd, g_accinfo.keyid, NULL, NULL, NULL, NULL);
			if (flag == 0) status = 4;
			if (g_accinfo.errmsg)
				strcat(g_accinfo.errmsg, T(" 改密失败 "));
		}
		else
		{
			if (g_accinfo.errmsg)
			{
				strcat(g_accinfo.errmsg, T(" 改密成功 "));
				printf("g_accinfo.errmsg[%s]\n", g_accinfo.errmsg);
			}
		}
		UnionDBPrintf(sql, sizeof(sql),
				"update account set curStatusID=%d where id=%d",
				status,accid);
		UnionDBUpdate(sql, &nrow, &msg);
		UnionDBPrintf(sql, sizeof(sql),
				"update worknote_account set errno=%d,detailInfo='%s',operateTime=%ld WHERE id=%d",
				flag , UnionExpectError(flag , ExpectMsg), time(NULL),g_accinfo.waterid);
		if (UnionDBUpdate(sql, &nrow, &msg) != 0)
		{
			if (msg)printf("update w_a [%s]error[%s]\n", sql,msg);
		}
		return flag;
	}
	/* added by luhg */
	else  // 密钥型
	{
		UnionLogDebugEx("chpwd.log","keyid=%s",g_accinfo.keyid);
		int nrow, flag;
		char sql[5000];
		int row = 0, col = 0;
		char *errmsg = NULL; 
		int hispwdid = 0;
		char cmd[100];
		char **result, *msg;
		char spv_ip[50]; // 当前SPV的ip
		int pid = getpid();
		char newPubName[50]; // 存放新公钥的名字(即时间戳+pid）
		int authKeyLen;  // 生成密钥的长度: 2048, 4096

		// 先在口令策略中查询密钥长度
		memset(sql, 0, sizeof(sql));
		UnionDBPrintf(sql, sizeof(sql), "select pwdPolicyID from account where id=%d", g_accinfo.accid);	
		UnionDBQuery(sql, &result, &row, &col, &errmsg);
		if (atoi(result[0]) == 0){
			memset(sql, 0, sizeof(sql));
			UnionDBPrintf(sql, sizeof(sql), "select authKeyLen from pwdpolicy where policyDefault=1");
			UnionDBQuery(sql, &result, &row, &col, &errmsg);
		}
		else{
			memset(sql, 0, sizeof(sql));
			UnionDBPrintf(sql, sizeof(sql), "select authKeyLen from pwdpolicy pp, account a where a.pwdPolicyID=pp.id and a.id=%d", g_accinfo.accid);
			UnionDBQuery(sql, &result, &row, &col, &errmsg);
		}
		authKeyLen = atoi(result[0]);
		UnionLogDebugEx("chpwd.log", "authKeyLen=%d", authKeyLen);


		// 执行脚本，根据时间戳生成一对新密钥
		time_t now = 0;
		time(&now);
		sprintf(newPubName, "%ld%c%d", now, '_', pid);
		memset(cmd,0,100);
		sprintf(cmd,"%s %s %d","/home/spv/bin/chAuthKey/genNewKey.sh ", newPubName, authKeyLen);
		UnionLogDebugEx("chpwd.log", "cmd=%s", cmd);
		system(cmd);
		
		// 把公钥名和私钥value插入到authSecretKey表中
		int f;
		char buf[5000] = {0};
		char secretKey[5000] = {0};
		long long authSecretKeyId = 0; // 新密钥的ID
		char *authSecretKeyPath = (char *)calloc(1, 128); // 存放新密钥的路径
		char oldPubName[64]; // 旧公钥名字(时间戳+pid)

		sprintf(authSecretKeyPath,"%s%s","/root/.ssh/id_rsa", newPubName);
		UnionLogDebugEx("AccMananger.log","authSecretKeyPath=[%s]", authSecretKeyPath);
		f = open(authSecretKeyPath, O_RDWR);
		UnionLogDebugEx("AccMananger.log","f=%d", f);
		if (f)
		{
			read(f, buf, 4500);

			UnionDBPrintf(sql, 5000, "insert into authSecretKey (value) values('%s')", buf); 
			UnionLogDebugEx("AccMananger.log","sql=[%s]", sql); 
			UnionDBInsertEx(sql, &row, &errmsg, &authSecretKeyId); 
			
		}
		memset(sql,0,1024);
		sprintf(sql,"update authSecretKey set pubKeyName='%s' where id=%lld ", newPubName, authSecretKeyId);
		UnionLogDebugEx("AccMananger.log", "sql=[%s]", sql);
		errmsg = NULL;
		UnionDBUpdate(sql, &row, &errmsg);

		// 改密前写入新密钥
		//UnionLogDebugEx("chpwd.log", "-------------------------------\nbuf=\n%s", buf);
		hispwdid = InsertHisKey(hispwdid, g_accinfo.accid, buf, -1);

		// 执行脚本更新服务器公钥并删除authorized_keys中的旧公钥
		// 先找出旧公钥的名字
		memset(sql, 0, sizeof(sql));
		sprintf(sql, "select pubKeyName from account a,authSecretKey ak where a.id=%d and ak.id=a.authSecretKeyID;"
					,g_accinfo.accid);	
		errmsg = NULL;
		UnionDBQuery(sql, &result, &row, &col, &errmsg);
		strcpy(oldPubName, result[0]);
		UnionLogDebugEx("chpwd.log", "oldPubName = %s", oldPubName);
	
		// 获取SPV的IP
		GetLocalIP(spv_ip); 
		UnionLogDebugEx("chpwd.log", "SPV's IP = %s", spv_ip);

		// 把旧私钥内容写入文件,用于执行脚本时登录服务器
#ifdef TEST
		flag = 0;
		sprintf(cmd, "%s %s", "/home/spv/bin/chAuthKey/ifSecretKeyExists.sh", oldPubName);
		flag = system(cmd);

		if (flag != 0){

			char file[50];
			memset(sql, 0, sizeof(sql));
			sprintf(sql, "select value from account a,authSecretKey ak where a.id=%d and ak.id=a.authSecretKeyID;"
						,g_accinfo.accid);
			errmsg = NULL;
			UnionDBQuery(sql, &result, &row, &col, &errmsg);
			strcpy(secretKey, result[0]);
			UnionLogDebugEx("chpwd.log", "\nsecretKey = %s", secretKey);
			sprintf(file, "/root/.ssh/id_rsa%s", oldPubName);
			FILE *fp = fopen(file, "w");
	    	fprintf(fp, "%s", secretKey);
    		fclose(fp);
			memset(cmd, 0, 100);
			sprintf(cmd, "chmod 600 %s", file);
			system(cmd);

		}
#endif


		// 执行脚本更新公钥
		memset(cmd, 0, 100);
		sprintf(cmd, "/home/spv/bin/chAuthKey/newChAuthKey.sh %s %s %s %s %s", g_accinfo.account, g_devinfo.ip, oldPubName, newPubName, spv_ip);
		UnionLogDebugEx("chpwd.log","cmd = %s",cmd);
		flag = system(cmd);
		flag = WEXITSTATUS(flag);
		//改密后写入更新状态
		hispwdid = InsertHisKey(hispwdid, g_accinfo.accid, buf, flag);
		UnionLogDebugEx("chpwd.log", "flag = %d", flag);

		// 改密失败的详细信息
		char *expectMsg = (char *)calloc(1, 256);
		g_accinfo.errmsg = (char *)calloc(1, 256);
		if (flag != 0){
            if (flag == 1)
                strcpy(expectMsg, "设备上不存在此账户, 或登录服务器密钥对错误");
            else if (flag == 2)
                strcpy(expectMsg, "未知错误");
        }


		//脚本执行成功后，把该账户的密钥ID更新
		if (flag == 0)
		{
			memset(sql,0,sizeof(sql));
			UnionDBPrintf(sql, sizeof(sql), "update account set authSecretKeyID=%lld where id=%d", 
						authSecretKeyId, g_accinfo.accid);
			errmsg = NULL;
			UnionDBUpdate(sql, &row, &errmsg);
		}

		int status = flag == 0? 4:3;

		int check_flag = 0;
        if (flag != 0)//改密失败后，重新进行校验
        {
			memset(cmd, 0, 100);
			sprintf(cmd, "/home/spv/bin/chAuthKey/check.exp %s %s %s", g_accinfo.account, g_devinfo.ip, oldPubName);
			UnionLogDebugEx("chpwd.log", "cmd = %s", cmd);
			check_flag = system(cmd);
			check_flag = WEXITSTATUS(check_flag);
			UnionLogDebugEx("chpwd.log", "check flag=%d", check_flag);
            if (check_flag == 0) status = 4; 
            if (g_accinfo.errmsg)
                strcat(g_accinfo.errmsg, T("更新密钥失败"));
        }    
        else 
        {    
            if (g_accinfo.errmsg)
            {    
                strcat(g_accinfo.errmsg, T("更新密钥成功"));
                printf("g_accinfo.errmsg[%s]\n", g_accinfo.errmsg);
            }    
        }    

		UnionLogDebugEx("chpwd.log", "g_accinfo.errmsg=%s", g_accinfo.errmsg);

        UnionDBPrintf(sql, sizeof(sql),
                "update account set curStatusID=%d where id=%d",
                status, g_accinfo.accid);
        UnionDBUpdate(sql, &nrow, &msg);
        UnionDBPrintf(sql, sizeof(sql),
                "update worknote_account set errno=%d, detailInfo='%s', operateTime=%ld WHERE id=%d",
                flag, expectMsg, time(NULL), g_accinfo.waterid);
        if (UnionDBUpdate(sql, &nrow, &msg) != 0)
        {
            if (msg)printf("update w_a [%s]error[%s]\n", sql,msg);
        }
		
		free(authSecretKeyPath);
		free(expectMsg);
		return flag;
		/* End added by luhg */
	}
}
static int DoCheck(char *script)
{
	int accid = g_accinfo.accid;
	int StatSucc, StatFail, flag, nrow;
	char lockmsg[1024],sql[1024], *msg, *ExpectMsg;
	if (LockAccount(accid, SOCheck, &StatSucc, &StatFail,lockmsg) != 0)
	{
		//
		printf("帐户%d %s\n", accid, lockmsg);
		UnionDBPrintf(sql, sizeof(sql),
				"update worknote_account set errno=%d ,detailInfo='%s',operateTime=%ld "
				"WHERE id=%d",
				1, lockmsg, time(NULL), g_accinfo.waterid
				);
		UnionDBUpdate(sql, &flag, &msg);
		return UNION_ACC_ERROR;
	}
	if (g_accinfo.level == 3 && g_devinfo.ossort != 2) flag = 0;
	else
	{
		char *loginname, *loginpass, *loginkey;
		if (g_accinfo.nologin == 1)
		{
			GetNameByNoLogin(&loginname, &loginpass, &loginkey, g_devinfo.devid);
		}
		if (g_accinfo.nologin == 1 && loginname && (loginpass || loginkey) &&
			strlen(loginname) && (strlen(loginpass) || strlen(loginkey)))
		{
			flag = CallSSH(g_devinfo.ip, "check", script, 
					loginname,loginpass, loginkey, NULL,NULL,NULL, &ExpectMsg, NULL, 0, g_accinfo.nologin, g_accinfo.account,g_accinfo.pwd);
		}
		else
		{
			flag = CallSSH(g_devinfo.ip, "check", script, 
					g_accinfo.account,g_accinfo.pwd, g_accinfo.keyid, NULL, NULL, NULL, &ExpectMsg);
		}
	}
	//更新worknote_account
	//更新帐户表
	{
		UnionAccLog(accid, flag, 0, NULL);
		UnionDBPrintf(sql, sizeof(sql),
				"update account set curStatusID=%d,lockPID=-1,lockDev='' where id=%d",
				flag == 0? StatSucc:StatFail,accid);
		UnionDBUpdate(sql, &nrow, &msg);
		UnionDBPrintf(sql, sizeof(sql),
				"update worknote_account set errno=%d,detailInfo='%s',operateTime=%ld WHERE id=%d",
				flag , UnionExpectError(flag , ExpectMsg), time(NULL),g_accinfo.waterid);
		UnionDBUpdate(sql, &nrow, &msg);
		printf("check result[%s][%d]\n", sql, nrow);
	}
	return flag;
}
static int DoTrust(const char *script)
{
	int flag = 0;
	//生成临时密码
	char *tempwd = UnionPwdGenByAccount(g_accinfo.accid);
	if (tempwd == NULL)
	{
		flag = UNION_GENPWD_ERR;
	}
	else
	{
		unsigned char EncryptedData[1024] = {0};
		int OutLen = 1024,len=0;
		UnionPswdEncrypt((unsigned char*)tempwd, strlen(tempwd), EncryptedData, OutLen, &len);
		free(tempwd);
		tempwd = (char*)EncryptedData;
		if (tempwd && strlen(tempwd))
		{
			g_accinfo.pwd = g_accinfo.tempwd;
			g_accinfo.tempwd = tempwd;
			flag = DoChange(script);
			if (flag == 0)
			{
				char sql[1024];
				UnionDBPrintf(sql, sizeof(sql), "update account set trustFlag=1 where id=%d", g_accinfo.accid);
				int row;
				char *msg;
				UnionDBUpdate(sql, &row, &msg);
			}
		}
		else
		{
			flag = UNION_GENPWD_ERR;
		}
	}
	return flag;
}

static int DoReg(char *script)
{
	int accid = g_accinfo.accid;
	int StatSucc, StatFail, nrow, flag;
	char lockmsg[1024],sql[1024], *msg, *ExpectMsg;	
	
	//LockAccount()返回值0成功1帐户状态错误2锁定失败3不允许的操作	
	if (LockAccount(accid, SOReg, &StatSucc, &StatFail,lockmsg) != 0)
	{
		//帐户锁定不成功
		printf("帐户%d %s\n", accid, lockmsg);
		UnionDBPrintf(sql, sizeof(sql),
				"update worknote_account set errno=%d ,detailInfo='%s',operateTime=%ld "
				"WHERE id=%d",
				1 , lockmsg, time(NULL),g_accinfo.waterid 
				);
		UnionDBUpdate(sql, &nrow, &msg);
		return UNION_ACC_ERROR;
	}
	
	int hisid = InsertHisPwd(0, accid, g_accinfo.tempwd, -1);
	char *loginname, *loginpass, *loginkey;
	if (g_accinfo.nologin == 1)
	{
		GetNameByNoLogin(&loginname, &loginpass, &loginkey, g_devinfo.devid);
	}
	if (g_accinfo.nologin == 1 && loginname && (loginpass || loginkey) &&
			strlen(loginname) && (strlen(loginpass) || strlen(loginkey)))
	{
		flag = CallSSH(g_devinfo.ip, "check", script, 
				loginname,loginpass,g_accinfo.tempkeyid, NULL, NULL, NULL, &ExpectMsg, 
				NULL, 0, g_accinfo.nologin,g_accinfo.account,g_accinfo.tempwd);
	}
	else
	{
		flag = CallSSH(g_devinfo.ip, "check", script, 
				g_accinfo.account,g_accinfo.tempwd,g_accinfo.tempkeyid, NULL, NULL, NULL, &ExpectMsg);
	}
	InsertHisPwd(hisid, accid, g_accinfo.tempwd, flag);
	if (flag == EXPECT_CONN_ERR)
	{
		StatFail = 1;
	}

#if 1	
	//mody by yusq 20180307 
	//帐户注册license控制
	int Nrow=0,Ncol=0;
	char **NRes,*Nerrmsg, Nsql[1024]; 
	//查询注册当前帐户是否存在，存在时帐户状态为2或3或4或5
	UnionDBPrintf(Nsql, 1024, "select count(*) from account where id = %d AND (curStatusID = 2 OR curStatusID = 3 OR curStatusID = 4 OR curStatusID = 5)",accid);
	UnionDBQuery(Nsql, &NRes, &Nrow, &Ncol, &Nerrmsg);
	//当前账户存在时，NTotal ！= 0
	int NTotal=atoi(NRes[0]);
	//重复注册时的判断，当帐户状态为2或3或4或5时，跳过license验证
	if ( NTotal ==0 )
	{
		int nret=0,inited=0,licensed=0,nnrow=0,nncol=0;
		char **Res,*errmsg,nsql[1024];
	
		nret = UnionCheckAuthStatus( &inited, &licensed );
		if(nret)
		{
			//授权检测失败
			return nret;
		}
		if (!licensed)
		{
			//系统未授权
			return UNION_LICENSE_UNAUTHORIZED;
		}
		struct UnionLicense  SKVLic;
		memset(&SKVLic, 0, sizeof(SKVLic));
		memset(&(SKVLic.SKVLicData), 0, sizeof(SKVLic.SKVLicData));
		UnionReadLicInfo(&SKVLic , 0);
  
		//认证成功、未认证、认证失败状态的帐户数不允许超过授权上限。
		UnionDBPrintf(nsql, sizeof(nsql), "select count(*) from account where curStatusID = 2 OR curStatusID = 3 OR curStatusID = 4 OR curStatusID =5");
		UnionDBQuery(nsql, &Res, &nnrow, &nncol, &errmsg);

		int Total=atoi(Res[0]);
		if(Total >= SKVLic.SKVLicData.KeysNum && SKVLic.SKVLicData.KeysNum != 0) 
		{
			//帐户达到License限制数
			UnionDBPrintf(nsql, sizeof(nsql),
				"update worknote_account set errno=%d,detailInfo='%s',operateTime=%ld WHERE id=%d",
				UNION_OBJECT_NUM_OVER_LIMIT , "帐户达到License限制数", time(NULL),g_accinfo.waterid);
				UnionDBUpdate(nsql, &nnrow, &errmsg);
				
			//帐户解锁
			UNLockAccount(accid);
		
			return UNION_OBJECT_NUM_OVER_LIMIT;
	  }
	}
#endif

	//更新worknote_account
	//更新帐户表
	{
		if (flag == 0 || g_devinfo.updateFlag == 1)
		{
			//trustFlag须为0，后续托管成功后再改为1
			UnionDBPrintf(sql, sizeof(sql),
					"update account set password='%s',pwdTime='%ld',trustFlag=0 where id=%d",
					g_accinfo.tempwd,time(NULL), accid);
			printf("pwdsql[%s]\n", sql);
			UnionDBUpdate(sql, &nrow, &msg);
			if (strlen(g_accinfo.tempkeyid) > 0 && atoi(g_accinfo.tempkeyid) > 0)
			{
				UnionDBPrintf(sql, sizeof(sql),
						"update account set authSecretKeyID='%s' where id=%d",
						g_accinfo.tempkeyid,accid);
				UnionDBUpdate(sql, &nrow, &msg);
			}
		}
		else
		{
			UnionDBPrintf(sql, sizeof(sql),
					"update account set password='%s',pwdTime='%ld' where id=%d AND password=''",
					g_accinfo.tempwd,time(NULL),accid);
			printf("pwdsql[%s]\n", sql);
			UnionDBUpdate(sql, &nrow, &msg);
			if (strlen(g_accinfo.tempkeyid) > 0 && atoi(g_accinfo.tempkeyid) > 0)
			{
				UnionDBPrintf(sql, sizeof(sql),
						"update account set authSecretKeyID='%s' where id=%d",
						g_accinfo.tempkeyid,accid);
				UnionDBUpdate(sql, &nrow, &msg);
			}
		}
		if (flag != EXPECT_CONN_ERR)
		{
			UnionDBPrintf(sql, sizeof(sql),
					"update account set curStatusID=%d,lockPID=-1,lockDev='' where id=%d",
					flag == 0? StatSucc:StatFail,accid);
		}
		else
		{
			UnionDBPrintf(sql, sizeof(sql),
					"update account set lockPID=-1,lockDev='' where id=%d",
					accid);
		}
		int nrow;
		UnionDBUpdate(sql, &nrow, &msg);
		
		UnionDBPrintf(sql, sizeof(sql),
				"update worknote_account set errno=%d,detailInfo='%s',operateTime=%ld WHERE id=%d",
				flag , UnionExpectError(flag, ExpectMsg), time(NULL),g_accinfo.waterid);
		UnionDBUpdate(sql, &nrow, &msg);
		
		if (flag == 0 && g_accinfo.trust == 1)
		{
			if (g_accinfo.errmsg == NULL) g_accinfo.errmsg = (char*)calloc(1,1024);
			strcat(g_accinfo.errmsg, T("注册成功 "));
			flag = DoTrust(script);
		}
		if (flag == 0 && g_accinfo.tempkeyid)
		{
			//密钥认证，同步账户
			char x[] = "x";
			flag = UnionCommonCli(0,UNION_COMMON_SYNC_ACC,x,x, 0, accid);
		}
		
		//mody by yusq 20171123
		UNLockAccount(accid);
	}
	return flag;
}

static int DoAdd(const char *ip, const char *type, const char *script, 
		const char *name, char *pwd, const int devid, UNION_ACC_ATTR *AccMap,
		char *worknote, char *sn)
{
	if (AccMap == NULL)
	{
		printf("无被管理帐户\n");
		return 0;
	}
	if (name == NULL || pwd == NULL || strlen(pwd) == 0 || strlen(name) == 0)
	{
		SetOperByDevice(worknote, sn, T("没有管理/特权帐户"), devid, AccMap);
		return UNION_ARGU_ERR;
	}

	



	/* Added by luhg */
	int i;
	char cmd[100] = {0};
	char q_sql[1024];
	char **result, *why;
	int nrow, ncol;
	int flag = 0;
	int userType;
	UNION_ACC_ATTR *attr = AccMap;
	
	for (i = 0; AccMap[i].id > 0; ++i)
	{
		UnionLogDebugEx("add.log", "AccMap[%d].id = %d", i, AccMap[i].id);
		// 判断添加账户的类型
		UnionDBPrintf(q_sql, sizeof(q_sql),
            "SELECT w_a.addUserType FROM account a, worknote_account w_a"
            " WHERE  a.id='%d' AND w_a.accountID=a.id AND w_a.worknote='%s'"
            " AND w_a.operSN='%s'", AccMap[i].id, worknote, sn); 	
		UnionLogDebugEx("add.log", "q_sql=%s", q_sql);
		UnionDBQuery(q_sql, &result, &nrow, &ncol, &why);	
		userType = atoi(result[0]);
		UnionLogDebugEx("add.log", "userType:%d", userType);

		if (userType == 1)  // 密钥型
		{
			attr[i].errno = 0;
			char sql[1024];
			//if (LockAndSet(attr+i, SOAdd) != 0)
			//{
			//	continue;
			//}				
			UnionDBPrintf(sql, sizeof(sql),
					"SELECT a.name FROM account a, worknote_account w_a"
					" WHERE  a.id='%d' AND w_a.accountID=a.id AND w_a.worknote='%s'"
					" AND w_a.operSN='%s'", attr[i].id, worknote, sn);
			char **result, *why;
			int nrow, ncol;
			flag = UnionDBQuery(sql, &result, &nrow, &ncol, &why);
			if (flag == 0 && nrow> 0)
			{
				attr[i].name = strdup(result[0]);
				UnionDBFree(result, nrow*ncol);
			}
			UnionLogDebugEx("add.log", "sql=%s", sql);
			UnionLogDebugEx("add.log", "attr[%d].name=%s",i,attr[i].name);

			// 生成一对新密钥对
    	    char newPubName[64]; // 存放新公钥的名字(即时间戳+pid）
			time_t now = 0;                                                                 
			int pid = getpid();
    	    time(&now);                                                                  
			sprintf(newPubName, "%ld%s%s%d", now, attr[i].name, "_", pid);
    	    memset(cmd,0,100); 
    	    sprintf(cmd,"%s %s","/home/spv/bin/addAuthUser/genNewKey.sh ",newPubName);
			system(cmd);

			// 把公钥名和私钥value插入到authSecretKey表中
    	    int f;
    	    char *errmsg = NULL;
    	    char buf[5000] = {0};
    	    int row = 0;
    	    long long authSecretKeyId = 0; // 新密钥的ID
    	    char *authSecretKeyPath = (char *)calloc(1, 128); // 存放新密钥的路径
			int hispwdid = 0;
			char spv_ip[30] = {0};

    	    sprintf(authSecretKeyPath,"%s%s","/root/.ssh/id_rsa",newPubName);
    	    f = open(authSecretKeyPath, O_RDWR);
    	    if (f)
    	    {
    	        read(f, buf, 4500);
    	        UnionDBPrintf(sql, 5000, "insert into authSecretKey (value) values('%s')", buf);
    	        UnionLogDebugEx("AccMananger.log","sql=[%s]", sql);
    	        UnionDBInsertEx(sql, &row, &errmsg, &authSecretKeyId);
    	    }
    	    memset(sql,0,1024);
    	    sprintf(sql,"update authSecretKey set pubKeyName='%s' where id=%lld ", newPubName, authSecretKeyId);
    	    UnionLogDebugEx("AccMananger.log", "sql=[%s]", sql);
    	    errmsg = NULL;
    	    UnionDBUpdate(sql, &row, &errmsg);
			
			// 添加前先把密钥插入历史
			hispwdid = InsertHisKey(hispwdid, attr[i].id, buf, -1);		

			// 获取SPV的IP
    	    GetLocalIP(spv_ip); 
    	    UnionLogDebugEx("add.log", "SPV's IP = %s", spv_ip);    
    	           
    	    // 把root密码解密
    	    unsigned char *rootPwd = (unsigned char *)pwd;
    	    unsigned char clearpwd[100] = {0}; 
			char clearpwd_with_mark[100] = {0};
    	    int pwdlen = 0; 
    	    UnionPswdDecrypt(rootPwd, strlen(pwd), clearpwd, 1000, &pwdlen);
			sprintf(clearpwd_with_mark, "%c%s%c", '"', clearpwd, '"');
    	    UnionLogDebugEx("add.log", "rootPwd=%s", clearpwd_with_mark);	

			// 执行脚本添加密钥型账户
			memset(cmd, 0, 100);
			sprintf(cmd, "%s %s %s %d %s %s %s", "/home/spv/bin/addAuthUser/addAuthKeyUser.sh", 
					attr[i].name, ip, 0, newPubName, spv_ip, clearpwd_with_mark);
			UnionLogDebugEx("add.log", "cmd=%s", cmd);	
			flag = system(cmd);
			flag = WEXITSTATUS(flag);
			UnionLogDebugEx("add.log", "flag = %d", flag);

			// 返回错误信息
			attr[i].msg = (char *)calloc(1, 256);
    	    if (flag != 0){
    	        if (flag == 1)
    	            strcpy(attr[i].msg, "管理员密码错误");
				else if (flag == 3)
					strcpy(attr[i].msg, "该账户已存在！");
    	    }    
			UnionLogDebugEx("add.log", "attr[%d].msg=%s", i, attr[i].msg);

			if (flag != 0)
			{
				attr[i].errno = flag;
			}
			UnionLogDebugEx("add.log", "attr[%d].errno=%d", i, attr[i].errno);
    	    memset(sql,0,1024);
			UnionDBPrintf(sql, sizeof(sql),
					"UPDATE worknote_account set errno=%d, detailInfo='%s', operateTime='%ld' WHERE "
					"worknote='%s' AND operSN='%s' AND accountID=%d"
					,attr[i].errno, attr[i].msg, time(NULL),worknote,sn,attr[i].id);
			char *msg;
			UnionDBUpdate(sql, &row, &msg);
			InsertHisKey(hispwdid, attr[i].id, buf, attr[i].errno);

			{
				if(attr[i].errno == 0)
				{
					UnionDBPrintf(sql, sizeof(sql), 
							"update account set authSecretKeyId='%lld', pwdTime='%ld', curStatusID=%d where id=%d",
							authSecretKeyId, time(NULL), 4, attr[i].id);	
				}
				else
				{
					UnionDBPrintf(sql, sizeof(sql),
							"update account set curStatusID=%d where id=%d",
							3, attr[i].id);
				}
				UnionDBUpdate(sql, &row, &msg);
			}
			free(attr[i].name);
			free(attr[i].msg);
			free(attr[i].tempwd);
			//托管
			if (attr[i].errno == 0)
			{
				GetAccInfo(g_devinfo.worknote,g_devinfo.sn, attr[i].id);
				if (g_accinfo.trust == 1)
					flag = DoTrust(script);
			}
			//帐户解锁
			UNLockAccount(attr[i].id);
			UnionLogDebugEx("add.log", "------------添加完一个密钥账户-------------");
		/* End added by luhg */

		}
		else if (userType == 0)
		{
		//for (i = 0; attr[i].id > 0; ++i)
		  {
			char sql[1024];
			if (LockAndSet(attr+i, SOAdd) != 0)
			{
				continue;
			}
			UnionDBPrintf(sql, sizeof(sql),
					"SELECT a.name,w_a.tmpPwd FROM account a, worknote_account w_a"
					" WHERE  a.id='%d' AND w_a.accountID=a.id AND w_a.worknote='%s'"
					" AND w_a.operSN='%s'", AccMap[i].id, worknote, sn
					);
			char **result, *why;
			int nrow, ncol;
			int flag = UnionDBQuery(sql, &result, &nrow, &ncol, &why);
			if (flag == 0 && nrow> 0)
			{
				attr[i].name = strdup(result[0]);
				attr[i].tempwd = strdup(result[1]);

				//提前记录密码
				attr[i].hisid = InsertHisPwd(0, attr[i].id, attr[i].tempwd, -1);
				UnionDBFree(result, nrow*ncol);
			}
			UnionLogDebugEx("add.log", "attr[%d].name = %s", i, attr[i].name);
		 }
			int flag = DupCallSSH(ip, type, script, name, pwd, devid, attr, worknote, sn);
		//for (i = 0; attr[i].id > 0; ++i)
		{
			if (attr[i].tempwd == NULL || attr[i].hisid == 0||attr[i].lock != 0) continue;
			if (flag != 0)
			{
				printf("DupCallSSH result [%d]\n", flag);
				attr[i].errno = flag;
			}
			
			if (attr[i].msg == NULL) attr[i].msg = strdup("");
			printf("DoReset accountid[%d] errno [%d]msg[%s]\n", 
					attr[i].id,attr[i].errno,attr[i].msg);
					
			char sql[1024];
			UnionDBPrintf(sql, sizeof(sql),
					"UPDATE worknote_account set errno=%d,detailInfo='%s',operateTime='%ld' WHERE "
					"worknote='%s' AND operSN='%s' AND accountID=%d"
					,attr[i].errno,UnionExpectError(attr[i].errno,attr[i].msg, 1), time(NULL),worknote,sn,attr[i].id);
			int row;
			char *msg;
			UnionDBUpdate(sql, &row, &msg);
		
	//add by yusq 20171030 
	//帐户添加license控制
	//
	//int nret=0,inited=0,licensed=0,nnrow=0,nncol=0;
	//char **Res,*errmsg,nsql[1024];
	//
	//nret = UnionCheckAuthStatus( &inited, &licensed );
	//if(nret)
	//{
	//	//授权检测失败
	//	return nret;
	//}
	//if (!licensed)
	//{
	//	//系统未授权
	//	return UNION_LICENSE_UNAUTHORIZED;
	//}
	//memset(&SKVLic, 0, sizeof(SKVLic));
	//memset(&(SKVLic.SKVLicData), 0, sizeof(SKVLic.SKVLicData));
	//UnionReadLicInfo(&SKVLic , 0);
  //
	//认证成功、未认证、认证失败状态的帐户数不允许超过授权上限。
	//UnionDBPrintf(nsql, sizeof(nsql), "select count(*) from account where curStatusID = 2 OR curStatusID = 3 OR curStatusID = 4");
	//UnionDBQuery(nsql, &Res, &nnrow, &nncol, &errmsg);
	//
	//int Total=atoi(Res[0]);
	//if(Total >= SKVLic.SKVLicData.KeysNum && SKVLic.SKVLicData.KeysNum != 0) 
	//	{
	//		//帐户达到License限制数
	//		UnionDBPrintf(nsql, sizeof(nsql),
	//			"UPDATE worknote_account set errno=%d,detailInfo='%s',operateTime='%ld' WHERE "
	//			"worknote='%s' AND operSN='%s' AND accountID=%d"
	//			,UNION_OBJECT_NUM_OVER_LIMIT,"帐户达到License限制数", time(NULL),worknote,sn,attr[i].id);
	//			UnionDBUpdate(nsql, &nnrow, &errmsg);
	//			
	//			//帐户解锁
	//			UNLockAccount(attr[i].id);
	//			
	//		return UNION_OBJECT_NUM_OVER_LIMIT;
	//	}
	//	//end add
		
		//维护帐户表
			InsertHisPwd(attr[i].hisid, attr[i].id, attr[i].tempwd, attr[i].errno);
		//if (attr[i].errno)
			{
				if (attr[i].errno == 0)
				{
					UnionDBPrintf(sql, sizeof(sql),
							"update account set password='%s', pwdTime='%ld', curStatusID=%d where id=%d",
							attr[i].tempwd,time(NULL),attr[i].succ,attr[i].id);
				}
				else
				{
					UnionDBPrintf(sql, sizeof(sql),
							"update account set curStatusID=%d where id=%d",
							attr[i].fail,attr[i].id);
				}
				printf("add pwdsql[%s]\n", sql);
				UnionDBUpdate(sql, &row, &msg);
			}
			free(attr[i].msg);
			free(attr[i].name);
			free(attr[i].tempwd);
			//托管
			if (attr[i].errno == 0)
			{
				GetAccInfo(g_devinfo.worknote,g_devinfo.sn, attr[i].id);
				if (g_accinfo.trust == 1)
					flag = DoTrust(script);
			}
			//帐户解锁
			UNLockAccount(attr[i].id);
		}
		//free(attr);
		//return flag;
	
		UnionLogDebugEx("add.log", "---------添加完一个口令账户-----------");
	  }

	}
	free(attr);
	UnionLogDebugEx("add.log", "---------------jump out-------------");
	return flag;
}

static int DoDel(const char *ip, const char *type, const char *script, 
		const char *name, char *pwd, const int devid, UNION_ACC_ATTR*AccMap,
		char *worknote, char *sn)
{
	if (AccMap == NULL)
	{
		printf("无被管理帐户\n");
		return 0;
	}
	UNION_ACC_ATTR *attr = AccMap;
	if (name == NULL || pwd == NULL || strlen(pwd) == 0 || strlen(name) == 0)
	{
		SetOperByDevice(worknote, sn, T("没有管理/特权帐户"), devid, AccMap);
		return UNION_ARGU_ERR;
	}
	int i;
	for (i = 0; AccMap[i].id > 0; ++i)
	{
		if (LockAndSet(AccMap+i, SODelete) != 0)
		{
			continue;
		}
		char sql[1024];
		UnionDBPrintf(sql, sizeof(sql),
				"SELECT a.name,w_a.tmpPwd FROM account a, worknote_account w_a"
				" WHERE  a.id='%d' AND w_a.accountID=a.id AND w_a.worknote='%s'"
				" AND w_a.operSN='%s'", attr[i].id, worknote, sn
				);
		char **result, *why;
		int nrow, ncol;
		int flag = UnionDBQuery(sql, &result, &nrow, &ncol, &why);
		if (flag == 0 && nrow> 0)
		{
			attr[i].name = strdup(result[0]);
			//attr[i].tempwd = strdup(result[1]);
		}
	}
	int flag = DupCallSSH(ip, type, script, name, pwd, devid, attr, worknote, sn);
	for (i = 0; attr[i].id > 0; ++i)
	{
		char sql[1024];
		int row;
		char *msg;
		if (attr[i].tempwd == NULL||attr[i].lock != 0) continue;
		if (flag != 0)
		{
			attr[i].errno = flag;
		}
		if (attr[i].msg == NULL) attr[i].msg = strdup("");
		printf("Do Del accountid[%d] errno [%d]msg[%s]\n", 
				attr[i].id,attr[i].errno,attr[i].msg);
		//维护流水表
		UnionDBPrintf(sql, sizeof(sql),
				"UPDATE worknote_account set errno=%d,detailInfo='%s',operateTime='%ld' WHERE "
				"worknote='%s' AND operSN='%s' AND accountID=%d"
				,attr[i].errno,UnionExpectError(attr[i].errno,attr[i].msg,1), time(NULL), worknote,sn,attr[i].id);
		UnionDBUpdate(sql, &row, &msg);
		//维护帐户表
		if (attr[i].errno == 0)
		{
			UnionDBPrintf(sql, sizeof(sql),
					"update account set curStatusID=6,trustFlag=0 where id=%d",
					attr[i].id);
			printf("del pwdsql[%s]\n", sql);
			UnionDBDelete(sql, &row, &msg);
			UnionDBPrintf(sql, sizeof(sql),
					"DELETE FROM account_group where accountID=%d", 
					attr[i].id);
			printf("del group sql[%s]\n", sql);
			UnionDBDelete(sql, &row, &msg);
		}
		free(attr[i].msg);
		free(attr[i].name);
		free(attr[i].tempwd);
		UNLockAccount(attr[i].id);
	}
	free(attr);
	return 0;
}

static int CheckListBusiness(const int devid)
{
	char sql[1024];
	UnionDBPrintf(sql, sizeof(sql),"select d.id "
			"FROM device d,os,ostype,ostype_business where d.id=%d AND "
			"d.osID=os.id AND os.ostypeID=ostype.id AND ostype.id=ostype_business.ostypeID AND "
			"ostype_business.businessID=6", devid);
	char **result, *msg;
	int nrow, ncol;
	UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
	return nrow;
}
static int UpdateWorknoteResource(char *worknote, char *sn, int devid, const char *info)
{
	char sql[1024];
	UnionDBPrintf(sql, sizeof(sql),
			"UPDATE worknote_resource SET errno=%d , detailInfo='%s' WHERE "
			" worknote='%s' AND operSN='%s' AND deviceID=%d",
			1, info, worknote, sn, devid);
	char *msg;
	int row;
	UnionDBUpdate(sql, &row, &msg);
	return 0;
}

static int GetParseCmd(char **cmd)
{
	if (cmd)
	{
		char sql[1024];
		UnionDBPrintf(sql, sizeof(sql), 
				"select distinct template.list from device,os,template_os,template "
				"WHERE device.id=%d and os.id=device.osID and "
				"template_os.osID=os.id and template.id=template_os.templateID"
				,g_devinfo.devid
				);
		char **result, *msg;
		int row, col;
		UnionDBQuery(sql, &result, &row, &col, &msg);
		printf("GetParseCmd sql0[%s]%d\n", sql, row);
		if (row <= 0)
		{
			UnionDBPrintf(sql, sizeof(sql), 
					"select distinct template.list from device,os,ostype,template_ostype,template "
					"WHERE device.id=%d and os.id=device.osID and ostype.id=os.ostypeID and "
					"template_ostype.ostypeID=ostype.id and template.id=template_ostype.templateID"
					,g_devinfo.devid
					);
			UnionDBQuery(sql, &result, &row, &col, &msg);
			printf("GetParseCmd sql[%s]%d\n", sql, row);
		}
		if (row > 0)
		{
			*cmd = result[0];
			printf("GetParseCmd res[%s]\n", *cmd);
		}
	}
	return 0;
}

static int DoList(const char *ip, const char *type, const char *script, 
		const char *name, char *pwd, const int devid, char *worknote, char *sn)
{
	printf("Call Do list\n");
	printf("SKVLic.SKVLicData.KeysNum = [%d]\n", SKVLic.SKVLicData.KeysNum);
	if (CheckListBusiness(devid) <= 0)
	{
		UpdateWorknoteResource(worknote, sn, devid, T("不支持的业务类型"));
	}
	char listfile[512],parsefile[512];
	snprintf(listfile, sizeof(listfile),"%s/log/%d.list", UnionGetHomeDir(), getpid());
	snprintf(parsefile, sizeof(listfile),"%s/log/%d.list.parse", UnionGetHomeDir(), getpid());
	int fd = STDOUT_FILENO;
	int cmd = CallSSH(ip, "list", script, name, pwd,g_devinfo.keyid, NULL, NULL, NULL, NULL, &fd);
	if (cmd != 0)
	{
		printf("list 失败，返回值 %d\n", cmd);
		return UpdateWorknoteResource(worknote, sn, devid, UnionExpectError(cmd,T("上收："),1));
	}
	char *Parse = NULL;
	GetParseCmd(&Parse);
	if (Parse == NULL)
	{
		return UpdateWorknoteResource(worknote, sn, devid, T("不能上收,无上收结果的处理方法"));
	}
	char parsecmd[1024];
	lseek(fd, 0 ,SEEK_SET);
	dup2(fd, STDIN_FILENO);
	snprintf(parsecmd, sizeof(parsecmd), "%s 2>&1>%s", Parse, parsefile);
	system(parsecmd);
	close(fd);
	FILE *fp = fopen(parsefile, "r");
	if (fp != NULL)
	{
		char buff[512];
		for(memset(buff, 0, sizeof(buff));
				NULL != fgets(buff, sizeof(buff), fp);
				memset(buff, 0, sizeof(buff)))
		{

			int errinfo = 0;

			while (strlen(buff) > 0 && 
					(buff[strlen(buff)-1] == '\n'|| buff[strlen(buff)-1] == '\r')
				  )
				buff[strlen(buff)-1]=0;
			if (strlen(buff) == 0)continue;
			int level = 1;
			if (strcmp(buff, name) == 0)
			{
				level = 2;
			}
			//帐户录入
			UnionDelAccCompare(0, devid, buff);
			char qsql[1024], **qset, *qerr;
			int qrow, qcol, ret = 0;
			UnionDBPrintf(qsql, sizeof(qsql), "select count(*) from pvault.account where curStatusID in (2,3,4,5)");
			if (UnionDBQuery(qsql, &qset, &qrow, &qcol, &qerr)) {
				printf("db query failed:[%s]\n", qerr);
				free(qerr);
				} else {
						ret = atoi(qset[0]);
						printf("qsql = [%s] ret = [%d]\n",qsql, ret);
						UnionDBFree(qset, qrow * qcol);
					}
			char sql[1024];
			if (ret < SKVLic.SKVLicData.KeysNum) {
				UnionDBPrintf(sql, sizeof(sql), "INSERT INTO account"
						"(name,protocolID,accountLevelID,curStatusID,deviceID) VALUES"
						"('%s', 0, %d, 2, %d)"
						,buff, level, devid);
			} else {
				UnionDBPrintf(sql, sizeof(sql), "INSERT INTO account"
						"(name,protocolID,accountLevelID,curStatusID,deviceID) VALUES"
						"('%s', 0, %d, 6, %d)"
						,buff, level, devid);

				errinfo = UNION_OBJECT_NUM_OVER_LIMIT;
			}
			printf("sql = [%s]\n", sql);
			char *msg;
			int row,col,flag; 
			int source = 0;//source 1 帐户增加
			long long id = 0;
			if ((flag = UnionDBInsertEx(sql, &row, &msg, &id)) != 0 && msg)
			{
				printf("sql[%s]error[%s]\n", sql, msg);
				free(msg);
			}
			if ((flag == UNION_DB_UNIQUE_KEY_ERR) && (ret < SKVLic.SKVLicData.KeysNum))
			{
				//只覆盖帐户状态为未注册、已注销
				UnionDBPrintf(sql, sizeof(sql), "SELECT id,curStatusID FROM account WHERE "
						" name='%s' AND protocolID=0 AND deviceID=%d"
						,buff, devid);
				char **res;
				flag = UnionDBQuery(sql, &res, &row, &col, &msg);
				if (row == 1)
				{
					id = atoll(res[0]);
					if (atoi(res[1]) == 1|| atoi(res[1]) == 6)
					{
						UnionDBPrintf(sql, sizeof(sql), "UPDATE account set curStatusID=2"
								",accountLevelID=%d WHERE "
								"id=%lld"
								,level,id);
						UnionDBUpdate(sql, &row, &msg);
						//已注销的帐户，上收到后，也发送邮件
						UnionAccLog(id, 0, 1, NULL);
						source = 1;
					}
				}
			}
			else
			{
				UnionAccLog(id, 0, 1, NULL);
				source = 1;
			}
			//把上收的帐户添入工单
			if (id > 0)
			{
				UnionDBPrintf(sql, sizeof(sql),
						"SELECT ID FROM worknote_account where worknote='%s' AND accountID='%lld'",
						worknote, id);
				char **result;
				int nrow, ncol;
				UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
				if (nrow > 0)
				{
					UnionDBFree(result, nrow*ncol);
					//已上收的帐户不记录
					/*
					UnionDBPrintf(sql, sizeof(sql),
							"UPDATE worknote_account set operateTime=%ld, operSN='%s',errno=0,"
							"detailInfo='',sourceInfo='' where "
							"worknote='%s' and accountID='%lld'", 
							time(NULL), sn, worknote, id);
					printf("list w_a2[%s]\n", sql);
					flag = UnionDBUpdate(sql, &row, &msg);
					*/
				}
				else
				{
					UnionDBPrintf(sql, sizeof(sql),
							"INSERT INTO worknote_account(worknote,accountID,operateTime,operSN, errno, detailInfo)"
							" VALUES('%s', %lld, %ld,'%s', %d, '%s')"
							,worknote, id, time(NULL), sn, errinfo, D(UnionGetErrDetail(errinfo)));
					printf("list w_a[%s]\n", sql);
					flag = UnionDBInsert(sql, &row, &msg);
				}
			}
		}
		//帐户比较，并预警
		UnionDelAccCompare(1, devid, NULL);
		fclose(fp);
	}
	unlink(listfile);
	unlink(parsefile);
	return cmd;
}


static int GetAccInfo(char *worknote, char *sn, int accid)
{
	memset(&g_accinfo, 0, sizeof(g_accinfo));
	if (accid == 0)
	{
		g_accinfo.accid = 0;
		/*
		g_accinfo.account = strdup(result[1]);
		g_accinfo.pwd = strdup(result[2]);
		g_accinfo.status = atoi(result[3]);
		g_accinfo.supwd = strdup(result[4]);
		g_accinfo.keyid = atoi(result[5]);
		g_accinfo.tempwd = strdup(result[6]);
		g_accinfo.tempsupwd = strdup(result[7]);
		g_accinfo.tempkeyid = atoi(result[8]);
		UnionDBFree(result, nrow*ncol);
		*/
		return 0;
	}
	char sql[1024], *msg, **result;
	int nrow, ncol;
	UnionDBPrintf(sql, sizeof(sql), 
			"SELECT a.id,a.name,a.password,a.curStatusID,a.suPwd,a.authSecretKeyID,"
			"w_a.tmpPwd,w_a.tmpSuPwd,w_a.authSecretKeyID,w_a.id,w_a.trustFlag,a.accountLevelID "
			",a.nologin FROM worknote_account w_a,account a "
			"WHERE w_a.accountID=a.id AND w_a.worknote='%s' AND w_a.operSN='%s' "
			" AND a.id='%d' "
			,worknote,sn,accid);
	UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
	if (nrow > 0)
	{
		g_accinfo.accid = atoi(result[0]);
		g_accinfo.account = strdup(result[1]);
		g_accinfo.pwd = strdup(result[2]);
		g_accinfo.status = atoi(result[3]);
		g_accinfo.supwd = strdup(result[4]);
		g_accinfo.keyid = strdup(result[5]);
		g_accinfo.tempwd = strdup(result[6]);
		g_accinfo.tempsupwd = strdup(result[7]);
		g_accinfo.tempkeyid = strdup(result[8]);
		g_accinfo.waterid = atoi(result[9]);
		g_accinfo.trust = atoi(result[10]);
		g_accinfo.level = atoi(result[11]);
		g_accinfo.nologin = atoi(result[12]);
		UnionDBFree(result, nrow*ncol);
		UnionLogDebugEx("chpwd.log","#########################%s!!!!!!!!!!!!!!!!!!!!!!!!",g_accinfo.keyid);
	}
	return 0;
}
static int SpeAccManage(char *worknote, char *sn, int type)
{
	int flag = 1, status = 2, errno = 1;
	const char *errmsg = T("操作成功，此帐户类型不支持口令校验");
	if (g_accinfo.accid == 0) return flag;
	if (!strcmp(g_accinfo.account, "[null]"))
	{
		errno = 0;
		flag = 0;
	}
	else if (!strcmp(g_accinfo.account, "[vnc_user]"))
	{
		errno = 0;
		flag = 0;
	}
	else if (g_accinfo.level == 3 && type == 1 && g_devinfo.ossort == 3)//特权
	{
		flag = 0;
		status = 4;
		errno = 0;
		errmsg = "";
	}
	if (flag == 0)
	{
		char sql[1024];
		int nrow;
		char *msg;
		if (type == 1)//注册
		{
			if (g_devinfo.updateFlag == 0)
			{
				UnionDBPrintf(sql, sizeof(sql),
						"update account set password='%s',pwdTime='%ld', curStatusID=%d where id=%d "
						" AND curStatusID<2 OR password='' OR password is null",
						g_accinfo.tempwd,time(NULL),status,g_accinfo.accid);
			}
			else
			{
				UnionDBPrintf(sql, sizeof(sql),
						"update account set password='%s',pwdTime='%ld', curStatusID=%d where id=%d "
						" AND curStatusID != 5",
						g_accinfo.tempwd,time(NULL),status,g_accinfo.accid);
			}
			UnionDBUpdate(sql, &nrow, &msg);
			printf("special sql[%s]\n", sql);
			InsertHisPwd(InsertHisPwd(0,g_accinfo.accid,g_accinfo.tempwd,errno),
					g_accinfo.accid,g_accinfo.tempwd,errno);
		}
		UnionDBPrintf(sql, sizeof(sql),
				"update worknote_account set errno=%d, detailInfo='%s',operateTime=%ld WHERE "
				"worknote='%s' AND operSN='%s' AND accountID='%d' ",
				errno, errmsg,time(NULL), worknote, sn, g_accinfo.accid
				);
		UnionDBUpdate(sql, &nrow, &msg);
		printf("special w_a sql[%s]\n", sql);
	}
	return flag;
}
static int AccManage(
		int type, char *worknote, char *sn, 
		int accid = 0,
		UNION_ACC_ATTR *AccMap = NULL,
		int devid = 0)
{
	//初始化全局帐户信息
	GetAccInfo(worknote, sn, accid);
	char acc[16];
	sprintf(acc, "%d", accid);
	char *script = GetScript(acc);
	if (script == NULL) 
	{
		printf("帐户获取脚本失败\n");
		return UNION_ARGU_ERR;
	}
	//匿名 vnc 特权帐户处理
	if (SpeAccManage(worknote, sn, type) == 0)
	{
		return 0;
	}

	int flag = 0;
	char lockmsg[1024];
	int succ,fail;
	//添加，删除，上收，帐户锁定、状态检查在接口中完成。
	//其他流程在接口外做检查，如DoChange接口方便复用
	switch(type)
	{
		case 1://注册
			flag = DoReg(script);
			break;
		case 2://添加
			flag = DoAdd(g_devinfo.ip, "add", g_devinfo.script, g_devinfo.account,g_devinfo.pwd,devid, AccMap,
					worknote,sn);
			break;
		case 3://注销
			break;
		case 4://删除
			flag = DoDel(g_devinfo.ip, "delete", g_devinfo.script, g_devinfo.account,g_devinfo.pwd,devid, AccMap,
					worknote,sn);
			break;
		case 5://改密
			flag = LockAccount(g_accinfo.accid, SOChange, &succ, &fail, lockmsg);
			if (flag == 0)
			{
				flag = DoChange(script);
				UNLockAccount(g_accinfo.accid);
			}
			else
			{
				SetOperByAccount(worknote, sn, lockmsg, g_accinfo.accid);
			}
			break;
		case 6://上收
			//if (accid == 0)
			{
				//上收的第二个阶段，重置帐户
				if (AccMap != NULL && AccMap[0].id > 0)
				{
					printf("dolist 2\n");
					LockAndSet(AccMap, SOReset, 1);
					int flag = UNION_AUTH_ERROR;
					if (g_devinfo.pwd2 && strlen(g_devinfo.pwd2))
					{
						flag = DoReset(g_devinfo.ip,"reset", script,
								g_devinfo.account,g_devinfo.pwd2, devid, AccMap, worknote, sn);
					}
					if (flag == UNION_AUTH_ERROR)
					{
						flag = DoReset(g_devinfo.ip,"reset", script,
								g_devinfo.account,g_devinfo.pwd, devid, AccMap, worknote, sn);
					}
					UNLockAndUNSet(AccMap, 1);
					return flag;
				}
				printf("dolist 1\n");
				int flag = UNION_AUTH_ERROR;
				if (g_devinfo.pwd2 && strlen(g_devinfo.pwd2))
				{
					flag = DoList(g_devinfo.ip,"list", g_devinfo.script,
							g_devinfo.account,g_devinfo.pwd2, devid, worknote,sn);
				}
				if (flag == UNION_AUTH_ERROR)
				{
					flag = DoList(g_devinfo.ip,"list", g_devinfo.script,
							g_devinfo.account,g_devinfo.pwd, devid, worknote,sn);
				}
				return flag;
			}
			break;
		case 7://重置
			if (accid == 0)
			{
				LockAndSet(AccMap, SOReset,1);
				flag = DoReset(g_devinfo.ip,"reset", g_devinfo.script,
						g_devinfo.account,g_devinfo.pwd, devid, AccMap, worknote, sn);
				UNLockAndUNSet(AccMap, 1);
				return flag;
			}
			break;
		case 8://托管
			flag = LockAccount(g_accinfo.accid, SOChange, &succ, &fail, lockmsg);
			if (flag == 0)
			{
				flag = DoChange(script);
				if (flag == 0)
				{
					char sql[1024];
					UnionDBPrintf(sql, sizeof(sql), "UPDATE account SET trustFlag=1 WHERE id='%d'",
							g_accinfo.accid);
					int row;
					char *msg;
					UnionDBUpdate(sql, &row, &msg);
				}
				UNLockAccount(g_accinfo.accid);
			}
			else
			{
				SetOperByAccount(worknote, sn, lockmsg, g_accinfo.accid);
			}
			break;
		case 9://更新
			flag = LockAccount(g_accinfo.accid, SOChange, &succ, &fail, lockmsg);
			if (flag == 0)
			{
				flag = DoChange(script);
				UNLockAccount(g_accinfo.accid);
			}
			else
			{
				SetOperByAccount(worknote, sn, lockmsg, g_accinfo.accid);
			}
			break;
		case 10://重置托管
			flag = DoReset(g_devinfo.ip,"reset", g_devinfo.script,
					g_devinfo.account,g_devinfo.pwd, devid, AccMap, worknote, sn);
			break;
		case 11://口令校验
			flag = DoCheck(script);
			break;
		case 12://领用
			break;
		default:
			printf("worknote type error\n");
			break;
	}
	return flag;
}
//-1端口获取失败
//-2认证方式错误
//-3非Linux/网络设备
static int GetResourcePort(int devid)
{
	char sql[1024];

	UnionDBPrintf(sql, sizeof(sql),
			"SELECT device.id from device,os,ostype WHERE device.osID=os.id AND os.ostypeID="
			"ostype.id AND (ostype.ossortID=2 OR ostype.ossortID=3) AND device.id=%d"
			,devid
			);
	char **result, *msg;
	int nrow, ncol;
	UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
	printf("sort sql[%s][%d]\n", sql, nrow);
	if (nrow <= 0)
	{
		return -3;
	}
	UnionDBPrintf(sql, sizeof(sql),
			"SELECT r.port,r.protocolID,d.authMode FROM union_resource r,device d WHERE r.deviceID=%d "
			"AND "
			"(r.protocolID=1 OR r.protocolID = 2) AND d.type=1 AND d.id=r.deviceID order by r.protocolID",
			devid);

	int port = -1;
	printf("port sql[%s]\n", sql);
	if (UnionDBQuery(sql, &result, &nrow, &ncol, &msg) == 0)
	{
		if (nrow > 0)
		{
			if ((atoi(result[2])&2)!=2)
			{
				return -2;
			}
			port = atoi(result[0]);
			if (atoi(result[1]) == 2)//telnet
			{
				g_devinfo.Istelnet = 1;
			}
			else if (nrow > 1)//ssh和telnet都存在时，检查ssh是否可联通
			{
				int fd = UnionConnectServerEx(g_devinfo.ip, port, 20);
				if (fd > 0)
				{
					close(fd);
				}
				else
				{
					g_devinfo.Istelnet = 1;
					port = atoi(result[ncol]);
				}
			}
			UnionDBFree(result, nrow*ncol);
		}
	}
	return port;
}
static int GetEnInfo(int devid)
{
	char sql[1024];
	UnionDBPrintf(sql, sizeof(sql),
			"SELECT password from account WHERE deviceID=%d AND (accountLevelID=3) AND (curStatusID=3 OR curStatusID=4) order by accountLevelID desc limit 1"
			,devid
			);
	char **result, *msg;
	int nrow, ncol;
	UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
	if (nrow > 0)
	{
		g_devinfo.en = result[0];
	}
	return 0;
}
static char *GetAccountPwd(int devid, char *account)
{
	char *val = NULL;
	char sql[1024];
	UnionDBPrintf(sql, sizeof(sql), "select password from account where deviceID=%d and name='%s' AND curStatusID=4 and protocolID=0",
			devid, account);
	char **result, *msg;
	int nrow, ncol;
	UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
	printf("acc sql[%s]%d\n", sql, nrow);
	if (result)
	{
		val = result[0];
	}
	return val;
}
static int GetDevInfo(char *worknote, char *sn, int devid)
{
	char sql[1024];
	char **result, *msg;
	int nrow, ncol;

	g_devinfo.devid = devid;
	g_devinfo.worknote = strdup(worknote);
	g_devinfo.sn = strdup(sn);

	UnionDBPrintf(sql, sizeof(sql),
			"select ostype.ossortID FROM device,os,ostype where device.id='%d' AND "
			"device.osID=os.id AND os.ostypeID=ostype.id",
			devid
			);
	UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
	if (nrow > 0)
	{
		g_devinfo.ossort = atoi(result[0]);
	}

	UnionDBPrintf(sql, sizeof(sql),
			"select applyinfo.updateFlag,worknote.worknoteType FROM applyinfo,worknote where"
			" applyinfo.worknote='%s' AND worknote.worknote='%s'",worknote,worknote
			);
	UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
	if (nrow <= 0)
	{
		UnionDBPrintf(sql, sizeof(sql),
				"select 0, worknote.worknoteType FROM worknote where"
				" worknote.worknote='%s'",worknote
				);
		UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
	}
	if (nrow > 0)
	{
		g_devinfo.updateFlag = atoi(result[0]);
		g_devinfo.worknotetype = atoi(result[1]);
		printf("type %x\n", g_devinfo.worknotetype);
	}
	
	UnionDBPrintf(sql, sizeof(sql),
			"select device.ip, device.id,authLimitNum,lockFailedNum,NoTTY FROM device where id=%d", devid
			);
	UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
	if (nrow == 1)
	{
		g_devinfo.ip = strdup(result[0]);
		g_devinfo.id = atoi(result[1]);
		g_devinfo.authlimit = atoi(result[2]);
		g_devinfo.authlock = atoi(result[3]);
		g_devinfo.NoTTY = atoi(result[4]);
		UnionDBFree(result, nrow*ncol);
	}
	
	//先查worknote_resource
	UnionDBPrintf(sql, sizeof(sql),
			"select w_r.loginAccount,w_r.loginPwd,w_r.loginAccountID,w_r.authSecretKeyID from worknote_resource w_r "
			"  WHERE w_r.worknote='%s' AND w_r.deviceID=%d "
			,worknote,devid
			);
	UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
	printf("devinfo0[%s]row[%d]\n", sql, nrow);
	//查询worknote_accouont
	if (nrow <= 0)
	{
		UnionDBPrintf(sql, sizeof(sql),
				"select w_a.loginAccount,w_a.loginPwd,w_a.loginAccountID,w_a.authSecretKeyID from worknote_account w_a "
				",account "
				"WHERE w_a.worknote='%s' AND w_a.operSN='%s' AND w_a.accountID=account.id AND "
				"account.deviceID=%d "
				, worknote, sn,devid);
		UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
		printf("devinfo1[%s]row[%d]\n", sql, nrow);
	}
	//随机获取管理帐户
	//过滤不能登录的帐户
	const char *sqllimit = "nologin=0";
	if (nrow <= 0 || (strlen(result[0]) == 0 && atoi(result[2]) <= 0))
	{
		if (g_devinfo.ossort == 2)//LINUX
		{
			UnionDBPrintf(sql, sizeof(sql),
					"SELECT name,password,id, authSecretKeyID from account WHERE %s and deviceID=%d AND (accountLevelID=3 OR accountLevelID=2) AND curStatusID=4 order by accountLevelID desc limit 1"
					,sqllimit,devid
					);
		}
		else if (g_devinfo.ossort == 3)//网络设备。不使用特权账户登录
		{
			UnionDBPrintf(sql, sizeof(sql),
					"SELECT name,password,id, authSecretKeyID from account WHERE %s and deviceID=%d AND (accountLevelID=2 ) AND (curStatusID=3 OR curStatusID=4) order by accountLevelID desc limit 1"
					,sqllimit,devid
					);
		}
		UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
		printf("devinfo3[%s]row[%d]\n", sql, nrow);
	}
	if (nrow > 0)
	{
		//系统已存在的帐户
		if (atoi(result[2]) > 0)
		{
			UnionDBPrintf(sql, sizeof(sql),
					"SELECT name,password,id,authSecretKeyID,curStatusID from account WHERE id = %d"
					,atoi(result[2])
					);

			UnionDBFree(result, nrow*ncol);
			UnionDBQuery(sql, &result, &nrow, &ncol, &msg);
			printf("devinfo4[%s]row[%d]\n", sql, nrow);
			if (nrow > 0)
			{
				if (atoi(result[4]) != 3 && atoi(result[4]) != 4)
				{
					printf("管理帐户的状态不对为%d\n", atoi(result[4]));
				}
				else
				{
					g_devinfo.account = strdup(result[0]);
					g_devinfo.pwd = strdup(result[1]);
					g_devinfo.keyid = strdup(result[3]);
					g_devinfo.script = GetScript(result[2]);
				}
			}
		}
		else if (strlen(result[0]) > 0)
		{
			g_devinfo.account = strdup(result[0]);
			g_devinfo.pwd = strdup(result[1]);
			g_devinfo.pwd2 = GetAccountPwd(devid, g_devinfo.account);
			if (g_devinfo.pwd && g_devinfo.pwd2 && strcmp(g_devinfo.pwd,g_devinfo.pwd2) == 0)
			{
				free(g_devinfo.pwd2);
				g_devinfo.pwd2 = NULL;
			}
			g_devinfo.keyid = strdup(result[3]);
			g_devinfo.script = GetScript(NULL);
		}
		else
		{
			printf("管理/特权帐户不唯一!\n");
		}
		UnionDBFree(result, nrow*ncol);
	}
	GetEnInfo(devid);
	if (g_devinfo.en == NULL) g_devinfo.en = strdup("x");
	return 0;
}
int UpdateWorknoteByDevice(char * worknote, char *sn, int devid, const char *msg)
{
	char sql[1024];
	UnionDBPrintf(sql, sizeof(sql), 
			"UPDATE worknote_account set errno='1',detailInfo='%s' WHERE "
			" worknote='%s' AND operSN='%s' AND accountID in (select id from account "
			" WHERE deviceID=%d AND protocolID=0)", 
			msg,worknote,sn,devid);
	char *err;
	int nrow;
	int flag = UnionDBUpdate(sql, &nrow, &err);
	return flag;
}
static int DevManage(char *worknote, char *sn, int devid)
{
	int flag = 0;
	char sql[1024];
	GetDevInfo(worknote, sn, devid);
	UnionDBPrintf(sql, sizeof(sql), "select worknoteType FROM worknote WHERE worknote='%s'",
			worknote);
	char **wnResult, *msg;
	int nrow, ncol;
	UnionDBQuery(sql, &wnResult, &nrow, &ncol, &msg);
	long long wnType = 0;
	if (nrow == 1)
	{
		wnType = atoll(wnResult[0]);
		wnType &= 0x000000FF;
	}
	else
	{
		printf("worknote error!\n");
		return UNION_ARGU_ERR;
	}
	UnionDBFree(wnResult, nrow*ncol);
	//检查是否为本地设备
	DevPort = GetResourcePort(devid);
	if (DevPort < 0) 
	{
		printf("设备%d端口%d获取失败. 非本地认证设备\n", devid, DevPort);
		if (DevPort == -2)
		{
			UpdateWorknoteByDevice(worknote, sn, devid, T("非本地认证设备"));
			return 0;
		}
		if (DevPort == -1 && wnType != 1)//注册时，没有端口的话，置为认证失败
		{
			UpdateWorknoteByDevice(worknote, sn, devid, T("ssh/telnet端口获取失败"));
			return 0;
		}
	}
	UnionDBPrintf(sql, sizeof(sql), 
			"select distinct account.id,account.accountLevelID FROM worknote_account,"
			"account,device,os,ostype WHERE "
			"account.protocolID =0 AND account.deviceID=device.id AND device.osID=os.id AND "
			"os.ostypeID=ostype.id AND (ostype.ossortID=2 OR ostype.ossortID=3) AND "
			"worknote_account.worknote='%s' AND worknote_account.operSN='%s' AND "
			"worknote_account.accountID=account.id AND account.deviceID='%d'",
			worknote,sn,devid);
	flag = UnionDBQuery(sql, &wnResult, &nrow, &ncol, &msg);
	printf("acc sql[%s]\n", sql);
	printf("dev %d has %d accounts\n", devid, nrow);
	if (flag != 0)
	{
		if (msg)
			printf("sql[%s]error[%s]\n", sql, msg);
		return flag;
	}
	UNION_ACC_ATTR *AccMap = (UNION_ACC_ATTR*)calloc(nrow+1, sizeof(UNION_ACC_ATTR));
	AccMap[nrow].id = -1;
	int i;
	for (i = 0;i < nrow; ++i)
	{
		AccMap[i].id = atoi(wnResult[i*ncol]);
	}
	//UnionDBFree(wnResult, nrow*ncol);
	//检查帐户状态。
	if (wnType == 6 || wnType == 2 || wnType== 4 || wnType == 7 ||wnType == 10)//上收 添加 重置 删除?
	{
		//此类工单不启动帐户进程
		printf("开始启动设备-帐户进程\n");
		int flag = AccManage(wnType, worknote,sn, 0, AccMap, devid);
		return flag;
	}
	if (nrow <= 0) return UNION_ARGU_ERR;

	//先修改特权帐户
	for (i = 0; i < nrow; ++i)
	{
		if (atoi(wnResult[i*ncol+1]) == 3 && g_devinfo.ossort == 2)
		{
			printf("先修改特权帐户%d\n", atoi(wnResult[i*ncol]));
			AccManage(wnType, worknote,sn,atoi(wnResult[i*ncol]));
			printf("修改特权帐户结束\n");
		}
	}
	//让步
	UnionSemPost();
	pid_t accpid[nrow];
	memset(accpid, 0, sizeof(accpid));
	for (i = 0; i < nrow  && 
			(mutex == NULL || g_devinfo.authlimit == 0 || i < g_devinfo.authlimit); ++i)
	{
		if (atoi(wnResult[i*ncol+1]) == 3 && g_devinfo.ossort == 2)
			continue;
		//不使用多进程
		if (mutex == NULL)
		{
			AccManage(wnType, worknote,sn,atoi(wnResult[i*ncol]));
		}
		else if ((accpid[i]= fork()) == 0)
		{
			//互斥的子进程
			UnionSemWait();
			AccManage(wnType, worknote,sn,atoi(wnResult[i*ncol]));
			//理论上应该在此处post信号。
			//为防止程序错误，不能到达此处，在waitpid处进行post
			exit(0);
		}
	}
	int status;
	pid_t waitid;
	
	//启动了i个进程
	//每有一个进程退出后，再启动一个新进程，直到进程总数为nrow
	while((waitid = waitpid(-1, &status, 0)))
	{
		if (waitid == -1||waitid == 0) break;
		for(int j = 0; j < i; ++j)
		{
			if (accpid[j] == 0) continue;
			if (accpid[j] == waitid)
			{
				accpid[j] = 0;
				status = WEXITSTATUS(status);
				printf(" acc id %d exit %d\n", waitid, status);
				UnionSemPost();

				//启动剩下的设备帐户进程
				if (i < nrow)
				{
					if ((accpid[i]= fork()) == 0)
					{
						//互斥的子进程
						UnionSemWait();
						AccManage(wnType, worknote,sn,atoi(wnResult[i*ncol]));
						exit(0);
					}
					i++;
				}
				break;
			}
		}
	}
	UnionSemWait();
	return 0;
}
int UnionLocalAccManage(char *worknote, char *sn)
{
	int inited, licensed;
	int ret = UnionCheckAuthStatus(&inited, &licensed);
	if(ret) {
		printf("授权检测失败！\n");
		return ret;
	}
	if(!licensed) {
		printf("系统未授权！\n");
		return UNION_LICENSE_UNAUTHORIZED;
		}
	
	memset(&SKVLic, 0, sizeof(SKVLic));
	memset(&(SKVLic.SKVLicData), 0, sizeof(SKVLic.SKVLicData));
	ret = UnionReadLicInfo(&SKVLic, 0);
	if (ret) {
		printf("获取软件授权失败！\n");
		return ret;
		}

	if (worknote == NULL || sn == NULL)
		return UNION_ARGU_ERR;
	UnionSemCreate();
	int flag = 0;
	char sql[1024];
	UnionDBPrintf(sql, sizeof(sql),
			"SELECT DISTINCT a.deviceID FROM account a, worknote_account w_a WHERE "
			"a.id=w_a.accountID AND w_a.worknote='%s' AND w_a.operSN='%s' "
			" UNION "
			"SELECT DISTINCT worknote_resource.deviceID FROM worknote_resource WHERE" 
			" worknote_resource.worknote='%s' AND worknote_resource.operSN='%s' AND "
			" worknote_resource.protocolID <=1 "
			,worknote, sn,worknote, sn
			);
	char **devRes, *msg;
	int devRow, devCol;
	flag = UnionDBQuery(sql, &devRes, &devRow, &devCol, &msg);
	printf("dev sql [%s]\nI have %d devs\n", sql, devRow);
	if (flag != 0)
	{
		if (msg)
		{
			printf("sql[%s]error[%s]\n", sql, msg);
			free(msg);
		}
	}
	int i;
	pid_t devpid[devRow];
	memset(devpid, 0, sizeof(devpid));
	for (i = 0; i < devRow; ++i)
	{
		if (mutex == NULL)
		{
			DevManage(worknote, sn, atoi(devRes[i*devCol]));
		}
		else if ((devpid[i] = fork()) == 0)
		{
			//互斥的子进程
			UnionSemWait();
			DevManage(worknote, sn, atoi(devRes[i*devCol]));
			exit(0);
		}
	}
	//让步
	UnionSemPost();
	int status;
	pid_t waitid = 0;
	while((waitid = waitpid(-1, &status, 0)))
	{
		if (waitid == -1 || waitid == 0)break;
		for (i = 0; i < devRow && devpid[i] != 0; ++i)
		{
			if (waitid == devpid[i])
			{
				status = WEXITSTATUS(status);
				printf(" dev id %d exit %d\n", devpid[i], status);
				UnionSemPost();
				break;
			}
		}
	}
	if (mutex) sem_destroy(mutex);
	return flag;
}
