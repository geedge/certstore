#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <linux/sockios.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <sys/types.h>
#include <pwd.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <ctype.h>
#include "rt_string.h"
#include "rt_common.h"

void do_system(const char *cmd)
{
    int xret = -1;

    if (likely(cmd)) {
	    xret = system(cmd);
	    if (likely(xret < 0)){
	        ;//rt_log_error(ERRNO_FATAL, "%s", strerror(errno));
	    }
    }
}

#define BUF_SIZE 1024
void rt_get_pname_by_pid(pid_t pid, char *task_name)
{
    char proc_pid_path[BUF_SIZE];
    char buf[BUF_SIZE];
    sprintf(proc_pid_path, "/proc/%d/status", pid);
    FILE* fp = fopen(proc_pid_path, "r");
    if(NULL != fp){
        if( fgets(buf, BUF_SIZE-1, fp)== NULL ){
            fclose(fp);
        }
        fclose(fp);
        sscanf(buf, "%*s %s", task_name);
    }
}

