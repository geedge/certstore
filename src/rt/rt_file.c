#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

#include "rt_common.h"

int rt_file_exsit(const char *realpath_file)
{
    return (!access(realpath_file, F_OK));
}

int rt_dir_exsit (const char *realpath)
{
    DIR *dir = NULL;
    int exsit = 0;

    if (unlikely (!realpath))
		goto finish;

    dir = opendir(realpath);
    if (!dir) goto finish;

    exsit = 1;
    closedir(dir);
finish:
    return exsit;
}

