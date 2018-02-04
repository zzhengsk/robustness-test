#include <iostream>
#include <unistd.h>
#include <ctime>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstring>

using namespace std;

#define STUDENTUID 7008105       // ********* csif uid **********//
//#define UID 1003

#define WRONG_OWN 1         // ownership not match
#define WRONG_PMS 2         // not correct permission
#define FILE_NOT_EXIST 3    // file not exist
#define EXE_FAIL 4          // execve fail
#define SYSCALL_FAIL 5      // syscall fail
#define BAD_TIME 6          // bad time stamp

char *envp[] = { (char*)"PATH=/bin:/user/bin",
                 (char*)"IFS=' \t\n'",
                 (char*)"SHELL=/bin/tcsh",
                 NULL};

int main(int argc, char** argv)
{
    // check if uid is match or not  
    if(getuid() != STUDENTUID)
    {
        cerr<<"ID doesn't match"<<endl; exit(WRONG_OWN);
    }
    
    // prompt the user for password
    int chPid, status;    // child Pid, and child exit status
    chPid = fork();
    if(chPid == -1)
    {
        cerr<<"Fork Fail"<<endl; exit(SYSCALL_FAIL);
    }
    else if(chPid == 0)
    {
        char *kinitargv[] = {(char*)"/usr/bin/kinit", NULL};
        if(execve(kinitargv[0], kinitargv, envp) == -1)
            exit(EXE_FAIL);    // execve fail
    }
    else
    {
        // check for all possible situations
        // first, check if the waitpid succeed or not
        if(waitpid(chPid, &status, 0) < 0)
        {
            cerr<<"Waitpid Fail"<<endl; exit(SYSCALL_FAIL);
        }
        // then check the child exit status
        if(WEXITSTATUS(status) == EXE_FAIL)
        {
            cerr<<"execve kinit(1) Fail"<<endl; exit(EXE_FAIL);
        }
        else if(WEXITSTATUS(status) == 0)
            cout<<"Access OK"<<endl;
        else
        {
            cerr<<"Access Denied"<<endl; exit(-1);
        }
    }

    // check the current directory has sniff or not
    struct stat st;
    if(stat("./sniff", &st) == -1)
    {
        cerr<<"current directory doesn't contain sniff"<<endl; exit(FILE_NOT_EXIST);
    }
    
    // check sniff is file or not
    if(!S_ISREG(st.st_mode))  
    {     
        cerr<<"sniff is not a file"<<endl; exit(FILE_NOT_EXIST);
    }
    
    // check ownership of sniff is match or not
    if(st.st_uid != STUDENTUID) 
    {
        cerr<<"ownership of sniff does not match"<<endl; exit(WRONG_OWN);
    }
    // check permission of sniff
    if(!(st.st_mode & S_IXUSR))
    {
        cerr<<"sniff can't be executed by the owner"<<endl; exit(WRONG_PMS);
    }
    if((st.st_mode & S_IRWXG) || (st.st_mode & S_IRWXO))
    {
        cerr<<"other users have permissions on sniff"<<endl; exit(WRONG_PMS);
    }
    
    // check the time stamp
    time_t cTime = st.st_ctim.tv_sec;      // changed time
    time_t mTime = st.st_mtim.tv_sec;      // modified time
    time_t currentTime = time(0);
    
    if(cTime < 0 || mTime < 0)
    {
        cerr<<"time stamp of snill has problems"<<endl; exit(BAD_TIME);
    }
    
    if( ((currentTime - cTime) > 60) || ((currentTime - mTime) > 60) )
    {
        cerr<<"sniff was created or modified over 1 minute ago"<<endl; exit(BAD_TIME);
    }
    
    // change ownership
    chPid = fork();
    if(chPid == -1)
    {
        cerr<<"Fork Fail"<<endl; exit(SYSCALL_FAIL);
    }
    else if(chPid == 0)
    {
        char *chownargv[] = {(char*)"/usr/bin/chown", (char*)"root:proj", (char*)"sniff", NULL};
        if(execve(chownargv[0], chownargv, envp) == -1)
            exit(EXE_FAIL);    // execve fail
    }
    else
    {
        // check for all possible situations
        if(waitpid(chPid, &status, 0) < 0)
        {
            cerr<<"Waitpid Fail"<<endl; exit(SYSCALL_FAIL);
        }
        // then check the child exit status
        if(WEXITSTATUS(status) == EXE_FAIL)
        {
            cerr<<"execve chown(1) Fail"<<endl; exit(EXE_FAIL);
        }
        else if(WEXITSTATUS(status) == 0)
            cout<<"successfully change ownership"<<endl;
        else
        {
            cerr<<"fail to change the ownership"<<endl; 
            exit(SYSCALL_FAIL); // it should exit,right?? 
        }
    }
    // change the permission 
    if( chmod("./sniff", 04550) == -1)
    {
        cerr<<"fail to change the permission"<<endl; exit(SYSCALL_FAIL);
    }
       
    return 0;
}

