/*
UNIX Daemon Server Programming Sample Program
Levent Karakas <levent at mektup dot at> May 2001

To compile:	cc -o exampled examped.c
To run:		./exampled
To test daemon:	ps -ef|grep exampled (or ps -aux on BSD systems)
To test log:	tail -f /tmp/exampled.log
To test signal:	kill -HUP `cat /tmp/exampled.lock`
To terminate:	kill `cat /tmp/exampled.lock`
*/

#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h> // for umask 
#include <sys/stat.h>


#define RUNNING_DIR	"/tmp"

//////////////////////////////////////////
// signal handler HUP and TERM
//////////////////////////////////////////
void signal_handler(int sig)
{
		switch(sig) 
		{
			case SIGHUP:
				break;

			case SIGTERM:
				exit(0);
				break;
		}
}

/////////////////////////////////////////
// Daemonize the program
/////////////////////////////////////////
void daemonize()
{
		int i;

		//////////////////////////////////////////
		// If already a daemon, nothing more to do
		if(getppid()==1) 
				return; 


		//////////////////////////////////////////
		// Have the parent exit and continue rest as child
		i=fork();
		if (i<0) exit(1); /* fork error */
		if (i>0) exit(0); /* parent exits */


		//////////////////////////////////////////
		// child (daemon) continues 
		setsid(); /* obtain a new process group */


		fclose(stdin);fclose(stdout);fclose(stderr);
		i=open("/dev/null",O_RDWR); dup(i); dup(i); /* handle standart I/O */

		umask(027); /* set newly created file permissions */
		chdir(RUNNING_DIR); /* change running directory */

		/////////////////////////////////////////
		// Manipulate signals 
		// signal(SIGCHLD,SIG_IGN); /* ignore child */
		signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
		signal(SIGTTOU,SIG_IGN);
		signal(SIGTTIN,SIG_IGN);

		signal(SIGCHLD, SIG_IGN); // Added newly to prevent fork+exec creating <defunct> zombies 

		signal(SIGHUP,signal_handler); /* catch hangup signal */
		signal(SIGTERM,signal_handler); /* catch kill signal */
}

