#include "socket.h"
#include "byte.h"
#include "dns.h"
#include "buffer.h"
#include "scan.h"
#include "ip6.h"
#include "str.h"
#include "fmt.h"
#include "ip4.h"
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>

int main(int argc,char* argv[]) {
  unsigned long count=1000;
  int64 fd;
  struct timeval a,b;
  unsigned long d;

  {
    struct rlimit rl;
    rl.rlim_cur=RLIM_INFINITY; rl.rlim_max=RLIM_INFINITY;
    setrlimit(RLIMIT_NPROC,&rl);
  }

  for (;;) {
    int i;
    int c=getopt(argc,argv,"hc:");
    if (c==-1) break;
    switch (c) {
    case 'c':
      i=scan_ulong(optarg,&count);
      if (i==0 || optarg[i]) {
	buffer_puts(buffer_2,"forkbench: warning: could not parse count: ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,"\n");
      }
      break;
    case 'h':
usage:
      buffer_putsflush(buffer_2,
		  "usage: forkbench [-h] [-c count] filename\n"
		  "\n"
		  "\t-h\tprint this help\n"
		  "\t-c n\tfork off n children (default: 1000)\n");
      return 0;
    }
  }

  {
    unsigned long i,j;
    int pfd[2];
    char buf[100];
    pid_t *p=malloc(count*sizeof(char*));
    if (!p) {
      buffer_puts(buffer_2,"out of memory!\n");
      exit(1);
    }
    if (pipe(pfd)==-1) {
      buffer_puts(buffer_2,"pipe failed: ");
      buffer_puterror(buffer_2);
      buffer_putnlflush(buffer_2);
    }
    for (i=0; i<count; ++i) {
      gettimeofday(&a,0);
      switch (p[i]=fork()) {
      case -1:
	buffer_puts(buffer_2,"fork failed: ");
	buffer_puterror(buffer_2);
	buffer_putnlflush(buffer_2);
	for (j=0; j<i; ++j) kill(p[j],SIGTERM);
	_exit(1);
      case 0: /* child */
	{
	  sigset_t ss;
	  siginfo_t si;
	  sigemptyset(&ss);
	  sigaddset(&ss,SIGTERM);
	  write(pfd[1],".",1);
	  close(pfd[1]);
	  sigwaitinfo(&ss,&si);
	  _exit(0);
	}
      }
      if (read(pfd[0],buf,1)!=1) {
	buffer_putsflush(buffer_2,"child did not write into pipe?!\n");
	for (j=0; j<i; ++j) kill(p[j],SIGTERM);
	_exit(1);
      }
      gettimeofday(&b,0);
      d=(b.tv_sec-a.tv_sec)*10000000;
      d=d+b.tv_usec-a.tv_usec;
      buffer_putulong(buffer_1,d);
      buffer_puts(buffer_1,"\n");
    }
    buffer_flush(buffer_1);
    buffer_putsflush(buffer_2,"killing children\n");
    for (i=0; i<count; ++i)
      kill(p[i],SIGTERM);
  }

  return 0;
}
