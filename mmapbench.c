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
  unsigned long count=25000;
  int64 fd;
  struct timeval a,b;
  unsigned long d;

  for (;;) {
    int i;
    int c=getopt(argc,argv,"hc:");
    if (c==-1) break;
    switch (c) {
    case 'c':
      i=scan_ulong(optarg,&count);
      if (i==0 || optarg[i]) {
	buffer_puts(buffer_2,"httpbench: warning: could not parse count: ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,"\n");
      }
      break;
    case '?':
usage:
      buffer_putsflush(buffer_2,
		  "usage: mmapbench [-h] [-c count] filename\n"
		  "\n"
		  "\t-h\tprint this help\n"
		  "\t-c n\tmmap n 4k pages (default: 25000)\n");
      return 0;
    }
  }

  if (!argv[optind]) goto usage;
  if (!io_readfile(&fd,argv[optind])) {
    buffer_puts(buffer_2,"could not open ");
    buffer_puts(buffer_2,argv[optind]);
    buffer_puts(buffer_2,": ");
    buffer_puterror(buffer_2);
    buffer_putnlflush(buffer_2);
    exit(1);
  }

  {
    unsigned long i;
    char **p=malloc(count*sizeof(char*));
    if (!p) {
      buffer_puts(buffer_2,"out of memory!\n");
      exit(1);
    }
    for (i=0; i<count; ++i) {
      gettimeofday(&a,0);
      p[i]=mmap(0,4096,PROT_READ,MAP_SHARED,fd,((off_t)i)*8192);
      if (p[i]==MAP_FAILED) {
	buffer_puts(buffer_2,"mmap failed: ");
	buffer_puterror(buffer_2);
	buffer_putnlflush(buffer_2);
      }
      gettimeofday(&b,0);
      d=(b.tv_sec-a.tv_sec)*10000000;
      d=d+b.tv_usec-a.tv_usec;
      buffer_putulong(buffer_1,d);
      buffer_puts(buffer_1,"\n");
    }
  }

  buffer_flush(buffer_1);
  return 0;
}
