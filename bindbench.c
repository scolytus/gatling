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
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>

int main(int argc,char* argv[]) {
  unsigned long count=1000;
  char ip[16];
  uint16 port=0;
  uint32 scope_id=0;
  int s;
  int v6;

  v6=0;

  {
    struct rlimit rl;
    rl.rlim_cur=RLIM_INFINITY; rl.rlim_max=RLIM_INFINITY;
    setrlimit(RLIMIT_NOFILE,&rl);
    setrlimit(RLIMIT_NPROC,&rl);
  }

  for (;;) {
    int i;
    int c=getopt(argc,argv,"h6c:");
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
    case '6':
      v6=1;
      break;
    case '?':
usage:
      buffer_putsflush(buffer_2,
		  "usage: bindbench [-h] [-6] [-c count]\n"
		  "\n"
		  "\t-h\tprint this help\n"
		  "\t-c n\tbind n sockets to port 0 (default: 1000)\n"
		  "\t-6\tbind IPv6 sockets instead of IPV4\n");
      return 0;
    }
  }


  {
    int i;
    unsigned long d;
    char ip[16];
    int port;
    struct timeval a,b,c;
    int *socks=alloca(count*sizeof(int));
    port=0; byte_zero(ip,16);
    for (i=0; i<count; ++i) {
      gettimeofday(&a,0);
      socks[i]=v6?socket_tcp6():socket_tcp4();
      gettimeofday(&b,0);
      if (v6)
	socket_bind6(socks[i],ip,port,0);
      else
	socket_bind4(socks[i],ip,port);
      gettimeofday(&c,0);
      d=(b.tv_sec-a.tv_sec)*10000000;
      d=d+b.tv_usec-a.tv_usec;
      buffer_putulong(buffer_1,d);
      buffer_putspace(buffer_1);
      d=(c.tv_sec-b.tv_sec)*10000000;
      d=d+c.tv_usec-b.tv_usec;
      buffer_putulong(buffer_1,d);
      buffer_puts(buffer_1,"\n");
    }
  }

  buffer_flush(buffer_1);
  return 0;
}
