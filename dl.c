#include "socket.h"
#include "byte.h"
#include "dns.h"
#include "buffer.h"
#include "scan.h"
#include "ip6.h"
#include "str.h"
#include "fmt.h"
#include "ip4.h"
#include "io.h"
#include "textcode.h"
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <utime.h>

static void carp(const char* routine) {
  buffer_puts(buffer_2,"httpbench: ");
  buffer_puts(buffer_2,routine);
  buffer_puts(buffer_2,": ");
  buffer_puterror(buffer_2);
  buffer_putnlflush(buffer_2);
}

static void panic(const char* routine) {
  carp(routine);
  exit(111);
}

static int make_connection(char* ip,uint16 port,uint32 scope_id) {
  int v6=byte_diff(ip,12,V4mappedprefix);
  int s;
  if (v6) {
    s=socket_tcp6();
    if (socket_connect6(s,ip,port,scope_id)==-1) {
      carp("socket_connect6");
      close(s);
      return -1;
    }
  } else {
    s=socket_tcp4();
    if (socket_connect4(s,ip+12,port)==-1) {
      carp("socket_connect4");
      close(s);
      return -1;
    }
  }
  return s;
}

struct utimbuf u;

static int readanswer(int s,int d) {
  char buf[8192];
  int i,j,body=-1,r;
  unsigned long long rest;
  i=0;
  while ((r=read(s,buf+i,sizeof(buf)-i)) > 0) {
    i+=r;
    for (j=0; j+3<i; ++j) {
      if (buf[j]=='\r' && buf[j+1]=='\n' && buf[j+2]=='\r' && buf[j+3]=='\n') {
	body=j+4;
	if (write(d,buf+body,r-j-4)!=r-j-4) panic("write");
	break;
      }
    }
    if (body!=-1) {
      if (byte_diff(buf,7,"HTTP/1.")) {
	buffer_putsflush(buffer_2,"invalid HTTP response!\n");
	return -1;
      }
      break;
    }
  }
  if (r==-1) return -1;
  rest=-1;
  for (j=0; j<r; j+=str_chr(buf+j,'\n')) {
    if (byte_equal(buf+j,17,"\nContent-Length: ")) {
      char* c=buf+j+17;
      if (c[scan_ulonglong(c,&rest)]!='\r') {
	buffer_putsflush(buffer_2,"invalid Content-Length header!\n");
	return -1;
      }
    } else if (byte_equal(buf+j,16,"\nLast-Modified: ")) {
      char* c=buf+j+16;
      if (c[scan_httpdate(c,&u.actime)]!='\r') {
	buffer_putsflush(buffer_2,"invalid Last-Modified header!\n");
	return -1;
      }
    }
    ++j;
  }
  rest-=(r-body);
  while (rest) {
    r=read(s,buf,rest>sizeof(buf)?sizeof(buf):rest);
    if (r<1) {
      if (r==-1)
	carp("read from HTTP socket");
      else {
	buffer_puts(buffer_2,"early HTTP EOF; expected ");
	buffer_putulong(buffer_2,rest);
	buffer_putsflush(buffer_2,"more bytes!\n");
	return -1;
      }
    } else {
      if (write(d,buf,r)!=r)
	panic("write");
      rest-=r;
    }
  }
  return 0;
}

int main(int argc,char* argv[]) {
  unsigned long count=1000;
  unsigned long interval=10;
  unsigned long sample=5;
  int keepalive=0;
  char ip[16];
  uint16 port=80;
  uint32 scope_id=0;
  stralloc ips={0};
  int s;
  char* request;
  int rlen;
  char* filename;
  int64 d;

  signal(SIGPIPE,SIG_IGN);

  {
    struct rlimit rl;
    rl.rlim_cur=RLIM_INFINITY; rl.rlim_max=RLIM_INFINITY;
    setrlimit(RLIMIT_NOFILE,&rl);
    setrlimit(RLIMIT_NPROC,&rl);
  }

  for (;;) {
    int i;
    int c=getopt(argc,argv,"c:i:s:k");
    if (c==-1) break;
    switch (c) {
    case 'k':
      keepalive=1;
      break;
    case 'i':
      i=scan_ulong(optarg,&interval);
      if (i==0 || optarg[i]) {
	buffer_puts(buffer_2,"httpbench: warning: could not parse interval: ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,"\n");
      }
      break;
    case 'c':
      i=scan_ulong(optarg,&count);
      if (i==0 || optarg[i]) {
	buffer_puts(buffer_2,"httpbench: warning: could not parse count: ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,"\n");
      }
      break;
    case 's':
      i=scan_ulong(optarg,&sample);
      if (i==0 || optarg[i]) {
	buffer_puts(buffer_2,"httpbench: warning: could not parse sample size: ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,"\n");
      }
      break;
    case '?':
usage:
      buffer_putsflush(buffer_2,"usage: dl url\n");
      return 0;
    }
  }

  if (!argv[optind]) goto usage;
  if (byte_diff(argv[optind],7,"http://")) goto usage;
  {
    char* host=argv[optind]+7;
    int colon=str_chr(host,':');
    int slash=str_chr(host,'/');
    char* c;
    if (host[0]=='[') {	/* ipv6 IP notation */
      int tmp;
      ++host;
      --colon; --slash;
      tmp=str_chr(host,']');
      if (host[tmp]==']') host[tmp]=0;
      if (host[tmp+1]==':') colon=tmp+1;
      if (colon<tmp+1) colon=tmp+1+str_len(host+tmp+1);
    }
    if (colon<slash) {
      host[colon]=0;
      c=host+colon+1;
      if (c[scan_ushort(c,&port)]!='/') goto usage;
      *c=0;
    }
    host[colon]=0;
    c=host+slash;
    *c=0;
    {
      char* tmp=alloca(str_len(host)+1);
      tmp[fmt_str(tmp,host)]=0;
      host=tmp;
    }
    *c='/';
    {
      int tmp=str_chr(host,'%');
      if (host[tmp]) {
	host[tmp]=0;
	scope_id=socket_getifidx(host+tmp+1);
	if (scope_id==0) {
	  buffer_puts(buffer_2,"httpbench: warning: network interface ");
	  buffer_puts(buffer_2,host+tmp+1);
	  buffer_putsflush(buffer_2," not found.\n");
	}
      }
    }

    {
      stralloc a={0};
      stralloc_copys(&a,host);
      if (dns_ip6(&ips,&a)==-1) {
	buffer_puts(buffer_2,"httpbench: could not resolve IP: ");
	buffer_puts(buffer_2,host);
	buffer_putnlflush(buffer_2);
	return 1;
      }
    }

    request=malloc(300+str_len(host)+3*str_len(c));
    if (!request) panic("malloc");
    {
      int i;
      i=fmt_str(request,"GET ");
      i+=fmt_urlencoded(request+i,c,str_len(c));
      i+=fmt_str(request+i," HTTP/1.0\r\nHost: ");
      i+=fmt_str(request+i,host);
      i+=fmt_str(request+i,":");
      i+=fmt_ulong(request+i,port);
      i+=fmt_str(request+i,"\r\nUser-Agent: httpbench/1.0\r\nConnection: ");
      i+=fmt_str(request+i,keepalive?"keep-alive":"close");
      i+=fmt_str(request+i,"\r\n\r\n");
      rlen=i; request[rlen]=0;
    }
    filename=c+str_rchr(c,'/')+1;

  }

  {
    int i;
    if (io_createfile(&d,filename)==0)
      panic("creat");
    s=-1;
    for (i=0; i+16<=ips.len; i+=16) {
      char buf[IP6_FMT];
      int v6=byte_diff(ips.s+i,12,V4mappedprefix);
      buffer_puts(buffer_1,"connecting to ");
      buffer_put(buffer_1,buf,
		 v6?
		 fmt_ip6(buf,ips.s+i):
		 fmt_ip4(buf,ips.s+i+12));
      buffer_puts(buffer_1," port ");
      buffer_putulong(buffer_1,port);
      buffer_putnlflush(buffer_1);
      s=make_connection(ips.s+i,port,scope_id);
      if (s!=-1) {
	byte_copy(ip,16,ips.s+i);
	break;
      }
    }
    if (s==-1)
      return 1;
  }
  if (write(s,request,rlen)!=rlen) panic("write");
  if (readanswer(s,d)==-1) exit(1);
  close(s);
  close(d);
  if (u.actime) {
    u.modtime=u.actime;
    if (utime(filename,&u)==-1) panic("utime");
  }
  return 0;
}
