#define _FILE_OFFSET_BITS 64
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
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <utime.h>
#ifdef __MINGW32__
#include <windows.h>
#include <fcntl.h>
#else
#include <sys/resource.h>
#include <sys/uio.h>
#endif
#include <sys/stat.h>
#include <errno.h>
#include "havealloca.h"

char* todel;

void alarm_handler(int dummy) {
  (void)dummy;
  if (todel) unlink(todel);
  exit(0);
}

static void carp(const char* routine) {
  buffer_puts(buffer_2,"dl: ");
  buffer_puts(buffer_2,routine);
  if (routine[0] && routine[str_len(routine)-1]!='\n') {
    buffer_puts(buffer_2,": ");
    buffer_puterror(buffer_2);
    buffer_putnlflush(buffer_2);
  } else
    buffer_flush(buffer_2);
}

static void panic(const char* routine) {
  carp(routine);
  exit(111);
}

static int make_connection(char* ip,uint16 port,uint32 scope_id) {
  int v6=byte_diff(ip,12,V4mappedprefix);
  int s;
  if (v6) {
    s=socket_tcp6b();
    if (socket_connect6(s,ip,port,scope_id)==-1) {
      carp("socket_connect6");
      close(s);
      return -1;
    }
  } else {
    s=socket_tcp4b();
    if (socket_connect4(s,ip+12,port)==-1) {
      carp("socket_connect4");
      close(s);
      return -1;
    }
  }
  return s;
}

struct utimbuf u;
unsigned long long resumeofs;

char* location;

static int readanswer(int s,const char* filename) {
  char buf[8192];
  int i,j,body=-1,r;
  int64 d;
  unsigned long httpcode;
  unsigned long long rest;
  int nocl;
  i=0; d=-1; httpcode=0; todel=(char*)filename;
  while ((r=read(s,buf+i,sizeof(buf)-i)) > 0) {
    i+=r;
    for (j=0; j+3<i; ++j) {
      if (buf[j]=='\r' && buf[j+1]=='\n' && buf[j+2]=='\r' && buf[j+3]=='\n') {
	unsigned long code;
	body=j+4;
	if (scan_ulong(buf+9,&code)) httpcode=code;
	if ((resumeofs && code==206 && io_appendfile(&d,filename)==0) ||
	    (!resumeofs && code==200 && ((strcmp(filename,"-"))?io_createfile(&d,filename)==0:((d=1)-1))))
	  panic("creat");
	if (d==-1) {
	  if (httpcode==301 || httpcode==302 || httpcode==303) {
	    char* l;
	    buf[r]=0;
	    if ((l=strstr(buf,"\nLocation:"))) {
	      l+=10;
	      while (*l == ' ' || *l == '\t') ++l;
	      location=l;
	      while (*l && *l != '\r' && *l != '\n') ++l;
	      *l=0;
	      return -2;
	    }
	    return -1;
	  }
	  for (j=0; buf[j]!='\n'; ++j) ;
	  write(2,buf,j+1);
	  return 0;
	}
	if (r-j-4)
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
  if (httpcode!= (resumeofs?206:200)) return 0;
  rest=-1; nocl=1;
  buf[r]=0;
  for (j=0; j<r; j+=str_chr(buf+j,'\n')) {
    if (j+17<r && byte_equal(buf+j,17,"\nContent-Length: ")) {
      char* c=buf+j+17;
      if (c[scan_ulonglong(c,&rest)]!='\r') {
	buffer_putsflush(buffer_2,"invalid Content-Length header!\n");
	return -1;
      }
      nocl=0;
    } else if (j+16<r && byte_equal(buf+j,16,"\nLast-Modified: ")) {
      char* c=buf+j+16;
      if (c[scan_httpdate(c,&u.actime)]!='\r') {
	buffer_putsflush(buffer_2,"invalid Last-Modified header!\n");
	return -1;
      }
    }
    ++j;
  }
  rest-=(r-body);
  while (nocl || rest) {
    r=read(s,buf,nocl?sizeof(buf):(rest>sizeof(buf)?sizeof(buf):rest));
    if (r<1) {
      if (r==-1)
	carp("read from HTTP socket");
      else {
	if (nocl) break;
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
  close(d);
  chmod(filename,0644);
  return 0;
}

static stralloc ftpresponse;

static int readftpresponse(buffer* b) {
  char c;
  int i,res,cont=0,num;
  if (!stralloc_copys(&ftpresponse,"")) panic("malloc");
  for (i=res=0; i<3; ++i) {
    if (buffer_getc(b,&c)!=1) panic("ftp command response read error");
    if (c<'0' || c>'9') panic("invalid ftp command response\n");
    res=res*10+c-'0';
  }
  num=3;
  for (i=3; ; ++i) {
    if (buffer_getc(b,&c)!=1) panic("ftp command response read error");
    if (!stralloc_append(&ftpresponse,&c)) panic("malloc");
    if (i==0) {
      cont=0; num=0;
      if (c==' ' || c=='\t') cont=1;
    }
    if (i<3 && c>='0' && c<='9') ++num;
    if (i==3 && num==3) cont=(c=='-');
    if (c=='\n') {
      if (cont) i=-1; else break;
    }
  }
  return res;
}

static int ftpcmd(int s,buffer* b,const char* cmd) {
  int l=str_len(cmd);
  if (write(s,cmd,l)!=l) panic("ftp command write error");
  return readftpresponse(b);
}

static int ftpcmd2(int s,buffer* b,const char* cmd,const char* param) {
  int l=str_len(cmd);
  int l2=str_len(param);
#ifdef __MINGW32__
  char* buf=alloca(l+l2+3);
  memcpy(buf,cmd,l);
  memcpy(buf+l,param,l2);
  memcpy(buf+l+l2,"\r\n",2);
  if (write(s,buf,l+l2+2)!=l+l2+2) panic("ftp command write error");
#else
  struct iovec v[3];
  v[0].iov_base=(char*)cmd;	v[0].iov_len=l;
  v[1].iov_base=(char*)param;	v[1].iov_len=l2;
  v[2].iov_base="\r\n";		v[2].iov_len=2;
  if (writev(s,v,3)!=l+l2+2) panic("ftp command write error");
#endif
  return readftpresponse(b);
}

static int scan_int2digit(const char* s, int* i) {
  if (s[0]<'0' || s[0]>'9' || s[1]<'0' || s[1]>'9') return 0;
  *i=(s[0]-'0')*10 + s[1]-'0';
  return 2;
}

static inline int issafe(unsigned char c) {
  return (c!='"' && c>=' ' && c!='+');
}

size_t fmt_urlencoded(char* dest,const char* src,size_t len) {
  register const unsigned char* s=(const unsigned char*) src;
  unsigned long written=0,i;
  for (i=0; i<len; ++i) {
    if (!issafe(s[i])) {
      if (dest) {
	dest[written]='%';
	dest[written+1]=fmt_tohex(s[i]>>4);
	dest[written+2]=fmt_tohex(s[i]&15);
      }
      written+=3;
    } else {
      if (dest) dest[written]=s[i]; ++written;
    }
  }
  return written;
}

int main(int argc,char* argv[]) {
  time_t ims=0;
  int useport=0;
  int usev4=0;
  int verbose=0;
  int newer=0;
  int resume=0;
  int keepalive=0;
  int imode=0;
  char ip[16];
  uint16 port=80;
  uint32 scope_id=0;
  stralloc ips={0};
  int s;
  char* request=0;
  int rlen=0;
  char* filename=0;
  char* pathname=0;
  char* output=0;
  char* useragent="dl/1.0";
  char* referer=0;
  enum {HTTP, FTP} mode;
  int skip;
  buffer ftpbuf;

#ifndef __MINGW32__
  signal(SIGPIPE,SIG_IGN);
#endif

  for (;;) {
    int c=getopt(argc,argv,"i:ko4nvra:O:U:R:");
    if (c==-1) break;
    switch (c) {
    case 'k':
      keepalive=1;
      break;
    case 'n':
      newer=1;
      break;
    case 'i':
      {
	struct stat ss;
	if (stat(optarg,&ss)==0) {
	  ims=ss.st_mtime;
	  imode=1;
	}
      }
      break;
    case 'r':
      resume=1;
      break;
    case 'o':
      useport=1;
      break;
    case '4':
      usev4=1;
      break;
    case 'v':
      verbose=1;
      break;
    case 'O':
      output=optarg;
      break;
    case 'U':
      useragent=optarg;
      break;
    case 'R':
      referer=optarg;
      break;
    case 'a':
#ifndef __MINGW32__
      {
	unsigned long n;
	signal(SIGALRM,alarm_handler);
	if (optarg[scan_ulong(optarg,&n)]==0)
	  alarm(n);
	break;
      }
#endif
    case '?':
usage:
      buffer_putsflush(buffer_2,"usage: dl [-i file] [-no4v] url\n"
		       "	-i fn	only fetch file if it is newer than fn\n"
		       "	-n	only fetch file if it is newer than local copy\n"
		       "	-r	resume\n"
		       "	-4	use PORT and PASV instead of EPRT and EPSV, only connect using IPv4\n"
		       "	-o	use PORT and EPRT instead of PASV and EPSV\n"
		       "	-a n	abort after n seconds\n"
		       "	-O fn	write output to fn\n"
		       "	-U s	set User-Agent HTTP header\n"
		       "	-R s	set Referer HTTP header\n"
		       "	-v	be verbose\n");
      return 0;
    }
  }
#ifdef __MINGW32__
  _fmode=O_BINARY;
#endif

  if (!argv[optind]) goto usage;
again:
  {
    static int redirects=0;
    if (++redirects>5) panic("too many redirects!\n");
  }
  mode=HTTP;
  if (byte_diff(argv[optind],skip=7,"http://")) {
    if (byte_diff(argv[optind],skip=6,"ftp://")) goto usage;
    mode=FTP;
    port=21;
  }
  {
    char* host=argv[optind]+skip;
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
    pathname=c;
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
	  buffer_puts(buffer_2,"dl: warning: network interface ");
	  buffer_puts(buffer_2,host+tmp+1);
	  buffer_putsflush(buffer_2," not found.\n");
	}
      }
    }

    {
      stralloc a={0};
      stralloc_copys(&a,host);
      if (verbose) buffer_putsflush(buffer_1,"DNS lookup... ");
      if (dns_ip6(&ips,&a)==-1 || ips.len==0) {
	buffer_puts(buffer_2,"dl: could not resolve IP: ");
	buffer_puts(buffer_2,host);
	buffer_putnlflush(buffer_2);
	return 1;
      }
      if (verbose) buffer_putsflush(buffer_1,"done\n");
    }

    if (output)
      filename=output;
    else
      filename=c+str_rchr(c,'/')+1;
    if (resume || newer) {
      struct stat ss;
      if (stat(filename,&ss)==0) {
	if (resume) {
	  resumeofs=ss.st_size;
	  if (verbose) {
	    buffer_puts(buffer_1,"Resuming from ");
	    buffer_putulonglong(buffer_1,resumeofs);
	    buffer_putsflush(buffer_1,"...\n");
	  }
	} else if (newer) {
	  if (verbose) buffer_putsflush(buffer_1,"Found old file as If-Modified-Since reference.\n");
	  ims=ss.st_mtime;
	}
      } else
	resume=0;
    }

    if (mode==HTTP) {
      request=malloc(300+str_len(host)+3*str_len(c)+str_len(useragent)+(referer?str_len(referer)+20:0));
      if (!request) panic("malloc");
      {
	int i;
	i=fmt_str(request,"GET ");
	i+=fmt_urlencoded(request+i,c,str_len(c));
	i+=fmt_str(request+i," HTTP/1.0\r\nHost: ");
	i+=fmt_str(request+i,host);
	i+=fmt_str(request+i,":");
	i+=fmt_ulong(request+i,port);
	if (ims) {
	  i+=fmt_str(request+i,"\r\nIf-Modified-Since: ");
	  i+=fmt_httpdate(request+i,ims);
	}
	if (resumeofs) {
	  i+=fmt_str(request+i,"\r\nRange: bytes=");
	  i+=fmt_ulonglong(request+i,resumeofs);
	  i+=fmt_str(request+i,"-");
	}
	i+=fmt_str(request+i,"\r\nUser-Agent: ");
	i+=fmt_str(request+i,useragent);
	if (referer) {
	  i+=fmt_str(request+i,"\r\nReferer: ");
	  i+=fmt_str(request+i,referer);
	}
	i+=fmt_str(request+i,"\r\nConnection: ");
	i+=fmt_str(request+i,keepalive?"keep-alive":"close");
	i+=fmt_str(request+i,"\r\n\r\n");
	rlen=i; request[rlen]=0;
      }
    }
  }

  {
    int i;
    s=-1;
    for (i=0; i+16<=ips.len; i+=16) {
      if (usev4 && !ip6_isv4mapped(ips.s+i)) continue;
      if (verbose) {
	char buf[IP6_FMT];
	buffer_puts(buffer_1,"connecting to ");
	buffer_put(buffer_1,buf,fmt_ip6c(buf,ips.s+i));
	buffer_puts(buffer_1," port ");
	buffer_putulong(buffer_1,port);
	buffer_putnlflush(buffer_1);
      }
      s=make_connection(ips.s+i,port,scope_id);
      if (s!=-1) {
	byte_copy(ip,16,ips.s+i);
	break;
      }
    }
    if (s==-1)
      return 1;
  }
  if (mode==HTTP) {
    if (write(s,request,rlen)!=rlen) panic("write");
    switch (readanswer(s,filename)) {
    case -1: exit(1);
    case -2: argv[optind]=location; location=0;
	     if (verbose) {
	       buffer_puts(buffer_1,"redirected to ");
	       buffer_puts(buffer_1,location);
	       buffer_putsflush(buffer_1,"...\n");
	     }
	     goto again;
    }
  } else if (mode==FTP) {
    char buf[2048];
    int i;
    int dataconn;
    buffer_init(&ftpbuf,(void*)read,s,buf,sizeof buf);
    if (verbose) buffer_putsflush(buffer_1,"Waiting for FTP greeting...");
    if ((readftpresponse(&ftpbuf)/100)!=2) panic("no 2xx ftp greeting.\n");
    if (verbose) buffer_putsflush(buffer_1,"\nUSER ftp...");
    if ((i=(ftpcmd(s,&ftpbuf,"USER ftp\r\n")/100))>3) panic("ftp login failed.\n");
    if (verbose) buffer_putsflush(buffer_1,"\nPASS luser@...");
    if ((i=(ftpcmd(s,&ftpbuf,"PASS luser@\r\n")/100))!=2) panic("ftp login failed.\n");

    if (verbose) buffer_putsflush(buffer_1,"\nTYPE I");
    if ((i=(ftpcmd(s,&ftpbuf,"TYPE I\r\n")/100))!=2) panic("Switching to binary mode failed.\n");

    if (verbose) {
      buffer_puts(buffer_1,"\nMDTM ");
      buffer_puts(buffer_1,pathname);
      buffer_putsflush(buffer_1,"... ");
    }
    if (ftpcmd2(s,&ftpbuf,"MDTM ",pathname)==213) {
      char* c=ftpresponse.s+1;
      struct tm t;
      int ok=1;
      int i;
      if (ftpresponse.len>15) {
	if (c[0]=='1' && c[1]=='9' && c[15]>='0') {
	  /* y2k bug; "19100" instead of "2000" */
	  if (scan_int2digit(c+3,&i)!=2) ok=0;
	  t.tm_year=i;
	  ++c;
	} else {
	  if (scan_int2digit(c,&i)!=2) ok=0;
	  t.tm_year=i*100;
	  if (scan_int2digit(c+2,&i)!=2) ok=0;
	  t.tm_year+=i;
	  t.tm_year-=1900;
	}
	c+=4;
	if (scan_int2digit(c   ,&i)!=2) ok=0; t.tm_mon=i-1;
	if (scan_int2digit(c+2 ,&i)!=2) ok=0; t.tm_mday=i;
	if (scan_int2digit(c+4 ,&i)!=2) ok=0; t.tm_hour=i;
	if (scan_int2digit(c+6 ,&i)!=2) ok=0; t.tm_min=i;
	if (scan_int2digit(c+8 ,&i)!=2) ok=0; t.tm_sec=i;
	if (c[10]!='\r') ok=0;
	if (ok) {
	  time_t r=mktime(&t);
	  u.actime=r;
	  if (verbose) buffer_putsflush(buffer_1,"ok.\n");
	  if (ims && r<=ims) {
	    if (verbose) buffer_puts(buffer_1,"Remote file is not newer, skipping download.");
	    goto skipdownload;
	  }
	} else
	  if (verbose) buffer_putsflush(buffer_1,"could not parse MDTM response.\n");
      } else
	if (verbose) buffer_putsflush(buffer_1,"invalid response format.\n");
    } else
      if (verbose) buffer_putsflush(buffer_1,"failed.\n");

    if (resume) {
      char* buf=alloca(str_len(filename)+10);
      int i;
      i=fmt_str(buf,"REST ");
      i+=fmt_ulonglong(buf+i,resumeofs);
      i+=fmt_str(buf+i,"\r\n");
      buf[i]=0; ++i;
      if (verbose) {
	buffer_put(buffer_1,buf,i-3);
	buffer_putsflush(buffer_1,"... ");
      }
      if (ftpcmd(s,&ftpbuf,buf)!=350) {
	buffer_putsflush(buffer_1,verbose?"FAILED!\n":"Resume failed!\n");
	exit(1);
      }
    }

    if (useport) {
      uint16 port;
      char ip2[16];
      char ip3[16];
      char buf[200];
      if (usev4) {
	int i,j;
	int srv=socket_tcp4b();
	if (srv==-1) panic("socket");
	socket_listen(srv,1);
	if (socket_local4(s,ip2,0)) panic("getsockname");
	if (socket_local4(srv,0,&port)) panic("getsockname");
	i=fmt_str(buf,"PORT ");
	for (j=0; j<4; ++j) {
	  i+=fmt_uint(buf+i,ip2[j]&0xff);
	  i+=fmt_str(buf+i,",");
	}
	i+=fmt_uint(buf+i,port>>8);
	i+=fmt_str(buf+i,",");
	i+=fmt_uint(buf+i,port&0xff);
	i+=fmt_str(buf+i,"\r\n");
	buf[i]=0;
	if (verbose) buffer_putsflush(buffer_1,buf);
	if (ftpcmd(s,&ftpbuf,buf) != 200) panic("PORT reply is not 200\n");
	if (verbose) buffer_putsflush(buffer_1,"Waiting for connection...");
	dataconn=socket_accept4(srv,ip3,0);
	if (verbose) buffer_putsflush(buffer_1," there it is.\n");
	if (byte_diff(ip3,4,ip+12)) panic("PORT stealing attack!\n");
      } else {
	int i;
	int srv=socket_tcp6b();
	if (srv==-1) panic("socket");
	socket_listen(srv,1);
	if (socket_local6(s,ip2,0,0)) panic("getsockname");
	if (socket_local6(srv,0,&port,0)) panic("getsockname");
	i=fmt_str(buf,"EPRT |");
	if (byte_equal(ip2,12,V4mappedprefix))
	  i+=fmt_str(buf+i,"1|");
	else
	  i+=fmt_str(buf+i,"2|");
	i+=fmt_ip6c(buf+i,ip2);
	i+=fmt_str(buf+i,"|");
	i+=fmt_ulong(buf+i,port);
	i+=fmt_str(buf+i,"|\r\n");
	buf[i]=0;
	if (verbose) buffer_putsflush(buffer_1,buf);
	if (ftpcmd(s,&ftpbuf,buf) != 200) panic("EPRT reply is not 200\n");
	if (verbose) buffer_putsflush(buffer_1,"Waiting for connection...");
	dataconn=socket_accept6(srv,ip3,0,0);
	if (verbose) buffer_putsflush(buffer_1," there it is.\n");
	if (byte_diff(ip3,16,ip)) panic("EPRT stealing attack!\n");
      }
    } else {
      int srv;
      if (usev4) {
	int i;
	if (verbose) buffer_putsflush(buffer_1,"PASV... ");
	if (ftpcmd(s,&ftpbuf,"PASV\r\n")!=227) panic("PASV reply is not 227\n");
	/* Passive Mode OK (127,0,0,1,204,228) */
	for (i=0; i<ftpresponse.len-1; ++i) {
	  if (ftpresponse.s[i]==',' && ftpresponse.s[i+1]>='0' && ftpresponse.s[i+1]<='9') {
	    unsigned long j;
	    if (scan_ulong(ftpresponse.s+i+1,&j) && j<256)
	      port=port*256+j;
	  }
	}
	if ((srv=socket_tcp4b())==-1) panic("socket");
	if (verbose) buffer_putsflush(buffer_1,"connecting... ");
	if (socket_connect4(srv,ip+12,port)==-1) panic("connect");
	if (verbose) buffer_putsflush(buffer_1,"done.\n");
	dataconn=srv;
      } else {
	if (verbose) buffer_putsflush(buffer_1,"EPSV... ");
	if (ftpcmd(s,&ftpbuf,"EPSV\r\n")!=229) panic("EPSV reply is not 229\n");
	/* Passive Mode OK (|||52470|) */
	for (i=0; i<ftpresponse.len-1; ++i) {
	  if (ftpresponse.s[i]>='0' && ftpresponse.s[i]<='9') {
	    unsigned long j;
	    if (scan_ulong(ftpresponse.s+i,&j) && j<65536) {
	      port=j;
	      break;
	    }
	  }
	}
	if ((srv=socket_tcp6b())==-1) panic("socket");
	if (verbose) buffer_putsflush(buffer_1,"connecting... ");
	if (socket_connect6(srv,ip,port,scope_id)==-1) panic("connect");
	if (verbose) buffer_putsflush(buffer_1,"done.\n");
	dataconn=srv;
      }
    }
    if (!filename[0]) {
      if (verbose) {
	buffer_puts(buffer_1,"CWD ");
	buffer_puts(buffer_1,pathname);
	buffer_putsflush(buffer_1,"... ");
      }
      if ((ftpcmd2(s,&ftpbuf,"CWD ",pathname)/100)!=2) panic("CWD failed\n");
      if (verbose) buffer_putsflush(buffer_2,"\nNLST\n");
      if (((i=ftpcmd(s,&ftpbuf,"NLST\r\n"))!=150) && i!=125) panic("No 125/150 response to NLST\n");
    } else {
      int i;
      if (verbose) {
	buffer_puts(buffer_1,"RETR ");
	buffer_puts(buffer_1,pathname);
	buffer_putsflush(buffer_1,"... ");
      }
      if (((i=ftpcmd2(s,&ftpbuf,"RETR ",pathname))!=150) && i!=125) panic("No 125/150 response to RETR\n");
      if (verbose) buffer_putsflush(buffer_1,"ok.  Downloading...\n");
    }
    {
      char buf[8192];
      unsigned int l;
      int64 d;
      if (filename[0]) {
	if ((resume?io_appendfile(&d,filename):io_createfile(&d,filename))==0)
	  panic("creat");
      } else d=1;
      while ((l=read(dataconn,buf,sizeof buf))>0) {
	if (d==1) {
	  unsigned int i,j;
	  for (i=j=0; i<l; ++i)
	    if (buf[i]!='\r') {
	      buf[j]=buf[i];
	      ++j;
	    }
	  l=j;
	}
	if (write(d,buf,l) != l) panic("short write");
      }
      if (l==-1) panic("read");
      if (d!=1) close(d);
    }
    close(dataconn);
    if (verbose) buffer_putsflush(buffer_1,"Download finished... Waiting for server to acknowledge... ");
    if ((readftpresponse(&ftpbuf)/100)!=2) panic("no 2xx ftp retr response.\n");
skipdownload:
    if (verbose) buffer_putsflush(buffer_1,"\nQUIT\n");
    ftpcmd(s,&ftpbuf,"QUIT\r\n");
  } else
    panic("invalid mode\n");
  close(s);
  if (filename[0] && u.actime) {
    u.modtime=u.actime;
    if (strcmp(filename,"-") && utime(filename,&u)==-1)
      if (errno!=ENOENT || !imode)
	panic("utime");
  }
  return 0;
}
