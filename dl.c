#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE
#include "socket.h"
#include "byte.h"
#include "buffer.h"
#include "scan.h"
#include "ip6.h"
#include "str.h"
#include "fmt.h"
#include "ip4.h"
#include "io.h"
#include "stralloc.h"
#include "textcode.h"
#include "uint64.h"
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "havealloca.h"
#include <assert.h>
#include <ctype.h>

int dostats;

char* todel;

void alarm_handler(int dummy) {
  (void)dummy;
  if (todel) unlink(todel);
  exit(1);
}

static void clearstats();

static void carp(const char* routine) {
  clearstats();
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

static unsigned long long int total;
static unsigned long long resumeofs;

static int statsprinted;

void printstats(unsigned long long nextchunk) {
  static unsigned long long int finished;
  static time_t start,now,prev;
  finished+=nextchunk;
  if (start==0) {
    start=now=prev=time(0);
    return;
  }
  prev=now; now=time(0);
  if (prev!=now) {
    char received[FMT_ULONG], totalsize[FMT_ULONG], timedone[FMT_ULONG], percent[10];
    char speed[FMT_ULONG+20];
    size_t i,j;
    if (total) {
      if (total>1000000000)
	i=finished/(total/10000);
      else
	i=finished*10000/total;
      j=fmt_ulong(percent,i/100);
      percent[j]='.';
      percent[j+1]=((i/10)%10)+'0';
      percent[j+2]=(i%10)+'0';
      percent[j+3]=0;
    } else
      strcpy(percent,"100.00");
    j=fmt_humank(received,resumeofs+finished);
    if (received[j-1]<='9') received[j++]='i';
    received[j]=0;
    j=fmt_humank(totalsize,resumeofs+total);
    if (totalsize[j-1]<='9') totalsize[j++]='i';
    totalsize[j]=0;

    if (now-start>=60) {
      j=fmt_ulong(timedone,(now-start)/60);
      timedone[j]=':';
      i=(now-start)%60;
      timedone[j+1]=(i/10)+'0';
      timedone[j+2]=(i%10)+'0';
      timedone[j+3]=0;
    } else {
      j=fmt_ulong(timedone,now-start);
      j+=fmt_str(timedone+j," sec");
      timedone[j]=0;
    }

    if (now-start>1 && total) {
      i=finished/(now-start);
      j=fmt_str(speed," (");
      j+=fmt_humank(speed+j,i);
      j+=fmt_str(speed+j,"iB/sec)"+(i>1000));
      speed[j]=0;
    } else
      speed[0]=0;

    if (now > start+3 && now-start) {
      unsigned long long int bps=finished/(now-start);
      size_t k=(total-finished)/bps;
      char lm[FMT_ULONG];

      if (k>=60) {
	j=fmt_ulong(lm,k/60);
	lm[j]=':';
	i=k%60;
	lm[j+1]=(i/10)+'0';
	lm[j+2]=(i%10)+'0';
	lm[j+3]=0;
      } else {
	j=fmt_ulong(lm,k);
	j+=fmt_str(lm+j," sec");
	lm[j]=0;
      }

      buffer_putm(buffer_2,"\r",percent,"% done; got ",received,"B ");
      if (total)
	buffer_putm(buffer_2,"of ",totalsize,"B ");
      buffer_putmflush(buffer_2,"in ",timedone,speed,", ",lm," to go.    ");
    } else {
      buffer_putm(buffer_2,"\r",percent,"% done; got ",received,"B ");
      if (total)
	buffer_putm(buffer_2,"of ",totalsize,"B ");
      buffer_putmflush(buffer_2,"in ",timedone,speed,".    ");
    }
    statsprinted=1;
  }
}

static void clearstats() {
  if (statsprinted) buffer_putsflush(buffer_2,"\r\e[K");
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

char* location;

static int readanswer(int s,const char* filename,int onlyprintlocation) {
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
	if (scan_ulong(buf+9,&code))
	  httpcode=code;
	else
	  goto kaputt;
	if (onlyprintlocation && (code/10 != 30)) return 0;
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
	      location=strndup(location,l-location);
	      return -2;
	    }
	    return -1;
	  }
	  for (j=0; buf[j]!='\n'; ++j) ;
	  write(2,buf,j+1);
	  return 0;
	}
	if (i-j-4)
	  if (write(d,buf+body,i-j-4)!=i-j-4) panic("write");
	break;
      }
    }
    if (body!=-1) {
      if (byte_diff(buf,7,"HTTP/1.")) {
kaputt:
	buffer_putsflush(buffer_2,"invalid HTTP response!\n");
	return -1;
      }
      break;
    }
  }
  if (r==-1) return -1;
  if (d==1) dostats=!isatty(1);
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
  total=rest;
  rest-=(r-body);
  printstats(total-rest);
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
      printstats(r);
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
  return (c!='"' && c>' ' && c!='+');
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

static int validatesmb(char* buf,size_t wanted,unsigned char type,unsigned char wordcount,
		unsigned short bytecount,unsigned short tid,unsigned short mid) {
  if (wanted<wordcount*2+0x23+bytecount) return -1;	// too short?
  if (!byte_equal(buf,4,"\xffSMB")) return -1;		// SMB magic?
  if ((unsigned char)buf[4]!=type) return -1;				// wrong message type?
  if (uint16_read(buf+12)!=0) return -1;		// process id high == 0?
  if (uint16_read(buf+24)!=tid) return -1;		// right tree id?
  if (uint16_read(buf+26)!=23) return -1;		// right process id?
  if (uint16_read(buf+30)!=mid) return -1;		// right multiplex id?
  if (buf[0x20]<wordcount) return -1;
  if (uint16_read(buf+0x20+wordcount*2)<bytecount) return -1;
  if (wanted<wordcount*2+0x22+uint16_read(buf+0x21+wordcount*2)) return -1;	// too short
  return 0;
}

static void readnetbios(buffer* b,char* buf,size_t* wanted) {
  if (buffer_get(b,buf,4)!=4) panic("short read\n");
  *wanted=(unsigned char)buf[1] * 65535 +
	  (unsigned char)buf[2] * 256 +
	  (unsigned char)buf[3];
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
  int onlyprintlocation=0;
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
  enum {HTTP, FTP, SMB} mode;
  int skip;
  buffer ftpbuf;
  char* host;

  dostats=isatty(2);

#ifndef __MINGW32__
  signal(SIGPIPE,SIG_IGN);
#endif

  for (;;) {
    int c=getopt(argc,argv,"i:ko4nvra:O:U:R:l");
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
    case 'l':
      onlyprintlocation=1;
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
		       "	-l	just print value of Location: header\n"
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
    if (byte_diff(argv[optind],skip=6,"ftp://")) {
      if (byte_diff(argv[optind],skip=6,"smb://")) goto usage;
      mode=SMB;
      port=445;
    } else {
      mode=FTP;
      port=21;
    }
  }
  {
    int colon;
    int slash;
    char* c;
    host=argv[optind]+skip;
    colon=str_chr(host,':');
    slash=str_chr(host,'/');
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
      struct addrinfo hints, *ai, *aitop;
      int gaierr;
      char p[FMT_ULONG];
      p[fmt_ulong(p,port)]=0;
      memset(&hints,0,sizeof(hints));
      hints.ai_family=AF_UNSPEC;
      hints.ai_flags=0;
      hints.ai_socktype=0;
      if (verbose) buffer_putsflush(buffer_1,"DNS lookup... ");
      if ((gaierr = getaddrinfo(host,p,&hints,&aitop)) != 0 || !aitop) {
	buffer_puts(buffer_2,"dl: could not resolve IP: ");
	buffer_puts(buffer_2,host);
	buffer_putnlflush(buffer_2);
	return 1;
      }
      ai=aitop;
      while (ai) {
	if (ai->ai_family==AF_INET6)
	  stralloc_catb(&ips,(char*)&(((struct sockaddr_in6*)ai->ai_addr)->sin6_addr),16);
	else {
	  stralloc_catb(&ips,V4mappedprefix,12);
	  stralloc_catb(&ips,(char*)&(((struct sockaddr_in*)ai->ai_addr)->sin_addr),4);
	}
	ai=ai->ai_next;
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
	if (onlyprintlocation)
	  i=fmt_str(request,"HEAD ");
	else
	  i=fmt_str(request,"GET ");
	i+=fmt_urlencoded(request+i,c,str_len(c));
	i+=fmt_str(request+i," HTTP/1.0\r\nHost: ");
	i+=fmt_str(request+i,host);
	if (port!=80) {
	  i+=fmt_str(request+i,":");
	  i+=fmt_ulong(request+i,port);
	}
	if (ims) {
	  i+=fmt_str(request+i,"\r\nIf-Modified-Since: ");
	  i+=fmt_httpdate(request+i,ims);
	}
	if (resumeofs) {
	  i+=fmt_str(request+i,"\r\nRange: bytes=");
	  i+=fmt_ulonglong(request+i,resumeofs);
	  i+=fmt_str(request+i,"-");
	}
	i+=fmt_str(request+i,"\r\nAccept: */*\r\nUser-Agent: ");
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
    switch (readanswer(s,filename,onlyprintlocation)) {
    case -1: exit(1);
    case -2: argv[optind]=location;
	     if (onlyprintlocation) {
	       buffer_puts(buffer_1,location);
	       buffer_putnlflush(buffer_1);
	       return 0;
	     }
	     if (verbose) {
	       buffer_puts(buffer_1,"redirected to ");
	       buffer_puts(buffer_1,location);
	       buffer_putsflush(buffer_1,"...\n");
	     }
	     location=0;
	     goto again;
    }

  } else if (mode==FTP) {

    char buf[2048];
    int i;
    int dataconn;
    buffer_init(&ftpbuf,(void*)read,s,buf,sizeof buf);
    if (verbose) buffer_putsflush(buffer_1,"Waiting for FTP greeting...");
    if ((readftpresponse(&ftpbuf)/100)!=2) panic("no 2xx ftp greeting.\n");
    if (verbose) buffer_putsflush(buffer_1,"\nUSER anonymous...");
    if ((i=(ftpcmd(s,&ftpbuf,"USER anonymous\r\n")/100))>3) panic("ftp login failed.\n");
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
      if (((i=ftpcmd2(s,&ftpbuf,"RETR ",pathname))!=150) && i!=125) {
	stralloc_0(&ftpresponse);
	buffer_puts(buffer_2,"dl: RETR failed:");
	buffer_putsaflush(buffer_2,&ftpresponse);
	return 1;
      }
      if (verbose) buffer_putsflush(buffer_1,"ok.  Downloading...\n");
      total=0;
      if (stralloc_0(&ftpresponse)) {
	char* c=strchr(ftpresponse.s,'(');
	if (c) {
	  ++c;
	  if (!scan_ulonglong(c,&total))
	    total=0;
	}
      }
    }
    {
      char buf[8192];
      unsigned int l;
      int64 d;
      if (filename[0]) {
	if ((resume?io_appendfile(&d,filename):io_createfile(&d,filename))==0)
	  panic("creat");
      } else {
	d=1;
	dostats=!isatty(1);
      }
      while ((l=read(dataconn,buf,sizeof buf))>0) {
	if (dostats) printstats(l);
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

  } else if (mode==SMB) {

    unsigned int mid=4;
    char inbuf[65*1024];
    char buf[8192];
    char* readbuf;
    char domain[200];
    size_t dlen;
    size_t wanted;
    unsigned short uid,tid,fid;
    size_t readsize;
    unsigned long long filesize;
    buffer ib=BUFFER_INIT(read,s,inbuf,sizeof(inbuf));

    /* Step 1: Negotiate dialect.  We only offer one */
    if (verbose) buffer_putsflush(buffer_1,"Negotiating SMB dialect... ");
    if (write(s,"\x00\x00\x00\x2f"	// NetBIOS
	        "\xffSMB"		// SMB
		"\x72\x00\x00\x00\x00\x00\x01\xc0\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x17\x00\x00\x00\x01\x00\x00\x0c"
		"\x00\x02NT LM 0.12",0x2f+4)!=0x2f+4) panic("Protocol negotiation request short write\n");

    readnetbios(&ib,buf,&wanted);

    if (wanted>sizeof(buf)) panic("packet too large");
    if (buffer_get(&ib,buf,wanted)!=wanted) panic("Protocol negotiation response short read\n");
    if (validatesmb(buf,wanted,0x72,17,0,0,1)) panic("Received invalid SMB response\n");
    if (uint16_read(buf+0x21)!=0) panic("Server requested invalid dialect\n");

    {
      char* x=buf+0x20+2*17;
      char* max=x+3+uint16_read(x+1);
      x+=3+(unsigned char)x[0];
      if (max>x && max-x<sizeof(domain)) {
	dlen=max-x;			// we are opportunistic bastards
	byte_copy(domain,dlen,x);	// in session setup we claim to come from the server's workgroup
	if (verbose) {
	  int i;
	  buffer_puts(buffer_1,"ok, got domain \"");
	  for (i=0; i<dlen; i+=2) {
	    if (domain[i+1] || !isprint(domain[i])) {
	      if (domain[i]==0) break;
	      buffer_put(buffer_1,".",1);
	    } else
	      buffer_put(buffer_1,domain+i,1);
	  }
	  buffer_putsflush(buffer_1,"\".\nSession Setup... ");
	}
      } else
	dlen=0;
    }

    if ((buf[0x33]&0x40)==0x40)
      readsize=64000;
    else {
      readsize=uint32_read(buf+0x27);
      if (readsize>64000) readsize=64000;
    }
    readbuf=malloc(readsize+300);
    if (!readbuf) panic("out of memory");

    /* Step 2: Session Setup. */
    {
      char *x;
      static char req[300]=
		"\x00\x00\x00\x00"	// NetBIOS
		"\xffSMB"		// SMB
		"\x73\x00\x00\x00\x00\x00\x01\xc0\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x17\x00\x00\x00\x02\x00\x0d\xff"
		"\x00\x00\x00\xff\xff\x02\x00\x17\x00\x17"
		"\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00"
		"\x00\x5c\x00\x00\x00"
		"\x00\x00"	// byte count
		"\x00\x00\x00"
		"G\x00U\x00""E\x00S\x00T\x00\x00\x00";	// "GUEST"
      size_t i;
      x=req+8+50+5+2+3+6*2;
      if (dlen) {
	byte_copy(x,dlen,domain);
	x+=dlen;
      }
      byte_copy(x,11,"U\x00n\x00i\x00x\x00\x00\x00\x00");
      x+=11;
      for (i=0; useragent[i]; ++i) {
	*x++=useragent[i];
	*x++=0;
      }
      x[0]=x[1]=x[2]=0;
      x+=3;
      uint32_pack_big(req,x-req-4);
      {
	char* y=req+8+50+5;
	uint16_pack(y,x-y-2);
      }
      if (write(s,req,x-req) != x-req) panic("Session Setup request short write");
    }

    readnetbios(&ib,buf,&wanted);
    if (wanted>sizeof(buf)) panic("packet too large");
    if (buffer_get(&ib,buf,wanted)!=wanted) panic("Session Setup response short read\n");
    if (validatesmb(buf,wanted,0x73,3,0,0,2)) panic("Received invalid SMB response\n");
    uid=uint16_read(buf+0x1c);

    if (verbose) {
      char* x,*y, * max;
      x=buf+0x20;
      x+=1+(unsigned char)x[0]*2;
      max=x+2+uint16_read(x);
      buffer_puts(buffer_1,"ok");
      x+=2;
      if ((uintptr_t)x&1) ++x;
      y=x;
      while (y<max && *y) y+=2;
      y+=2;
      if (y<max) {
	buffer_puts(buffer_1,", server \"");
	while (y<max) {
	  if (y[1] || !isprint(y[0])) {
	    if (!y[0]) break;
	    buffer_put(buffer_1,".",1);
	  } else
	    buffer_put(buffer_1,y,1);
	  y+=2;
	}
	buffer_puts(buffer_1,"\" on \"");
	while (x<max) {
	  if (x[1] || !isprint(x[0])) {
	    if (!x[0]) break;
	    buffer_put(buffer_1,".",1);
	  } else
	    buffer_put(buffer_1,x,1);
	  x+=2;
	}
      }
      buffer_putsflush(buffer_1,"\".\nTree Connect... ");
    }

    /* Step 3: Tree Connect */
    {
      char *x;
      char req[200+(strlen(host)+strlen(pathname))*2];
      size_t i;
      byte_copy(req,8+30+7+2+1,
		"\x00\x00\x00\x00"	// NetBIOS
		"\xffSMB"		// SMB
		"\x75\x00\x00\x00\x00\x00\x01\xc0\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x17\x00\x00\x00\x03\x00\x04\xff"
		"\x00\x00\x00\x00\x00\x01\x00"
		"\x00\x00"	// byte count
		"\x00");
      x=req+8+30+7+2+1;
      x[0]=x[2]='\\';
      x[1]=x[3]=0;
      x+=4;
      for (i=0; host[i]; ++i) {
	x[0]=host[i];
	x[1]=0;
	x+=2;
      }
      x[0]='\\'; x[1]=0; x+=2;
      if (*pathname=='/' || *pathname=='\\') ++pathname;
      for (i=0; pathname[i] && pathname[i]!='/' && pathname[i]!='\\'; ++i) {
	x[0]=pathname[i];
	x[1]=0;
	x+=2;
      }
      byte_copy(x,8,"\x00\x00?????");
      x+=8;
      uint32_pack_big(req,x-req-4);
      {
	char* y=req+8+30+7;
	uint16_pack(y,x-y-2);
      }
      uint16_pack(req+4+0x1c,uid);
      if (write(s,req,x-req) != x-req) panic("Tree Connect request short write");
    }

    readnetbios(&ib,buf,&wanted);
    if (wanted>sizeof(buf)) panic("packet too large");
    if (buffer_get(&ib,buf,wanted)!=wanted) panic("Tree Connect response short read\n");
    tid=uint16_read(buf+24);
    if (validatesmb(buf,wanted,0x75,3,0,tid,3)) panic("Received invalid SMB response\n");
    if (verbose) {
      buffer_puts(buffer_1,"ok, tid=");
      buffer_putulong(buffer_1,tid);
      buffer_putsflush(buffer_1,".\nCreateFile... ");
    }

    /* Step 4: CreateFile */
    {
      char *x,*y;
      char req[200+(strlen(pathname))*2];
      byte_copy(req,8+80+2,
		"\x00\x00\x00\x00"	// NetBIOS
		"\xffSMB"		// SMB
		"\xa2\x00\x00\x00\x00\x00\x01\xc0\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x17\x00\x00\x00\x04\x00\x18\xff"
		"\x00\x00\x00\x00\xFE\xFE\x10\x00\x00\x00"
		"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x07\x00\x00\x00\x01\x00\x00\x00\x40\x00"
		"\x00\x00\x01\x00\x00\x00\x01"
		"\x00\x00"	// byte count
		"\x00\\\x00");
      uint16_pack(req+4+24,tid);
      uint16_pack(req+4+0x1c,uid);
      x=req+8+80+2;
      y=pathname;

      while (*y=='/' || *y=='\\') ++y;
      while (*y && *y!='/' && *y!='\\') ++y;
      while (*y=='/' || *y=='\\') ++y;

      uint16_pack(req+8+34,(strlen(y)+1)*2);
      while (*y) {
	x[0]=*y;
	if (x[0]=='/') x[0]='\\';
	x[1]=0;
	x+=2;
	++y;
      }
      uint32_pack_big(req,x-req-4);
      {
	char* y=req+8+77;
	uint16_pack(y,x-y-2);
      }
      if (write(s,req,x-req) != x-req) panic("CreateFile request short write");
    }
    readnetbios(&ib,buf,&wanted);
    if (wanted>sizeof(buf)) panic("packet too large");
    if (buffer_get(&ib,buf,wanted)!=wanted) panic("CreateFile response short read\n");
    if (validatesmb(buf,wanted,0xa2,34,0,tid,4)) panic("Received invalid SMB response\n");
    fid=uint16_read(buf+0x20+6);
    filesize=uint64_read(buf+0x58);
    u.actime=(uint64_read(buf+0x44) / 10000000ll) - 11644473600ll;
    if (verbose) {
      char tbuf[30];
      tbuf[fmt_httpdate(tbuf,u.actime)]=0;
      buffer_puts(buffer_1,"ok, fid=");
      buffer_putulong(buffer_1,fid);
      buffer_puts(buffer_1,", size=");
      buffer_putulonglong(buffer_1,filesize);
      buffer_putmflush(buffer_1,", mtime=",tbuf,".\n");
    }

    if (filesize<=resumeofs) {
      if (verbose) buffer_putsflush(buffer_1,"File already fully transmitted.\n");
      goto closeanddone;
    }
    if (ims && u.actime<=ims) {
      if (verbose) buffer_putsflush(buffer_1,"The local file is as new as the remote file.\n");
      goto closeanddone;
    }

    /* Step 5: ReadFile */
    {
      static char req[]=
		"\x00\x00\x00\x3b"	// NetBIOS
		"\xffSMB"		// SMB
		"\x2e\x00\x00\x00\x00\x00\x01\xc0\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x17\x00\x00\x00\x05\x00\x0c\xff"
		"\x00\x00\x00w0u0__\x00"
		"\xf0\x00\xf0\x00\x00\x00\x00\x00\xf0u"
		"1__\x00\x00";
      size_t rest;
      size_t gotten;
      int nextwritten=0;
      int64 d;
      uint16_pack(req+4+0x1c,uid);
      uint16_pack(req+4+24,tid);
      uint16_pack(req+8+33,fid);
      if (filename[0]) {
	if ((resume?io_appendfile(&d,filename):io_createfile(&d,filename))==0)
	  panic("creat");
      } else {
	d=1;
	dostats=!isatty(1);
      }
      total=filesize-resumeofs;
      while (resumeofs<filesize) {
	size_t dataofs;

	uint16_pack(req+30+4,++mid);
	uint32_pack(req+8+33+2,resumeofs&0xffffffff);
	uint32_pack(req+8+49,resumeofs>>32);
	rest=(filesize-resumeofs>readsize)?readsize:filesize-resumeofs;
	uint16_pack(req+8+33+2+4,rest);
	uint16_pack(req+8+33+2+6,rest);
	uint16_pack(req+8+47,rest);

	if (!nextwritten) {
	  if (write(s,req,0x3b+4)!=0x3b+4) panic("ReadFile request short write");
	}
	readnetbios(&ib,buf,&wanted);
	if (wanted>readsize+300) panic("packet too large");
	if (wanted<0x20+12*2+3) panic("Received invalid SMB response\n");
	if (buffer_get(&ib,readbuf,0x20+12*2+3)!=0x20+12*2+3) panic("ReadFile response short read\n");

	if (validatesmb(readbuf,wanted,0x2e,12,0,tid,mid)) panic("Received invalid SMB response\n");
	gotten=uint16_read(readbuf+0x39);
	dataofs=uint16_read(readbuf+0x2d);
	if (dataofs+gotten>wanted) panic("invalid dataofs in ReadFile response");
	if (gotten<rest) break;	// someone truncated the file while we read?

	/* pipeline next read request */
	resumeofs+=gotten;
	if (resumeofs<filesize) {
	  uint16_pack(req+30+4,mid+1);
	  uint32_pack(req+8+33+2,resumeofs&0xffffffff);
	  uint32_pack(req+8+49,resumeofs>>32);
	  rest=(filesize-resumeofs>readsize)?readsize:filesize-resumeofs;
	  uint16_pack(req+8+33+2+4,rest);
	  uint16_pack(req+8+33+2+6,rest);
	  uint16_pack(req+8+47,rest);
	  if (write(s,req,0x3b+4)!=0x3b+4) panic("ReadFile request short write");
	  nextwritten=1;
	}

	if (buffer_get(&ib,readbuf+0x20+12*2+3,wanted-(0x20+12*2+3))!=wanted-(0x20+12*2+3)) panic("ReadFile response short read\n");
	if (write(d,readbuf+dataofs,gotten)!=gotten) panic("short write.  disk full?\n");
	if (dostats) printstats(gotten);
      }

      io_close(d);
    }

closeanddone:

    if (verbose) buffer_putsflush(buffer_1,"Close... ");

    /* Step 6: Close */
    {
      static char req[]=
		"\x00\x00\x00\x29"	// NetBIOS
		"\xffSMB"		// SMB
		"\x04\x00\x00\x00\x00\x00\x01\xc0\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\xFE\xFE\x17\x00\x00\x00\x05\x00\x03\xFE"
		"\xFE\xff\xff\xff\xff\x00\x00";
      uint16_pack(req+30+4,++mid);
      uint16_pack(req+8+29,fid);
      uint16_pack(req+8+20,tid);
      uint16_pack(req+4+0x1c,uid);
      if (write(s,req,8+37)!=8+37) panic("Close request short write");
      readnetbios(&ib,buf,&wanted);
      if (wanted>sizeof(buf)) panic("packet too large");
      if (buffer_get(&ib,buf,wanted)!=wanted) panic("Close response short read\n");
      if (validatesmb(buf,wanted,0x04,0,0,tid,mid)) panic("Received invalid SMB response\n");
    }

    if (verbose) buffer_putsflush(buffer_1,"ok.\nTree Disconnect... ");

    /* Step 7: Tree Disconnect */
    {
      static char req[]=
		"\x00\x00\x00\x23"	// NetBIOS
		"\xffSMB"		// SMB
		"\x71\x00\x00\x00\x00\x00\x01\xc0\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x17\x00\x00\x00\x05\x00\x00\x00";
      uint16_pack(req+30+4,++mid);
      uint16_pack(req+8+33,fid);
      uint16_pack(req+28,tid);
      uint16_pack(req+4+0x1c,uid);
      if (write(s,req,0x23+4)!=0x23+4) panic("Tree Disconnect request short write");
      readnetbios(&ib,buf,&wanted);
      if (wanted>sizeof(buf)) panic("packet too large");
      if (buffer_get(&ib,buf,wanted)!=wanted) panic("Tree Disconnect response short read\n");
      if (validatesmb(buf,wanted,0x71,0,0,tid,mid)) panic("Received invalid SMB response\n");
    }
    if (verbose) buffer_putsflush(buffer_1,"ok.\n");

  } else
    panic("invalid mode\n");
  close(s);
  if (filename[0] && u.actime) {
    u.modtime=u.actime;
    if (strcmp(filename,"-") && utime(filename,&u)==-1)
      if (errno!=ENOENT || !imode)
	panic("utime");
  }
  clearstats();
  return 0;
}
