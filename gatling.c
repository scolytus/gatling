// #define SUPPORT_SMB
#define SUPPORT_FTP
#define SUPPORT_PROXY
/* #define DEBUG to enable more verbose debug messages for tracking fd
 * leaks */
/* #define DEBUG */
#define SUPPORT_CGI
/* #define SUPPORT_HTACCESS */

/* http header size limit: */
#define MAX_HEADER_SIZE 8192

#define _FILE_OFFSET_BITS 64
#include "socket.h"
#include "io.h"
#include "buffer.h"
#include "ip4.h"
#include "ip6.h"
#include "array.h"
#include "case.h"
#include "fmt.h"
#include "iob.h"
#include "str.h"
#include "scan.h"
#include "textcode.h"
#include "uint32.h"
#include "uint16.h"
#include "mmap.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "version.h"
#include <assert.h>
#include <fnmatch.h>
#include <sys/wait.h>
#include <sys/mman.h>
#ifdef SUPPORT_SMB
#include <iconv.h>
#endif
#ifdef SUPPORT_PROXY
#include <regex.h>
#endif
#include <limits.h>
#include <string.h>
#include "havealloca.h"

unsigned long timeout_secs=23;
tai6464 next;

#ifdef TIMEOUT_DEBUG
void new_io_timeout(int64 d,tai6464 t) {
  struct taia now;
  struct taia diff;
  taia_now(&now);
  taia_sub(&diff,&t,&now);
  buffer_puts(buffer_2,"DEBUG: scheduling timeout for fd #");
  buffer_putlonglong(buffer_2,d);
  buffer_puts(buffer_2," in ");
  buffer_putlonglong(buffer_2,diff.sec.x);
  buffer_putsflush(buffer_2," seconds.\n");
  io_timeout(d,t);
}

int64 new_io_timeouted() {
  int64 x=io_timeouted();
  buffer_puts(buffer_2,"DEBUG: io_timeouted called, returned ");
  buffer_putlonglong(buffer_2,x);
  buffer_putnlflush(buffer_2);
  return x;
}

#define io_timeout new_io_timeout
#define io_timeouted new_io_timeouted
#endif

static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";

#ifdef USE_ZLIB
#include <zlib.h>
#endif

#ifdef SUPPORT_CGI
static int forksock[2];
#endif

#if defined(__OpenBSD__) || defined(__NetBSD__)
#define __broken_itojun_v6__
#endif
#define RELEASE "Gatling/" VERSION

int virtual_hosts;
int transproxy;
int directory_index;
int logging;
int nouploads;
int chmoduploads;
int64 origdir;

#ifdef SUPPORT_SMB
char workgroup[20]="FNORD";
int wglen;
char workgroup_utf16[100];
int wglen16;
#endif

#ifdef SUPPORT_HTTPS
/* in ssl.c */
#include <openssl/ssl.h>
#include <openssl/err.h>
extern int init_serverside_tls(SSL** ssl,int sock);
extern int init_clientside_tls(SSL** ssl,int sock);
#endif

static void carp(const char* routine) {
  buffer_putmflush(buffer_2,routine,": ",strerror(errno),"\n");
#if 0
  buffer_puts(buffer_2,routine);
  buffer_puts(buffer_2,": ");
  buffer_puterror(buffer_2);
  buffer_putnlflush(buffer_2);
#endif
}

static void panic(const char* routine) {
  carp(routine);
  exit(111);
}

enum encoding {
  NORMAL,
  GZIP,
  BZIP2,
};

enum conntype {
  HTTPSERVER6,	/* call socket_accept6() */
  HTTPSERVER4,	/* call socket_accept4() */
  HTTPREQUEST,	/* read and handle http request */

#ifdef SUPPORT_FTP
  FTPSERVER6,	/* call socket_accept6() */
  FTPSERVER4,	/* call socket_accept4() */
  FTPCONTROL6,	/* read and handle ftp commands */
  FTPCONTROL4,	/* read and handle ftp commands */
  FTPPASSIVE,	/* accept a slave connection */
  FTPACTIVE,	/* still need to connect slave connection */
  FTPSLAVE,	/* send/receive files */
#endif

#ifdef SUPPORT_SMB
  SMBSERVER6,	/* call socket_accept6() */
  SMBSERVER4,	/* call socket_accept4() */
  SMBREQUEST,	/* read and handle SMB request */
#endif

#ifdef SUPPORT_PROXY
  PROXYSLAVE,	/* write-to-proxy connection. */
		/* write HTTP header; switch type to PROXYPOST */
  PROXYPOST,	/* while still_to_copy>0: write POST data; relay answer */
  HTTPPOST,	/* type of HTTP request until POST data is completely
		   written; read post data and write them to proxy */
#endif

#ifdef SUPPORT_HTTPS
  HTTPSSERVER4,	/* call socket_accept6() */
  HTTPSSERVER6,	/* call socket_accept4() */
  HTTPSACCEPT,	/* call SSL_accept() */
  HTTPSREQUEST,	/* read and handle https request */
  HTTPSRESPONSE,	/* write response to https request */
#endif
};

#ifdef SUPPORT_FTP
enum ftpstate {
  GREETING,
  WAITINGFORUSER,
  LOGGEDIN,
  WAITCONNECT,
  DOWNLOADING,
  UPLOADING,
};

int askforpassword;
#endif

struct http_data {
  enum conntype t;
#ifdef SUPPORT_FTP
  enum ftpstate f;
#endif
  array r;
  io_batch iob;
  unsigned char myip[16];	/* this is needed for virtual hosting */
  uint32 myscope_id;		/* in the absence of a Host header */
  uint16 myport,peerport;
  uint16 destport;	/* port on remote system, used for active FTP */
  char* hdrbuf,* bodybuf;
  const char *mimetype;
  int hlen,blen;	/* hlen == length of hdrbuf, blen == length of bodybuf */
  int keepalive;	/* 1 if we want the TCP connection to stay connected */
			/* this is always 1 for FTP except after the client said QUIT */
  int filefd;	/* -1 or the descriptor of the file we are sending out */
  int buddy;	/* descriptor for the other connection, only used for FTP */
  unsigned char peerip[16];	/* needed for active FTP */
  enum encoding encoding;
#ifdef SUPPORT_FTP
  char* ftppath;
  uint64 ftp_rest;	/* offset to start transfer at */
#endif
  uint64 sent_until,prefetched_until;
#ifdef SUPPORT_PROXY
  uint64 still_to_copy;	/* for POST requests */
  int havefirst;	/* first read contains cgi header */
  char* oldheader;	/* old, unmodified request */
#endif
#ifdef SUPPORT_HTTPS
  SSL* ssl;
  int writefail;
#endif
#ifdef SUPPORT_SMB
  enum { PCNET10, LANMAN21, NTLM012 } smbdialect;
#endif
};

#if defined(SUPPORT_PROXY) || defined(SUPPORT_CGI)
/* You configure a list of regular expressions, and if a request matches
 * one of them, the request is forwarded to some other IP:port.  You can
 * run another httpd there that can handle CGI, PHP, JSP and whatnot. */
struct cgi_proxy {
  regex_t r;
  char ip[16];
  uint16 port;
  uint32 scope_id;
  struct cgi_proxy* next;
}* cgis;
struct cgi_proxy* last;

/* if port==0 then execute the CGI locally */
#endif

#ifdef SUPPORT_CGI
static int add_cgi(const char* c) {
  struct cgi_proxy* x=malloc(sizeof(struct cgi_proxy));
  if (!x) return -1;
  byte_zero(x,sizeof(struct cgi_proxy));
  if (regcomp(&x->r,c,REG_EXTENDED|REG_NOSUB)) {
    free(x);
    return -1;
  }
  if (!last)
    cgis=last=x;
  else
    last->next=x; last=x;
  return 0;
}
#endif

#ifdef SUPPORT_PROXY
static int add_proxy(const char* c) {
  struct cgi_proxy* x=malloc(sizeof(struct cgi_proxy));
  int i;
  if (!x) return -1;
  byte_zero(x,sizeof(struct cgi_proxy));
  i=scan_ip6if(c,x->ip,&x->scope_id);
  if (c[i]!='/') { nixgut: free(x); return -1; }
  c+=i+1;
  i=scan_ushort(c,&x->port);
  if (c[i]!='/') goto nixgut;
  c+=i+1;
  if (regcomp(&x->r,c,REG_EXTENDED|REG_NOSUB)) goto nixgut;
  if (!last)
    cgis=last=x;
  else
    last->next=x; last=x;
  return 0;
}

static char* http_header(struct http_data* r,char* h);
int buffer_putlogstr(buffer* b,const char* s);
void httperror_realm(struct http_data* r,const char* title,const char* message,const char* realm);
void httperror(struct http_data* r,const char* title,const char* message);
static int header_complete(struct http_data* r);

static int proxy_connection(int sockfd,const char* c,const char* dir,struct http_data* d) {
  struct cgi_proxy* x=cgis;
  struct stat ss;
  if (stat(".proxy",&ss)==-1) return -3;
  while (x) {
    if (regexec(&x->r,c,0,0,0)==0) {
      /* if the port is zero, then use local execution proxy mode instead */
      int s;
      struct http_data* h;

      if (!(h=(struct http_data*)malloc(sizeof(struct http_data)))) continue;
      byte_zero(h,sizeof(struct http_data));

      if (logging) {
	char buf[IP6_FMT+10];
	char* tmp;
	const char* method="???";
	{
	  int x;
	  x=fmt_ip6c(buf,h->myip);
	  x+=fmt_str(buf+x,"/");
	  x+=fmt_ulong(buf+x,h->myport);
	  buf[x]=0;
	}
	tmp=array_start(&d->r);
#ifdef SUPPORT_HTTPS
	switch (*tmp) {
	case 'H': method=(d->t==HTTPREQUEST)?"HEAD":"HEAD/SSL"; break;
	case 'G': method=(d->t==HTTPREQUEST)?"GET":"GET/SSL"; break;
	case 'P': method=(d->t==HTTPREQUEST)?"POST":"POST/SSL"; break;
	}
#else
	switch (*tmp) {
	case 'H': method="HEAD"; break;
	case 'G': method="GET"; break;
	case 'P': method="POST"; break;
	}
#endif
	buffer_putm(buffer_1,method,x->port?"/PROXY ":"/CGI ");
	buffer_putulong(buffer_1,sockfd);
	buffer_puts(buffer_1," ");
	buffer_putlogstr(buffer_1,c);
	buffer_puts(buffer_1," 0 ");
	buffer_putlogstr(buffer_1,(tmp=http_header(d,"User-Agent"))?tmp:"[no_user_agent]");
	buffer_puts(buffer_1," ");
	buffer_putlogstr(buffer_1,(tmp=http_header(d,"Referer"))?tmp:"[no_referrer]");
	buffer_puts(buffer_1," ");
	buffer_putlogstr(buffer_1,(tmp=http_header(d,"Host"))?tmp:buf);
	buffer_putsflush(buffer_1,"\n");
      }

      if (x->port) {
	/* proxy mode */
	h->t=PROXYSLAVE;
	s=socket_tcp6();
	if (s==-1) return -1;
	if (!io_fd(s)) {
punt:
	  free(h);
	  io_close(s);
	  return -1;
	}
	io_eagain(s);
	if (socket_connect6(s,x->ip,x->port,x->scope_id)==-1)
	  if (errno!=EINPROGRESS)
	    goto punt;
	if (logging) {
	  char tmp[100];
	  char bufsockfd[FMT_ULONG];
	  char bufs[FMT_ULONG];
	  char bufport[FMT_ULONG];

	  bufsockfd[fmt_ulong(bufsockfd,sockfd)]=0;
	  bufs[fmt_ulong(bufs,s)]=0;
	  bufport[fmt_ulong(bufport,x->port)]=0;
	  tmp[fmt_ip6ifc(tmp,x->ip,x->scope_id)]=0;

	  buffer_putm(buffer_1,"proxy_connect ",bufsockfd," ",bufs," ",tmp," ",bufport," ");
#if 0
	  buffer_puts(buffer_1,"proxy_connect ");
	  buffer_putulong(buffer_1,sockfd);
	  buffer_putspace(buffer_1);
	  buffer_putulong(buffer_1,s);
	  buffer_putspace(buffer_1);
	  buffer_put(buffer_1,tmp,fmt_ip6ifc(tmp,x->ip,x->scope_id));
	  buffer_putspace(buffer_1);
	  buffer_put(buffer_1,tmp,fmt_ulong(tmp,x->port));
	  buffer_putspace(buffer_1);
#endif
	  buffer_putlogstr(buffer_1,c);
	  buffer_putnlflush(buffer_1);
	}
	io_wantwrite(s);
#ifdef SUPPORT_CGI
      } else {
	/* local CGI mode */
	uint32 a,len; uint16 b;
	pid_t pid;
	char* req=array_start(&d->r); /* "GET /t.cgi/foo/bar?fnord HTTP/1.0\r\nHost: localhost:80\r\n\r\n"; */
	char ra[IP6_FMT];
	req[strlen(req)]=' ';
	d->keepalive=0;
	ra[fmt_ip6c(ra,d->peerip)]=0;
	a=strlen(req); write(forksock[0],&a,4);
	a=strlen(dir); write(forksock[0],&a,4);
	a=strlen(ra); write(forksock[0],&a,4);
	write(forksock[0],req,strlen(req));
	write(forksock[0],dir,strlen(dir));
	write(forksock[0],ra,strlen(ra));
	b=d->peerport; write(forksock[0],&b,2);
	b=d->myport; write(forksock[0],&b,2);

	read(forksock[0],&a,4);		/* code; 0 means OK */
	read(forksock[0],&len,4);	/* length of error message */
	read(forksock[0],&pid,sizeof(pid));
	if (len) {
	  char* c=alloca(len+1);
	  read(forksock[0],c,len);
	  httperror(d,"502 Gateway Broken",c);
	  free(h);
	  return -1;
	} else {
	  s=io_receivefd(forksock[0]);
	  if (s==-1) {
	    buffer_putsflush(buffer_2,"received no file descriptor for CGI\n");
	    free(h);
	    return -1;
	  }
	  if (!io_fd(s)) {
	    httperror(d,"502 Gateway Broken",c);
	    io_close(s);
	    free(h);
	    return -1;
	  }
	}
	h->t=PROXYPOST;
	if (logging) {
	  char bufsfd[FMT_ULONG];
	  char bufs[FMT_ULONG];
	  char bufpid[FMT_ULONG];

	  bufsfd[fmt_ulong(bufsfd,sockfd)]=0;
	  bufs[fmt_ulong(bufs,s)]=0;
	  bufpid[fmt_ulong(bufpid,pid)]=0;

	  buffer_putmflush(buffer_1,"cgi_fork ",bufsfd," ",bufs," ",bufpid,"\n");
#if 0
	  buffer_puts(buffer_1,"cgi_fork ");
	  buffer_putulong(buffer_1,sockfd);
	  buffer_putspace(buffer_1);
	  buffer_putulong(buffer_1,s);
	  buffer_putspace(buffer_1);
	  buffer_putulong(buffer_1,pid);
	  buffer_putnlflush(buffer_1);
#endif
	}
#endif
      }
      h->buddy=sockfd;
      d->buddy=s;
      io_setcookie(s,h);
      {
	struct http_data* x=io_getcookie(sockfd);
	if (x) {
	  char* cl=http_header(x,"Content-Length");
	  if (cl) {
	    char c;
	    if ((c=cl[scan_ulonglong(cl,&h->still_to_copy)])!='\r' && c!='\n') h->still_to_copy=0;
	  }
	  x->still_to_copy=0;
//	  printf("still_to_copy init: %p %llu <-> %p %llu\n",x,x->still_to_copy,h,h->still_to_copy);
	  byte_copy(h->peerip,16,x->peerip);
	  if (!h->still_to_copy && h->t==PROXYPOST) {
	    io_wantread(s);
	    io_dontwantwrite(s);
	    io_dontwantread(sockfd);
	    io_dontwantwrite(sockfd);
	  } else {
	    /* there is still data to copy */

#if 0
	    char* data=array_start(&d->r);
	    long i,j,found;
	    j=array_bytes(&d->r);
	    found=-1;
	    for (i=0; i<j; ++i)
	      if (byte_equal(data+i,4,"\r\n\r\n")) {
		found=i+4; break;
	      }
	    assert(found!=-1);	/* we shouldn't be here if the header was not complete */
	    if (found!=-1) {
	    }
#endif
	    /* TODO: check whether we already have data to read */

	    io_wantread(sockfd);
	    io_dontwantwrite(sockfd);
	    io_wantread(s);
	    if (header_complete(d) < array_bytes(&d->r))	/* FIXME */
	      io_wantwrite(s);
	    else
	      io_dontwantwrite(s);
	  }
	}
      }

      if (timeout_secs)
	io_timeout(s,next);
      return s;
    }
    x=x->next;
  }
  return -3;
}

int proxy_write_header(int sockfd,struct http_data* h) {
  /* assume we can write the header in full. */
  /* slight complication: we need to turn keep-alive off and we need to
   * add a X-Forwarded-For header so the handling web server can write
   * the real IP to the log file. */
  struct http_data* H=io_getcookie(h->buddy);
  int i,j;
  long hlen=array_bytes(&h->r);
  char* hdr=array_start(&h->r);
  char* newheader=alloca(hlen+200);
  for (i=j=0; i<hlen; ) {
    int k=str_chr(hdr+i,'\n');
    if (k==0) break;
    if (case_starts(hdr+i,"Connection: ") || case_starts(hdr+i,"X-Forwarded-For: "))
      i+=k+1;
    else {
      byte_copy(newheader+j,k+1,hdr+i);
      i+=k+1;
      j+=k+1;
    }
  }
  if (j) j-=2;
  H->keepalive=0;
  j+=fmt_str(newheader+j,"Connection: close\r\nX-Forwarded-For: ");
  j+=fmt_ip6c(newheader+j,H->peerip);
  j+=fmt_str(newheader+j,"\r\n\r\n");
  if (write(sockfd,newheader,j)!=j)
    return -1;
  return 0;
}

static void cleanup(int64 fd);

int proxy_is_readable(int sockfd,struct http_data* H) {
  char buf[8192];
  int i;
  char* x;
  int res=0;
  struct http_data* peer=io_getcookie(H->buddy);
  i=read(sockfd,buf,sizeof(buf));
  if (i==-1) return -1;
  if (i==0) {
    if (logging) {
      char numbuf[FMT_ULONG];
      numbuf[fmt_ulong(numbuf,sockfd)]=0;
      buffer_putmflush(buffer_1,"cgiproxy_read0 ",numbuf,"\n");
#if 0
      buffer_puts(buffer_1,"cgiproxy_read0 ");
      buffer_putulong(buffer_1,sockfd);
      buffer_putnlflush(buffer_1);
#endif
    }
    if (peer) {
      peer->buddy=-1;
      if (peer->iob.bytesleft==0) {
	cleanup(sockfd);
	return -3;
      }
    }
    H->buddy=-1;
    io_wantwrite(H->buddy);
    io_close(sockfd);
    return -3;
  } else {
    int needheader=0;
    if (!H->havefirst) {
      H->havefirst=1;
      if (byte_diff(buf,5,"HTTP/"))
	/* No "HTTP/1.0 200 OK", need to write our own header. */
	needheader=1;
    }
    if (needheader) {
      int j;
      x=malloc(i+100);
      if (!x) goto nomem;
      j=fmt_str(x,"HTTP/1.0 200 Here you go\r\nServer: " RELEASE "\r\n");
      byte_copy(x+j,i,buf);
      i+=j;
    } else {
      x=malloc(i);
      if (!x) goto nomem;
      byte_copy(x,i,buf);
    }
    if (peer) iob_addbuf_free(&peer->iob,x,i);
  }
  io_dontwantread(sockfd);
  io_wantwrite(H->buddy);
  return res;
nomem:
  if (logging) {
    char numbuf[FMT_ULONG];
    numbuf[fmt_ulong(numbuf,sockfd)]=0;
    buffer_putmflush(buffer_1,"outofmemory ",numbuf,"\n");
  }
  cleanup(sockfd);
  return -1;
}

int read_http_post(int sockfd,struct http_data* H) {
  char buf[8192];
  int i;
  long l=H->still_to_copy;
  if (l>sizeof(buf)) l=sizeof(buf);
  i=read(sockfd,buf,sizeof(buf));
//  printf("read_http_post: want to read %ld bytes from %d; got %d\n",l,sockfd,i);
  if (i<1) return -1;
  H->still_to_copy-=i;
//  printf("still_to_copy read_http_post: %p %llu -> %llu\n",H,H->still_to_copy+i,H->still_to_copy);
  array_catb(&H->r,buf,i);
  if (array_failed(&H->r))
    return -1;
  return 0;
}

#endif


static int open_for_reading(int64* fd,const char* name,struct stat* SS) {
  /* only allow reading of world readable files */
  if (io_readfile(fd,name)) {
    struct stat ss;
    if (!SS) SS=&ss;
    if (fstat(*fd,SS)==-1 || !(SS->st_mode&S_IROTH)) {
      close(*fd);
      *fd=-1;
      return 0;
    }
    return 1;
  }
  return 0;
}

#ifdef SUPPORT_FTP
static int open_for_writing(int64* fd,const char* name) {
  /* only allow creating files in world writable directories */
  const char* c;
  char* x;
  struct stat ss;
  c=name+str_rchr(name,'/');
//  if (!*c) return 0;	/* no slashes?  There's something fishy */
  if (!*c) {
    x=".";
  } else {
    x=alloca(c-name+1);
    byte_copy(x,c-name,name); x[c-name]=0;
  }
  if (stat(x,&ss)==-1) return 0;	/* better safe than sorry */
  if (!(ss.st_mode&S_IWOTH)) return 0;
  return io_createfile(fd,name);
}


/* "/foo" -> "/foo"
 * "/foo/./" -> "/foo"
 * "/foo/.." -> "/" */
static int canonpath(char* s) {
  int i,j;
  char c;
  for (i=j=0; (c=s[i]); ++i) {
    if (c=='/') {
      while (s[i+1]=='/') ++i;			/* "//" */
    } else if (c=='.' && j && s[j-1]=='/') {
      if (s[i+1]=='.' && (s[i+2]=='/' || s[i+2]==0)) {		/* /../ */
	if (j>1)
	  for (j-=2; s[j]!='/' && j>0; --j);	/* remove previous dir */
	i+=2;
      } else if (s[i+1]=='/' || s[i+1]==0) {
	++i;
	continue;
      } else
	c=':';
    }
    if (!(s[j]=s[i])) break; ++j;
  }
  if (j && s[j-1]=='/') --j;
  if (!j) { s[0]='/'; j=1; }
  s[j]=0;
  return j;
}
#endif

static int header_complete(struct http_data* r) {
  long i;
  long l=array_bytes(&r->r);
  const char* c=array_start(&r->r);
#ifdef SUPPORT_HTTPS
  if (r->t==HTTPREQUEST || r->t==HTTPSREQUEST)
#else
  if (r->t==HTTPREQUEST)
#endif
  {
    for (i=0; i+1<l; ++i) {
      if (c[i]=='\n' && c[i+1]=='\n')
	return i+2;
      if (i+3<l &&
	  c[i]=='\r' && c[i+1]=='\n' &&
	  c[i+2]=='\r' && c[i+3]=='\n')
	return i+4;
    }
#ifdef SUPPORT_SMB
  } else if (r->t==SMBREQUEST) {
    /* SMB */
    /* first four bytes are the NetBIOS session;
     * byte 0: 0 ("session message"),
     * bytes 1-3: message length (big endian) */
    uint32 len;
    if (c[0]!=0) return 1;
    len=uint32_read_big(c) & 0x00ffffff;
    if (l==len+4) return len+4;
#endif
  } else {
    /* FTP */
    for (i=0; i<l; ++i)
      if (c[i]=='\n')
	return i+1;
  }
  return 0;
}

static char oom[]="HTTP/1.0 500 internal error\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nout of memory\n";

void httperror_realm(struct http_data* r,const char* title,const char* message,const char* realm) {
  char* c;
  if (r->t==HTTPSERVER4 || r->t==HTTPSERVER6 || r->t==HTTPREQUEST
#ifdef SUPPORT_HTTPS
      || r->t==HTTPSSERVER4 || r->t==HTTPSSERVER6
      || r->t==HTTPSREQUEST || r->t==HTTPSRESPONSE
#endif
								) {
    c=r->hdrbuf=(char*)malloc(str_len(message)+str_len(title)+str_len(realm?realm:"")+300);
    if (!c) {
      r->hdrbuf=oom;
      r->hlen=str_len(r->hdrbuf);
      buffer_putsflush(buffer_1,"error_oom\n");
      iob_addbuf(&r->iob,r->hdrbuf,r->hlen);
    } else {
      c+=fmt_str(c,"HTTP/1.0 ");
      c+=fmt_str(c,title);
      c+=fmt_str(c,"\r\nContent-Type: text/html\r\nConnection: ");
      c+=fmt_str(c,r->keepalive?"keep-alive":"close");
      c+=fmt_str(c,"\r\nServer: " RELEASE "\r\nContent-Length: ");
      c+=fmt_ulong(c,str_len(message)+str_len(title)+16-4);
      if (realm) {
	c+=fmt_str(c,"\r\nWWW-Authenticate: Basic realm=\"");
	c+=fmt_str(c,realm);
	c+=fmt_str(c,"\"");
      }
      c+=fmt_str(c,"\r\n\r\n<title>");
      c+=fmt_str(c,title+4);
      c+=fmt_str(c,"</title>\n");
      c+=fmt_str(c,message);
      c+=fmt_str(c,"\n");
      r->hlen=c - r->hdrbuf;
      iob_addbuf_free(&r->iob,r->hdrbuf,r->hlen);
    }
  } else {
    /* FTP */
    c=r->hdrbuf=(char*)malloc(str_len(title)+3);
    c+=fmt_str(c,title);
    c+=fmt_str(c,"\r\n");
    r->hlen=c-r->hdrbuf;
    iob_addbuf_free(&r->iob,r->hdrbuf,r->hlen);
  }
}

void httperror(struct http_data* r,const char* title,const char* message) {
  httperror_realm(r,title,message,0);
}

static unsigned int fmt_2digits(char* dest,int i) {
  dest[0]=(i/10)+'0';
  dest[1]=(i%10)+'0';
  return 2;
}



#if 0
 _     _   _
| |__ | |_| |_ _ __
| '_ \| __| __| '_ \
| | | | |_| |_| |_) |
|_| |_|\__|\__| .__/
              |_|
#endif

static struct mimeentry { const char* name, *type; } mimetab[] = {
  { "html",	"text/html" },
  { "txt",	"text/plain" },
  { "css",	"text/css" },
  { "dvi",	"application/x-dvi" },
  { "ps",	"application/postscript" },
  { "pdf",	"application/pdf" },
  { "gif",	"image/gif" },
  { "png",	"image/png" },
  { "jpeg",	"image/jpeg" },
  { "jpg",	"image/jpeg" },
  { "mpeg",	"video/mpeg" },
  { "mpg",	"video/mpeg" },
  { "avi",	"video/x-msvideo" },
  { "mov",	"video/quicktime" },
  { "qt",	"video/quicktime" },
  { "mp3",	"audio/mpeg" },
  { "ogg",	"audio/x-oggvorbis" },
  { "wav",	"audio/x-wav" },
  { "pac",	"application/x-ns-proxy-autoconfig" },
  { "sig",	"application/pgp-signature" },
  { "torrent",	"application/x-bittorrent" },
  { "class",	"application/octet-stream" },
  { "js",	"application/x-javascript" },
  { "tar",	"application/x-tar" },
  { "zip",	"application/zip" },
  { "rar",	"application/x-rar-compressed" },
  { "7z",	"application/x-7z-compressed" },
  { "dtd",	"text/xml" },
  { "xml",	"text/xml" },
  { "xbm",	"image/x-xbitmap" },
  { "xpm",	"image/x-xpixmap" },
  { "xwd",	"image/x-xwindowdump" },
  { "text",	"text/plain" },
  { "txt",	"text/plain" },
  { "m3u",	"audio/x-mpegurl" },
  { 0 } };

const char* mimetype(const char* filename) {
  int i,e=str_rchr(filename,'.');
  if (filename[e]==0) return "text/plain";
  ++e;
  for (i=0; mimetab[i].name; ++i)
    if (str_equal(mimetab[i].name,filename+e))
      return mimetab[i].type;
  return "application/octet-stream";
}

static int tolower(char a) {
  return a>='A' && a<='Z' ? a-'A'+'a' : a;
}

static int header_diff(const char* s,const char* t) {
  /* like str_diff but s may also end with '\r' or '\n' */
  register int j;
  j=0;
  for (;;) {
    if ((j=(tolower(*s)-tolower(*t)))) break; if (!*t) break; ++s; ++t;
  }
  if (*s=='\r' || *s=='\n') j=-*t;
  return j;
}

static char* http_header_blob(char* b,long l,char* h) {
  long i;
  long sl=str_len(h);
  for (i=0; i+sl+2<l; ++i)
    if (b[i]=='\n' && case_equalb(b+i+1,sl,h) && b[i+sl+1]==':') {
      b+=i+sl+2;
      if (*b==' ' || *b=='\t') ++b;
      return b;
    }
  return 0;
}

static char* http_header(struct http_data* r,char* h) {
  return http_header_blob(array_start(&r->r),array_bytes(&r->r),h);
}

typedef struct de {
  long name;	/* offset within b */
  struct stat ss;
} de;
char* base;

int sort_name_a(de* x,de* y) { return (str_diff(base+x->name,base+y->name)); }
int sort_name_d(de* x,de* y) { return (str_diff(base+y->name,base+x->name)); }
int sort_mtime_a(de* x,de* y) { return x->ss.st_mtime-y->ss.st_mtime; }
int sort_mtime_d(de* x,de* y) { return y->ss.st_mtime-x->ss.st_mtime; }
int sort_size_a(de* x,de* y) { return x->ss.st_size-y->ss.st_size; }
int sort_size_d(de* x,de* y) { return y->ss.st_size-x->ss.st_size; }

static inline int issafe(unsigned char c) {
  return (c!='"' && c!='%' && c>=' ' && c!='+');
}

unsigned long fmt_urlencoded(char* dest,const char* src,unsigned long len) {
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

void catencoded(array* a,char* s) {
  unsigned int len=str_len(s);
  char* buf=alloca(fmt_urlencoded(0,s,len));
  array_catb(a,buf,fmt_urlencoded(buf,s,len));
}

void cathtml(array* a,char* s) {
  unsigned int len=str_len(s);
  char* buf=alloca(fmt_html(0,s,len));
  array_catb(a,buf,fmt_html(buf,s,len));
}

int http_dirlisting(struct http_data* h,DIR* D,const char* path,const char* arg) {
  long i,o,n;
  struct dirent* d;
  int (*sortfun)(de*,de*);
  array a,b,c;
  de* ab;
  byte_zero(&a,sizeof(a));
  byte_zero(&b,sizeof(b));
  byte_zero(&c,sizeof(c));
  o=n=0;
  while ((d=readdir(D))) {
    de* x=array_allocate(&a,sizeof(de),n);
    if (!x) break;
    x->name=o;
    if (lstat(d->d_name,&x->ss)==-1) continue;
    array_cats0(&b,d->d_name);
    o+=str_len(d->d_name)+1;
    ++n;
  }
  closedir(D);
  if (array_failed(&a) || array_failed(&b)) {
    array_reset(&a);
    array_reset(&b);
    return 0;
  }
  base=array_start(&b);
  sortfun=sort_name_a;
  if (arg) {
    if (str_equal(arg,"N=D")) sortfun=sort_name_d;
    else if (str_equal(arg,"N=A")) sortfun=sort_name_a;
    else if (str_equal(arg,"M=A")) sortfun=sort_mtime_a;
    else if (str_equal(arg,"M=D")) sortfun=sort_mtime_d;
    else if (str_equal(arg,"S=A")) sortfun=sort_size_a;
    else if (str_equal(arg,"S=D")) sortfun=sort_size_d;
  }
  qsort(array_start(&a),n,sizeof(de),(int(*)(const void*,const void*))sortfun);
  array_cats(&c,"<title>Index of ");
  array_cats(&c,path);
  array_cats(&c,"</title>\n<h1>Index of ");
  array_cats(&c,path);
  {
    char* tmp=http_header(h,"User-Agent");
    if (tmp && byte_equal(tmp,5,"Wget/"))
      array_cats(&c,"</h1>\n<table><tr><th>Name<th>Last Modified<th>Size\n");
    else {
      array_cats(&c,"</h1>\n<table><tr><th><a href=\"?N=");
      array_cats(&c,sortfun==sort_name_a?"D":"A");
      array_cats(&c,"\">Name</a><th><a href=\"?M=");
      array_cats(&c,sortfun==sort_mtime_a?"D":"A");
      array_cats(&c,"\">Last Modified</a><th><a href=\"?S=");
      array_cats(&c,sortfun==sort_size_a?"D":"A");
      array_cats(&c,"\">Size</a>\n");
    }
  }
  ab=array_start(&a);
  for (i=0; i<n; ++i) {
    char* name=base+ab[i].name;
    char buf[31];
    int j;
    struct tm* x=localtime(&ab[i].ss.st_mtime);
    if (name[0]=='.') {
      if (name[1]==0) continue; /* skip "." */
      if (name[1]!='.' || name[2]!=0)	/* skip dot-files */
	continue;
    }
    if (name[0]==':') name[0]='.';
    array_cats(&c,"<tr><td><a href=\"");
    catencoded(&c,base+ab[i].name);
    if (S_ISDIR(ab[i].ss.st_mode)) array_cats(&c,"/");
    array_cats(&c,"\">");
    cathtml(&c,base+ab[i].name);
    if (S_ISDIR(ab[i].ss.st_mode)) array_cats(&c,"/"); else
    if (S_ISLNK(ab[i].ss.st_mode)) array_cats(&c,"@");
    array_cats(&c,"</a><td>");

    j=fmt_2digits(buf,x->tm_mday);
    j+=fmt_str(buf+j,"-");
    byte_copy(buf+j,3,months+3*x->tm_mon); j+=3;
    j+=fmt_str(buf+j,"-");
    j+=fmt_2digits(buf+j,(x->tm_year+1900)/100);
    j+=fmt_2digits(buf+j,(x->tm_year+1900)%100);
    j+=fmt_str(buf+j," ");
    j+=fmt_2digits(buf+j,x->tm_hour);
    j+=fmt_str(buf+j,":");
    j+=fmt_2digits(buf+j,x->tm_min);

    array_catb(&c,buf,j);
    array_cats(&c,"<td align=right>");
    array_catb(&c,buf,fmt_humank(buf,ab[i].ss.st_size));
  }
  array_cats(&c,"</table>");
  array_reset(&a);
  array_reset(&b);
  if (array_failed(&c)) return 0;
  h->bodybuf=array_start(&c);
  h->blen=array_bytes(&c);
  return 1;
}

#ifdef SUPPORT_HTACCESS
/* check whether there is a .htaccess file in the current directory.
 * if it is, expect the following format:

Realm
username:password
username2:password2
...

 * Realm is the HTTP realm (transmitted in the http authentication
 * required message and usually displayed by the browser).  Only basic
 * authentication is supported.  Please note that .htaccess files are
 * not looked for in other directories.  If you want subdirectories
 * covered, use hard or symbolic links.  The function returns 0 if the
 * authentication was OK or -1 if authentication is needed (the HTTP
 * response was then already written to the iob). */
int http_dohtaccess(struct http_data* h) {
  unsigned long filesize;
  char* map;
  char* s;
  char* auth;
  char* realm;
  int r=0;
  map=mmap_read(".htaccess",&filesize);
  if (!map) return 1;
  for (s=map; (s<map+filesize) && (*s!='\n'); ++s);		/* XXX */
  if (s>=map+filesize) goto done;
  realm=alloca(s-map+1);
  memmove(realm,map,s-map);
  realm[s-map]=0;
  ++s;
  auth=http_header(h,"Authorization");
  if (auth) {
    if (str_start(auth,"Basic ")) {
      char* username,* password;
      char* decoded;
      int i;
      unsigned long l,dl,ul;
      auth+=6;
      while (*auth==' ' || *auth=='\t') ++auth;
      i=str_chr(auth,'\n');
      if (i && auth[i-1]=='\r') --i;
      decoded=alloca(i+1);
      l=scan_base64(auth,decoded,&dl);
      if (auth[l]!='\n' && auth[l]!='\r') goto needauth;
      decoded[dl]=0;
      l=str_rchr(decoded,':');
      if (decoded[l]!=':') goto needauth;
      username=decoded; ul=l;
      decoded[l]=0; password=decoded+l+1;

      for (l=0; l<filesize; ) {
	while (l<filesize && map[l]!='\n') ++l; if (map[l]=='\n') ++l;
	if (l>=filesize) break;
	if (byte_equal(map+l,ul,username) && map[l+ul]==':') {
	  char* crypted=crypt(password,map+l+ul+1);
	  i=str_len(crypted);
	  if (l+ul+1+i <= filesize)
	    if (byte_equal(map+l+ul+1,i,crypted)) {
	      r=1;
	      goto done;
	    }
	}
      }
    }
  }
needauth:
  httperror_realm(h,"401 Authorization Required","Authorization required to view this web page",realm);
done:
  munmap(map,filesize);
  return r;
}
#endif

int64 http_openfile(struct http_data* h,char* filename,struct stat* ss,int sockfd) {
  char* dir=0;
  char* s;
  char* args;
  unsigned long i;
  int64 fd;
  int doesgzip,doesbzip2;

  char* Filename;

  doesgzip=0; doesbzip2=0; h->encoding=NORMAL;
  {
    char* tmp=http_header(h,"Accept-Encoding");
    if (tmp) {	/* yeah this is crude, but it gets the job done */
      int end=str_chr(tmp,'\n');
      for (i=0; i+4<end; ++i)
	if (byte_equal(tmp+i,4,"gzip"))
	  doesgzip=1;
	else if (byte_equal(tmp+i,4,"bzip2"))
	  doesbzip2=1;
    }
  }

  args=0;
  /* the file name needs to start with a / */
  if (filename[0]!='/') return -1;


  /* first, we need to strip "?.*" from the end */
  i=str_chr(filename,'?');
  Filename=alloca(i+5);	/* enough space for .gz and .bz2 */
  byte_copy(Filename,i+1,filename);
  if (Filename[i]=='?') { Filename[i]=0; args=filename+i+1; }
  /* second, we need to un-urlencode the file name */
  /* we can do it in-place, the decoded string can never be longer */
  scan_urlencoded2(Filename,Filename,&i);
  Filename[i]=0;
  /* third, change /. to /: so .procmailrc is visible in ls as
   * :procmailrc, and it also thwarts most web root escape attacks */
  for (i=0; Filename[i]; ++i)
    if (Filename[i]=='/' && Filename[i+1]=='.')
      Filename[i+1]=':';
  /* fourth, try to do some el-cheapo virtual hosting */
  if (!(s=http_header(h,"Host"))) {
    /* construct artificial Host header from IP */
    s=alloca(IP6_FMT+7);
    i=fmt_ip6c(s,h->myip);
    i+=fmt_str(s+i,":");
    i+=fmt_ulong(s+i,h->myport);
    s[i]=0;
  } else {
    if (virtual_hosts>=0) {
      char* tmp;
      int j=str_chr(s,'\r');
      /* replace port in Host: with actual port */
      if (!s[i=str_chr(s,':')] || i>j || !transproxy) {	/* add :port */
	if (i>j) i=j;
	tmp=alloca(i+7);
	byte_copy(tmp,i,s);
	tmp[i]=':'; ++i;
	i+=fmt_ulong(tmp+i,h->myport);
	tmp[i]=0;
	s=tmp;
      }
    }
  }
  fchdir(origdir);
  if (virtual_hosts>=0) {
    if (chdir(dir=s)==-1)
      if (chdir(dir="default")==-1)
	if (virtual_hosts==1)
	  return -1;
  }
  while (Filename[1]=='/') ++Filename;

#ifdef SUPPORT_HTACCESS
  if (http_dohtaccess(h)==0) return -5;
#endif

#ifdef SUPPORT_PROXY
  switch ((i=proxy_connection(sockfd,Filename,dir,h))) {
  case -3: break;
  case -1: return -1;
  default:
    if (i>=0) {
      h->buddy=i;
      return -3;
    }
  }
#else
  (void)sockfd;		/* shut up gcc warning about unused variable */
#endif
  if (Filename[(i=str_len(Filename))-1] == '/') {
    /* Damn.  Directory. */
    if (Filename[1] && chdir(Filename+1)==-1) return -1;
    h->mimetype="text/html";
    if (!open_for_reading(&fd,"index.html",ss)) {
      DIR* d;
      if (!directory_index) return -1;
      if (!(d=opendir("."))) return -1;
      if (!http_dirlisting(h,d,Filename,args)) return -1;
#ifdef USE_ZLIB
      if (doesgzip) {
	uLongf destlen=h->blen+30+h->blen/1000;
	char *compressed=malloc(destlen+15);
	if (!compressed) return -2;
	if (compress2(compressed+8,&destlen,h->bodybuf,h->blen,3)==Z_OK && destlen<h->blen) {
	  /* I am absolutely _not_ sure why this works, but we
	   * apparently have to ignore the first two and the last four
	   * bytes of the output of compress2.  I got this from googling
	   * for "compress2 header" and finding some obscure gzip
	   * integration in aolserver */
	  unsigned int crc=crc32(0,0,0);
	  crc=crc32(crc,h->bodybuf,h->blen);
	  free(h->bodybuf);
	  h->bodybuf=compressed;
	  h->encoding=GZIP;
	  byte_zero(compressed,10);
	  compressed[0]=0x1f; compressed[1]=0x8b;
	  compressed[2]=8; /* deflate */
	  compressed[3]=1; /* indicate ASCII */
	  compressed[9]=3; /* OS = Unix */
	  uint32_pack(compressed+10-2-4+destlen,crc);
	  uint32_pack(compressed+14-2-4+destlen,h->blen);
	  h->blen=destlen+18-2-4;
	} else {
	  free(compressed);
	}
      }
#endif
      return -2;
    }
    if (doesbzip2) {
      int64 gfd;
      if (open_for_reading(&gfd,"index.html.bz2",ss)) {
	io_close(fd);
	fd=gfd;
	h->encoding=BZIP2;
      }
    }
    if (doesgzip) {
      int64 gfd;
      if (open_for_reading(&gfd,"index.html.gz",ss)) {
	io_close(fd);
	fd=gfd;
	h->encoding=GZIP;
      }
    }
  } else {
    h->mimetype=mimetype(Filename);
    if (!open_for_reading(&fd,Filename+1,ss)) {
      if (errno==ENOENT) {
	char buf[2048];
	int i;
	if ((i=readlink(Filename+1,buf,sizeof(buf)))!=-1) {
	  buf[i]=0;
	  if (strstr(buf,"://")) {
	    h->bodybuf=malloc(strlen(buf)+300);
	    h->hdrbuf=malloc(strlen(buf)+300);
	    if (h->bodybuf && h->hdrbuf) {
	      int i;
	      i=fmt_str(h->bodybuf,"Look <a href=\"");
	      i+=fmt_str(h->bodybuf+i,buf);
	      i+=fmt_str(h->bodybuf+i,"\">here</a>!\n");
	      h->blen=i;

	      i=fmt_str(h->hdrbuf,"HTTP/1.0 301 Go Away\r\nConnection: ");
	      i+=fmt_str(h->hdrbuf+i,h->keepalive?"keep-alive":"close");
	      i+=fmt_str(h->hdrbuf+i,"\r\nServer: " RELEASE "\r\nContent-Length: ");
	      i+=fmt_ulong(h->hdrbuf+i,h->blen);
	      i+=fmt_str(h->hdrbuf+i,"\r\nLocation: ");
	      i+=fmt_str(h->hdrbuf+i,buf);
	      i+=fmt_str(h->hdrbuf+i,"\r\n\r\n");
	      h->hlen=i;
	      return -4;
	    }
	    free(h->bodybuf); free(h->hdrbuf);
	  }
	}
      }
      return -1;
    }
#ifdef DEBUG
    if (logging) {
      buffer_puts(buffer_1,"open_file ");
      buffer_putulong(buffer_1,sockfd);
      buffer_putspace(buffer_1);
      buffer_putulong(buffer_1,fd);
      buffer_putspace(buffer_1);
      buffer_puts(buffer_1,Filename);
      buffer_putnlflush(buffer_1);
    }
#endif
    if (doesgzip || doesbzip2) {
      int64 gfd;
      i=str_len(Filename);
      if (doesbzip2) {
	Filename[i+fmt_str(Filename+i,".bz2")]=0;
	if (open_for_reading(&gfd,Filename,ss)) {
	  io_close(fd);
	  fd=gfd;
	  h->encoding=BZIP2;
	}
      }
      if (doesgzip && h->encoding==NORMAL) {
	Filename[i+fmt_str(Filename+i,".gz")]=0;
	if (open_for_reading(&gfd,Filename,ss)) {
	  io_close(fd);
	  fd=gfd;
	  h->encoding=GZIP;
	}
      }
      Filename[i]=0;
    }
  }
  if (S_ISDIR(ss->st_mode)) {
    io_close(fd);
    return -1;
  }
  return fd;
}

int buffer_putlogstr(buffer* b,const char* s) {
  unsigned long l=str_len(s);
  char* x;
  for (l=0; s[l] && s[l]!='\r' && s[l]!='\n'; ++l) ;
  if (!l) return 0;
  x=alloca(l);
  return buffer_put(b,x,fmt_foldwhitespace(x,s,l));
}

void httpresponse(struct http_data* h,int64 s,long headerlen) {
  int head;
  int post;
  char* c;
  const char* m;
  time_t ims=0;
  uint64 range_first,range_last;
  h->filefd=-1;

  array_cat0(&h->r);
  c=array_start(&h->r);
  if (byte_diff(c,4,"GET ") && byte_diff(c,5,"POST ") && byte_diff(c,5,"HEAD ")) {
e400:
    httperror(h,"400 Invalid Request","This server only understands GET and HEAD.");

    if (logging) {
      char numbuf[FMT_ULONG];
      numbuf[fmt_ulong(numbuf,s)]=0;
      buffer_putmflush(buffer_1,"error_400 ",numbuf,"\n");
#if 0
      buffer_puts(buffer_1,"error_400 ");
      buffer_putulong(buffer_1,s);
      buffer_putsflush(buffer_1,"\n");
#endif
    }

  } else {
    char *d;
    int64 fd;
    struct stat ss;
    char* tmp;
    head=c[0]=='H';
    post=c[0]=='P';
    c+=(head||post)?5:4;
    for (d=c; *d!=' '&&*d!='\t'&&*d!='\n'&&*d!='\r'; ++d) ;
    if (*d!=' ') goto e400;
    *d=0;

    if ((m=http_header(h,"Connection"))) {
      if (!header_diff(m,"keep-alive"))
	h->keepalive=1;
      else
	h->keepalive=0;
    } else {
      if (byte_equal(d+1,8,"HTTP/1.0"))
	h->keepalive=0;
      else
	h->keepalive=1;
    }

    if (c[0]!='/') goto e404;
    fd=http_openfile(h,c,&ss,s);
    if (fd==-1) {
e404:
      httperror(h,"404 Not Found","No such file or directory.");

      if (logging) {
	char buf[IP6_FMT+10];
	int x;
	x=fmt_ip6c(buf,h->myip);
	x+=fmt_str(buf+x,"/");
	x+=fmt_ulong(buf+x,h->myport);
	buf[x]=0;
#ifdef SUPPORT_HTTPS
	if (h->t == HTTPSREQUEST)
	  buffer_puts(buffer_1,"HTTPS/");
#endif
	buffer_puts(buffer_1,head?"HEAD/404 ":post?"POST/404 ":"GET/404 ");
	buffer_putulong(buffer_1,s);
	buffer_puts(buffer_1," ");
	buffer_putlogstr(buffer_1,c);
	buffer_puts(buffer_1," 0 ");
	buffer_putlogstr(buffer_1,(tmp=http_header(h,"User-Agent"))?tmp:"[no_user_agent]");
	buffer_puts(buffer_1," ");
	buffer_putlogstr(buffer_1,(tmp=http_header(h,"Referer"))?tmp:"[no_referrer]");
	buffer_puts(buffer_1," ");
	buffer_putlogstr(buffer_1,(tmp=http_header(h,"Host"))?tmp:buf);
	buffer_putsflush(buffer_1,"\n");
      }

    } else {
      char* filename=c;
      if (fd==-4) {	/* redirect */
	iob_addbuf_free(&h->iob,h->hdrbuf,h->hlen);
	iob_addbuf_free(&h->iob,h->bodybuf,h->blen);
      } else if (fd==-5) {
	/* 401 -> log nothing. */
      } else if (fd==-2) {
	char* c;
	c=h->hdrbuf=(char*)malloc(250);
	if (!c)
	  httperror(h,"500 Sorry","Out of Memory.");
	else {

	  if (logging) {
	    char buf[IP6_FMT+10];
	    int x;
	    x=fmt_ip6c(buf,h->myip);
	    x+=fmt_str(buf+x,"/");
	    x+=fmt_ulong(buf+x,h->myport);
	    buf[x]=0;
#ifdef SUPPORT_HTTPS
	    if (h->t == HTTPSREQUEST)
	      buffer_puts(buffer_1,"HTTPS/");
#endif
	    buffer_puts(buffer_1,head?"HEAD ":"GET ");
	    buffer_putulong(buffer_1,s);
	    buffer_puts(buffer_1," ");
	    buffer_putlogstr(buffer_1,filename);
	    buffer_puts(buffer_1," ");
	    buffer_putulonglong(buffer_1,h->blen);
	    buffer_puts(buffer_1," ");
	    buffer_putlogstr(buffer_1,(tmp=http_header(h,"User-Agent"))?tmp:"[no_user_agent]");
	    buffer_puts(buffer_1," ");
	    buffer_putlogstr(buffer_1,(tmp=http_header(h,"Referer"))?tmp:"[no_referrer]");
	    buffer_puts(buffer_1," ");
	    buffer_putlogstr(buffer_1,(tmp=http_header(h,"Host"))?tmp:buf);
	    buffer_putsflush(buffer_1,"\n");
	  }

	  c+=fmt_str(c,"HTTP/1.1 200 Here you go\r\nContent-Type: text/html\r\nConnection: ");
	  c+=fmt_str(c,h->keepalive?"keep-alive":"close");
	  c+=fmt_str(c,"\r\nServer: " RELEASE "\r\nContent-Length: ");
	  c+=fmt_ulong(c,h->blen);
	  if (h->encoding!=NORMAL) {
	    c+=fmt_str(c,"\r\nContent-Encoding: ");
	    c+=fmt_str(c,h->encoding==GZIP?"gzip":"bzip2");
	  }
	  c+=fmt_str(c,"\r\n\r\n");
	  h->hlen=c-h->hdrbuf;
	  iob_addbuf_free(&h->iob,h->hdrbuf,h->hlen);
	  if (head)
	    free(h->bodybuf);
	  else
	    iob_addbuf_free(&h->iob,h->bodybuf,h->blen);
	}
#ifdef SUPPORT_PROXY
      } else if (fd==-3) {
	struct http_data* x=io_getcookie(h->buddy);
	if (x) {
	  char *c=array_start(&h->r);
	  c[str_len(c)]=' ';
	  array_catb(&x->r,array_start(&h->r),headerlen);
	}
	io_dontwantread(s);
	return;
#endif
      } else {
#ifdef DEBUG
	if (logging) {
	  buffer_puts(buffer_1,"filefd ");
	  buffer_putulong(buffer_1,s);
	  buffer_putspace(buffer_1);
	  buffer_putulong(buffer_1,fd);
	  buffer_putnlflush(buffer_1);
	}
#endif
	h->filefd=fd;
	range_first=0; range_last=ss.st_size;
	if ((c=http_header(h,"If-Modified-Since")))
	  if ((unsigned char)(c[scan_httpdate(c,&ims)])>' ')
	    ims=0;
	if ((c=http_header(h,"Range"))) {
	  if (byte_equal(c,6,"bytes=")) {
	    int i;
	    c+=6;
	    if ((i=scan_ulonglong(c,&range_first))) {
	      c+=i;
	      if (*c=='-' && c[1]) {
		++c;
		if ((i=scan_ulonglong(c,&range_last))) {
		  if (!i) goto rangeerror;
		  ++range_last;
		}
	      }
	    } else {
rangeerror:
#ifdef DEBUG
	      if (logging) {
		buffer_puts(buffer_1,"bad_range_close ");
		buffer_putulong(buffer_1,s);
		buffer_putspace(buffer_1);
		buffer_putulong(buffer_1,fd);
		buffer_putnlflush(buffer_1);
	      }
#endif
	      io_close(h->filefd); h->filefd=-1;
	      httperror(h,"416 Bad Range","The requested range can not be satisfied.");
	      goto fini;
	    }
	  }
	}
	if (range_last<range_first) {
	  /* rfc2616, page 123 */
	  range_first=0; range_last=ss.st_size;
	}
	if (range_last>ss.st_size) range_last=ss.st_size;

	c=h->hdrbuf=(char*)malloc(500);
	if (ss.st_mtime<=ims) {
	  c+=fmt_str(c,"HTTP/1.1 304 Not Changed");
	  head=1;
	  io_close(fd); fd=-1;
	} else
	  if (range_first || range_last!=ss.st_size)
	    c+=fmt_str(c,"HTTP/1.1 206 Partial Content");
	  else
	    c+=fmt_str(c,"HTTP/1.1 200 Coming Up");

	c+=fmt_str(c,"\r\nContent-Type: ");
	c+=fmt_str(c,h->mimetype);
	c+=fmt_str(c,"\r\nServer: " RELEASE "\r\nContent-Length: ");
	c+=fmt_ulonglong(c,range_last-range_first);
	c+=fmt_str(c,"\r\nLast-Modified: ");
	c+=fmt_httpdate(c,ss.st_mtime);
	if (h->encoding!=NORMAL) {
	  c+=fmt_str(c,"\r\nContent-Encoding: ");
	  c+=fmt_str(c,h->encoding==GZIP?"gzip":"bzip2");
	}
	if (range_first || range_last!=ss.st_size) {
	  c+=fmt_str(c,"\r\nContent-Range: bytes ");
	  c+=fmt_ulonglong(c,range_first);
	  c+=fmt_str(c,"-");
	  c+=fmt_ulonglong(c,range_last-1);
	  c+=fmt_str(c,"/");
	  c+=fmt_ulonglong(c,ss.st_size);
	}
	if (range_first>ss.st_size) {
	  free(c);
	  httperror(h,"416 Bad Range","The requested range can not be satisfied.");
	  buffer_puts(buffer_1,"error_416 ");
	} else {
	  c+=fmt_str(c,"\r\nConnection: ");
	  c+=fmt_str(c,h->keepalive?"keep-alive":"close");
	  c+=fmt_str(c,"\r\n\r\n");
	  iob_addbuf_free(&h->iob,h->hdrbuf,c - h->hdrbuf);
	  if (!head)
	    iob_addfile_close(&h->iob,fd,range_first,range_last-range_first);
	  else
	    if (fd!=-1) io_close(fd);
	  if (logging) {
	    if (h->hdrbuf[9]=='3') {
	      buffer_puts(buffer_1,head?"HEAD/304 ":"GET/304 ");
	    } else {
	      buffer_puts(buffer_1,head?"HEAD ":"GET ");
	    }
	  }
	}

	if (logging) {
	  char buf[IP6_FMT+10];
	  int x;
	  x=fmt_ip6c(buf,h->myip);
	  x+=fmt_str(buf+x,"/");
	  x+=fmt_ulong(buf+x,h->myport);
	  buf[x]=0;
	  buffer_putulong(buffer_1,s);
	  buffer_puts(buffer_1," ");
	  buffer_putlogstr(buffer_1,filename);
	  switch (h->encoding) {
	  case GZIP: buffer_puts(buffer_1,".gz"); break;
	  case BZIP2: buffer_puts(buffer_1,".bz2");
	  case NORMAL: break;
	  }
	  buffer_puts(buffer_1," ");
	  buffer_putulonglong(buffer_1,range_last-range_first);
	  buffer_puts(buffer_1," ");
	  buffer_putlogstr(buffer_1,(tmp=http_header(h,"User-Agent"))?tmp:"[no_user_agent]");
	  buffer_puts(buffer_1," ");
	  buffer_putlogstr(buffer_1,(tmp=http_header(h,"Referer"))?tmp:"[no_referrer]");
	  buffer_puts(buffer_1," ");
	  buffer_putlogstr(buffer_1,(tmp=http_header(h,"Host"))?tmp:buf);
	  buffer_putsflush(buffer_1,"\n");
	}
      }
    }
  }
fini:
  io_dontwantread(s);
  io_wantwrite(s);
}


#ifdef SUPPORT_FTP
/*
  __ _
 / _| |_ _ __
| |_| __| '_ \
|  _| |_| |_) |
|_|  \__| .__/
        |_|
*/

static int ftp_vhost(struct http_data* h) {
  char* y;
  int i;

  /* construct artificial Host header from IP */
  y=alloca(IP6_FMT+7);
  i=fmt_ip6c(y,h->myip);
  i+=fmt_str(y+i,":");
  i+=fmt_ulong(y+i,h->myport);
  y[i]=0;

  fchdir(origdir);
  if (virtual_hosts>=0) {
    if (chdir(y)==-1)
      if (chdir("default")==-1)
	if (virtual_hosts==1) {
	  h->hdrbuf="425 no such virtual host.\r\n";
	  return -1;
	}
  }
  return 0;
}

static int ftp_open(struct http_data* h,const char* s,int forreading,int sock,const char* what,struct stat* ss) {
  int l=h->ftppath?str_len(h->ftppath):0;
  char* x=alloca(l+str_len(s)+5);
  char* y;
  int64 fd;

  /* first, append to path */
  if (s[0]!='/' && h->ftppath)
    y=x+fmt_str(x,h->ftppath);
  else
    y=x;
  y+=fmt_str(y,"/");
  y+=fmt_str(y,s);
  if (y[-1]=='\n') --y;
  if (y[-1]=='\r') --y;
  *y=0;

  /* now reduce "//" and "/./" and "/[^/]+/../" to "/" */
  l=canonpath(x);

  if (ftp_vhost(h)) return -1;

  errno=0; fd=-1;
  h->hdrbuf=forreading?"550 No such file or directory.\r\n":"550 Uploading not permitted here!\r\n";
  if (x[1]) {
    switch (forreading) {
    case 1: open_for_reading(&fd,x+1,ss); break;
    case 0: open_for_writing(&fd,x+1); break;
    case 2: fd=mkdir(x+1,0777);
	    if (!fd) chmod(x+1,0777);
	    break;
    }
  }
#ifdef DEBUG
  if (forreading<2)
    if (logging) {
      buffer_puts(buffer_1,"ftp_open_file ");
      buffer_putulong(buffer_1,sock);
      buffer_putspace(buffer_1);
      buffer_putulong(buffer_1,fd);
      buffer_putspace(buffer_1);
      buffer_puts(buffer_1,x+1);
      buffer_putnlflush(buffer_1);
    }
#endif

  if (logging && what) {
    buffer_puts(buffer_1,what);
    if (fd==-1) buffer_puts(buffer_1,"/404");
    buffer_putspace(buffer_1);
    buffer_putulong(buffer_1,sock);
    buffer_putspace(buffer_1);
    buffer_putlogstr(buffer_1,x[1]?x:"/");
    buffer_putspace(buffer_1);
  }
  return fd;
}

static int ftp_retrstor(struct http_data* h,const char* s,int64 sock,int forwriting) {
  uint64 range_first,range_last;
  struct stat ss;
  struct http_data* b;

  char buf[IP6_FMT+10];
  int x;
  x=fmt_ip6c(buf,h->myip);
  x+=fmt_str(buf+x,"/");
  x+=fmt_ulong(buf+x,h->myport);
  buf[x]=0;

  if (h->buddy==-1 || !(b=io_getcookie(h->buddy))) {
    h->hdrbuf="425 Could not establish data connection.\r\n";
    return -1;
  }
  if (b->filefd!=-1) { io_close(b->filefd); b->filefd=-1; }
  b->filefd=ftp_open(h,s,forwriting^1,sock,forwriting?"STOR":"RETR",&ss);
  if (forwriting) ss.st_size=0;
  if (b->filefd==-1) {
    if (logging) {
      buffer_putulonglong(buffer_1,0);
      buffer_putspace(buffer_1);
      buffer_putlogstr(buffer_1,buf);
      buffer_putnlflush(buffer_1);
    }
    return -1;
  }

  if (!forwriting) {
    if (fstat(b->filefd,&ss)==-1)
      range_last=0;
    else
      range_last=ss.st_size;
    range_first=h->ftp_rest; h->ftp_rest=0;
    if (range_first>range_last) range_first=range_last;
    iob_addfile_close(&b->iob,b->filefd,range_first,range_last-range_first);
    if (logging) {
      buffer_putulonglong(buffer_1,range_last-range_first);
      buffer_putspace(buffer_1);
    }
  }

  if (logging) {
    buffer_putlogstr(buffer_1,buf);
    buffer_putnlflush(buffer_1);
  }

  h->f=WAITCONNECT;
  h->hdrbuf=malloc(100);
  b->f=forwriting?UPLOADING:DOWNLOADING;
  if (!h->hdrbuf) {
    h->hdrbuf=(b->t==FTPSLAVE)?"125 go on\r\n":"150 go on\r\n";
    return -1;
  } else {
    int i;
    if (b->t==FTPSLAVE) {
      i=fmt_str(h->hdrbuf,"125 go on (");
      if (forwriting)
	io_wantread(h->buddy);
      else
	io_wantwrite(h->buddy);
      h->f=LOGGEDIN;
    } else if (b->t==FTPACTIVE)
      i=fmt_str(h->hdrbuf,"150 connecting (");
    else
      i=fmt_str(h->hdrbuf,"150 listening (");
    if (forwriting)
      i+=fmt_str(h->hdrbuf+i,"for upload)\r\n");
    else {
      i+=fmt_ulonglong(h->hdrbuf+i,ss.st_size);
      i+=fmt_str(h->hdrbuf+i," bytes)\r\n");
    }
    h->hdrbuf[i]=0;
  }

  return 0;
}

static int ftp_mdtm(struct http_data* h,const char* s) {
  struct stat ss;
  int fd;
  int i;
  struct tm* t;
  if ((fd=ftp_open(h,s,1,0,0,&ss))==-1) return -1;
  io_close(fd);
  t=gmtime(&ss.st_mtime);
  h->hdrbuf=malloc(100);
  if (!h->hdrbuf) {
    h->hdrbuf="500 out of memory\r\n";
    return -1;
  }
  i=fmt_str(h->hdrbuf,"213 ");
  i+=fmt_2digits(h->hdrbuf+i,(t->tm_year+1900)/100);
  i+=fmt_2digits(h->hdrbuf+i,(t->tm_year+1900)%100);
  i+=fmt_2digits(h->hdrbuf+i,t->tm_mon+1);
  i+=fmt_2digits(h->hdrbuf+i,t->tm_mday);
  i+=fmt_2digits(h->hdrbuf+i,t->tm_hour);
  i+=fmt_2digits(h->hdrbuf+i,t->tm_min);
  i+=fmt_2digits(h->hdrbuf+i,t->tm_sec);
  i+=fmt_str(h->hdrbuf+i,"\r\n");
  h->hdrbuf[i]=0;
  return 0;
}

static int ftp_size(struct http_data* h,const char* s) {
  struct stat ss;
  int fd;
  int i;
  if ((fd=ftp_open(h,s,1,0,0,&ss))==-1) return -1;
  io_close(fd);
  h->hdrbuf=malloc(100);
  if (!h->hdrbuf) {
    h->hdrbuf="500 out of memory\r\n";
    return -1;
  }
  i=fmt_str(h->hdrbuf,"213 ");
  i+=fmt_ulonglong(h->hdrbuf+i,ss.st_size);
  i+=fmt_str(h->hdrbuf+i,"\r\n");
  h->hdrbuf[i]=0;
  return 0;
}


static void ftp_ls(array* x,const char* s,const struct stat* const ss,time_t now,const char* pathprefix) {
  char buf[2048];
  int i,j;
  struct tm* t;
  {
    int i,m=ss->st_mode;
    for (i=0; i<10; ++i) buf[i]='-';
    if (S_ISDIR(m)) buf[0]='d'; else
    if (S_ISLNK(m)) buf[0]='l';	/* other specials not supported */
    if (m&S_IRUSR) buf[1]='r';
    if (m&S_IWUSR) buf[2]='w';
    if (m&S_IXUSR) buf[3]='x';
    if (m&S_IRGRP) buf[4]='r';
    if (m&S_IWGRP) buf[5]='w';
    if (m&S_IXGRP) buf[6]='x';
    if (m&S_IROTH) buf[7]='r';
    if (m&S_IWOTH) buf[8]='w';
    if (m&S_IXOTH) buf[9]='x';
    buf[10]=' ';
  }
  array_catb(x,buf,11);

  i=j=fmt_ulong(buf,ss->st_nlink);
  if (i<3) j=3;
  array_catb(x,buf+100,fmt_pad(buf+100,buf,i,j,j));
  array_cats(x," root     root     ");

  buf[i=fmt_ulonglong(buf,ss->st_size)]=' ';
  j=++i; if (i<8) j=8;
  array_catb(x,buf+100,fmt_pad(buf+100,buf,i,j,j));

  {
    t=localtime(&ss->st_mtime);
    array_catb(x,months+3*t->tm_mon,3);
    array_cats(x," ");
    array_catb(x,buf,fmt_2digits(buf,t->tm_mday));
    array_cats(x," ");
    if (ss->st_mtime<=now && ss->st_mtime>=now-60*60*12*356) {
      array_catb(x,buf,fmt_2digits(buf,t->tm_hour));
      array_cats(x,":");
      array_catb(x,buf,fmt_2digits(buf,t->tm_min));
    } else {
      array_cats(x," ");
      array_catb(x,buf,fmt_ulong0(buf,t->tm_year+1900,4));
    }
  }
  array_cats(x," ");
  array_cats(x,pathprefix);
  array_cats(x,s);
  if (S_ISLNK(ss->st_mode)) {
    array_cats(x," -> ");
    array_cats(x,readlink(s,buf,sizeof(buf))?"[error]":buf);
  }
  array_cats(x,"\r\n");
}

static int ftp_list(struct http_data* h,char* s,int _long,int sock) {
  int i,l=h->ftppath?str_len(h->ftppath):0;
  char* x=alloca(l+str_len(s)+5);
  char* y;
  DIR* D;
  struct dirent* d;
  int rev=0;
  int what=0;
  time_t now;

  char* pathprefix="";
  char* match=0;

  unsigned long o,n;
  int (*sortfun)(de*,de*);
  array a,b,c;
  de* ab;

  if (h->buddy==-1 || !io_getcookie(h->buddy)) {
    h->hdrbuf="425 Could not establish data connection\r\n";
    return -1;
  }

  i=str_len(s);
  if (i>1) {
    if (s[i-1]=='\n') --i;
    if (s[i-1]=='\r') --i;
    s[i]=0;
  }

  byte_zero(&a,sizeof(a));
  byte_zero(&b,sizeof(b));
  byte_zero(&c,sizeof(c));
  o=n=0;

  if (s[0]=='-') {
    for (++s; *s && *s!=' '; ++s) {
      switch (*s) {
      case 'l': _long=1; break;
      case 'r': rev=1; break;
      case 'S': what=1; break;
      case 't': what=2; break;
      }
    }
    while (*s==' ') ++s;
  }
  {
    switch (what) {
    case 1: sortfun=rev?sort_size_a:sort_size_d; break;
    case 2: sortfun=rev?sort_mtime_a:sort_mtime_d; break;
    default: sortfun=rev?sort_name_d:sort_name_a; break;
    }
  }

  /* first, append to path */
  if (h->ftppath && s[0]!='/')
    y=x+fmt_str(x,h->ftppath);
  else
    y=x;
  y+=fmt_str(y,"/");
  y+=fmt_str(y,s);
  if (y[-1]=='\n') --y;
  if (y[-1]=='\r') --y;
  *y=0;

  /* now reduce "//" and "/./" and "/[^/]+/../" to "/" */
  l=canonpath(x);

  if (ftp_vhost(h)) return 0;

  /* cases:
   *   it's a directory
   *     -> opendir(foo/bar), ...
   *   foo/$fnord
   *     -> pathprefix="foo/"; chdir(foo); opendir(...); fnmatch($fnord)
   *   /pub/$fnord
   *     -> pathprefix="/pub/"; chdir(/pub); opendir(...); fnmatch($fnord)
   */

  if (!x[1] || chdir(x+1)==0) {		/* it's a directory */
    pathprefix="";
    match=0;
  } else {
    if (s[0]!='/') {	/* foo/$fnord */
      int z=str_rchr(s,'/');
      if (s[z]!='/') {
	pathprefix="";
	match=s;
      } else {
	pathprefix=alloca(z+2);
	byte_copy(pathprefix,z,s);
	pathprefix[z]='/';
	pathprefix[z+1]=0;
	match=0;
	z=str_rchr(x,'/');
	x[z]=0;
	if (x[0]=='/' && x[1] && chdir(x+1)==-1) {
notfound:
	  h->hdrbuf="450 no such file or directory.\r\n";
	  return -1;
	}
	x[z]='/';
	match=x+z+1;
      }
    } else {		/* /pub/$fnord */
      int z=str_rchr(x,'/');
      x[z]=0;
      if (x[0]=='/' && x[1] && chdir(x+1)==-1) goto notfound;
      match=x+z+1;
      pathprefix=alloca(z+2);
      byte_copy(pathprefix,z,x);
      pathprefix[z]='/';
      pathprefix[z+1]=0;
    }
  }

  D=opendir(".");
  if (!D)
    goto notfound;
  else {
    while ((d=readdir(D))) {
      de* X=array_allocate(&a,sizeof(de),n);
      if (!X) break;
      X->name=o;
      if (lstat(d->d_name,&X->ss)==-1) continue;
      if (!match || fnmatch(match,d->d_name,FNM_PATHNAME)==0) {
	array_cats0(&b,d->d_name);
	o+=str_len(d->d_name)+1;
	++n;
      }
    }
    closedir(D);
  }
  if (array_failed(&a) || array_failed(&b)) {
    array_reset(&a);
    array_reset(&b);
nomem:
    h->hdrbuf="500 out of memory\r\n";
    return -1;
  }
  base=array_start(&b);
  qsort(array_start(&a),n,sizeof(de),(int(*)(const void*,const void*))sortfun);

  ab=array_start(&a);
  now=time(0);
  for (i=0; i<n; ++i) {
    char* name=base+ab[i].name;

    if (name[0]=='.') {
      if (name[1]==0) continue; /* skip "." */
      if (name[1]!='.' || name[2]!=0)	/* skip dot-files */
	continue;
    }
    if (_long)
      ftp_ls(&c,name,&ab[i].ss,now,pathprefix);
    else {
      array_cats(&c,pathprefix);
      array_cats(&c,name);
      array_cats(&c,"\r\n");
    }
  }
  array_reset(&a);
  array_reset(&b);
  if (array_failed(&c)) goto nomem;
  if (array_bytes(&c)==0) {
    h->hdrbuf="450 no match\r\n";
    return -1;
  } else {
    struct http_data* b=io_getcookie(h->buddy);
    assert(b);
    if (b) {
      iob_addbuf_free(&b->iob,array_start(&c),array_bytes(&c));
      b->f=DOWNLOADING;
      h->f=WAITCONNECT;
      if (b->t==FTPSLAVE) {
	h->hdrbuf="125 go on\r\n";
	io_wantwrite(h->buddy);
	h->f=LOGGEDIN;
      } else if (b->t==FTPACTIVE)
	h->hdrbuf="150 connecting\r\n";
      else
	h->hdrbuf="150 I'm listening\r\n";
    }
  }
  if (logging) {
    buffer_puts(buffer_1,_long?"LIST ":"NLST ");
    buffer_putulong(buffer_1,sock);
    buffer_putspace(buffer_1);
    buffer_putlogstr(buffer_1,x[1]?x:"/");
    buffer_putspace(buffer_1);
    buffer_putulong(buffer_1,array_bytes(&c));
    buffer_putspace(buffer_1);
    {
      char buf[IP6_FMT+10];
      int x;
      x=fmt_ip6c(buf,h->peerip);
      x+=fmt_str(buf+x,"/");
      x+=fmt_ulong(buf+x,h->peerport);
      buffer_put(buffer_1,buf,x);
    }
    buffer_putnlflush(buffer_1);
  }
  return 0;
}

static int ftp_cwd(struct http_data* h,char* s) {
  int l=h->ftppath?str_len(h->ftppath):0;
  char* x=alloca(l+str_len(s)+5);
  char* y;
  /* first, append to path */
  if (s[0]!='/' && h->ftppath)
    y=x+fmt_str(x,h->ftppath);
  else
    y=x;
  y+=fmt_str(y,"/");
  y+=fmt_str(y,s);
  if (y[-1]=='\n') --y;
  if (y[-1]=='\r') --y;
  *y=0;

  /* now reduce "//" and "/./" and "/[^/]+/../" to "/" */
  l=canonpath(x);

  if (ftp_vhost(h))
    return -1;

  if (x[1] && chdir(x+1)) {
    h->hdrbuf="525 directory not found.\r\n";
    return -1;
  }
  y=realloc(h->ftppath,l+1);
  if (!y) {
    h->hdrbuf="500 out of memory.\r\n";
    return -1;
  }
  y[fmt_str(y,x)]=0;
  h->ftppath=y;
  h->hdrbuf="250 ok.\r\n";
  return 0;
}

static int ftp_mkdir(struct http_data* h,const char* s) {
  if (ftp_open(h,s,2,0,"mkdir",0)==-1) return -1;
  h->hdrbuf="257 directory created.\r\n";
  return 0;
}

void ftpresponse(struct http_data* h,int64 s) {
  char* c;
  h->filefd=-1;

  c=array_start(&h->r);
  {
    char* d,* e=c+array_bytes(&h->r);

/*    write(1,c,e-c); */

    for (d=c; d<e; ++d) {
      if (*d=='\n') {
	if (d>c && d[-1]=='\r') --d;
	*d=0;
	break;
      }
      if (*d==0) *d='\n';
    }
  }
  if (case_equals(c,"QUIT")) {
    h->hdrbuf="221 Goodbye.\r\n";
    h->keepalive=0;
  } else if (case_equals(c,"ABOR") ||
	     case_equals(c,"\xff\xf4\xff\xf2""ABOR") ||
	     case_equals(c,"\xff\xf4\xff""ABOR")) {
    /* for some reason, on Linux 2.6 the trailing \xf2 sometimes does
     * not arrive although it is visible in the tcpdump */
    if (h->buddy==-1)
      h->hdrbuf="226 Ok.\r\n";
    else {
      io_close(h->buddy);
      h->buddy=-1;
      h->hdrbuf="426 Ok.\r\n226 Connection closed.\r\n";
    }
  } else if (case_starts(c,"USER ")) {
    c+=5;
    if (case_equals(c,"ftp") || case_equals(c,"anonymous")) {
      if (askforpassword)
	h->hdrbuf="331 User name OK, please use your email address as password.\r\n";
      else
	h->hdrbuf="230 No need for passwords, you're logged in now.\r\n";
    } else {
      if (askforpassword)
	h->hdrbuf="230 I only serve anonymous users.  But I'll make an exception.\r\n";
      else
	h->hdrbuf="331 I only serve anonymous users.  But I'll make an exception.\r\n";
    }
    h->f=LOGGEDIN;
  } else if (case_starts(c,"PASS ")) {
    h->hdrbuf="230 If you insist...\r\n";
  } else if (case_starts(c,"TYPE ")) {
    h->hdrbuf="200 yeah, whatever.\r\n";
  } else if (case_equals(c,"PASV") || case_equals(c,"EPSV")) {
    int epsv=(*c=='e' || *c=='E');
    char ip[16];
    uint16 port;
#ifdef __broken_itojun_v6__
#warning fixme
#endif
    if (h->buddy!=-1) {
      if (logging) {
	buffer_puts(buffer_1,"close/olddataconn ");
	buffer_putulong(buffer_1,h->buddy);
	buffer_putnlflush(buffer_1);
      }
      io_close(h->buddy);
    }
    h->buddy=socket_tcp6();
    if (h->buddy==-1) {
      h->hdrbuf="425 socket() failed.\r\n";
      goto ABEND;
    }
    io_nonblock(h->buddy);
    if (socket_bind6_reuse(h->buddy,h->myip,0,h->myscope_id)==-1) {
closeandgo:
      io_close(h->buddy);
      h->hdrbuf="425 socket error.\r\n";
      goto ABEND;
    }
    if (socket_local6(h->buddy,ip,&port,0)==-1) goto closeandgo;
    if (!(h->hdrbuf=malloc(100))) goto closeandgo;
    if (epsv==0) {
      c=h->hdrbuf+fmt_str(h->hdrbuf,"227 Passive Mode OK (");
      {
	int i;
	for (i=0; i<4; ++i) {
	  c+=fmt_ulong(c,h->myip[12+i]);
	  c+=fmt_str(c,",");
	}
      }
      c+=fmt_ulong(c,(port>>8)&0xff);
      c+=fmt_str(c,",");
      c+=fmt_ulong(c,port&0xff);
      c+=fmt_str(c,")\r\n");
    } else {
      c=h->hdrbuf+fmt_str(h->hdrbuf,"229 Passive Mode OK (|||");
      c+=fmt_ulong(c,port);
      c+=fmt_str(c,"|)\r\n");
    }
    *c=0;
    if (io_fd(h->buddy)) {
      struct http_data* x=malloc(sizeof(struct http_data));
      if (!x) {
freecloseabort:
	free(h->hdrbuf);
	c=0;
	goto closeandgo;
      }
      byte_zero(x,sizeof(struct http_data));
      x->buddy=s; x->filefd=-1;
      x->t=FTPPASSIVE;
      io_setcookie(h->buddy,x);
      socket_listen(h->buddy,1);
      io_wantread(h->buddy);
      if (logging) {
	buffer_puts(buffer_1,epsv?"epsv_listen ":"pasv_listen ");
	buffer_putulong(buffer_1,s);
	buffer_putspace(buffer_1);
	buffer_putulong(buffer_1,h->buddy);
	buffer_putspace(buffer_1);
	buffer_putulong(buffer_1,port);
	buffer_putnlflush(buffer_1);
      }
    } else
      goto freecloseabort;
  } else if (case_starts(c,"PORT ") || case_starts(c,"EPRT ")) {
    int eprt=(*c=='e' || *c=='E');
    char ip[16];
    uint16 port;
#ifdef __broken_itojun_v6__
#warning fixme
#endif
    if (h->buddy!=-1) {
      if (logging) {
	buffer_puts(buffer_1,"close/olddataconn ");
	buffer_putulong(buffer_1,h->buddy);
	buffer_putnlflush(buffer_1);
      }
      io_close(h->buddy);
      h->buddy=-1;
    }
    c+=5;
    if (eprt) {
      /* |1|10.0.0.4|1025| or @2@::1@1026@ */
      char sep;
      int i;
      if (!(sep=*c)) goto syntaxerror;
      if (c[2]!=sep) goto syntaxerror;
      if (c[1]=='1') {
	byte_copy(ip,12,V4mappedprefix);
	if (c[3+(i=scan_ip4(c+3,ip+12))]!=sep || !i) goto syntaxerror;
      } else if (c[1]=='2') {
	if (c[3+(i=scan_ip6(c+3,ip))]!=sep || !i) goto syntaxerror;
      } else goto syntaxerror;
      c+=i+4;
      if (c[i=scan_ushort(c,&port)]!=sep || !i) goto syntaxerror;
    } else {
      /* 10,0,0,1,4,1 -> 10.0.0.1:1025 */
      unsigned long l;
      int r,i;
      for (i=0; i<4; ++i) {
	if (c[r=scan_ulong(c,&l)]!=',' || l>255) {
syntaxerror:
	  h->hdrbuf="501 Huh?  What?!  Where am I?\r\n";
	  goto ABEND;
	}
	c+=r+1;
	ip[12+i]=l;
	byte_copy(ip,12,V4mappedprefix);
      }
      if (c[r=scan_ulong(c,&l)]!=',' || l>255) goto syntaxerror;
      c+=r+1;
      port=l<<8;
      r=scan_ulong(c,&l); if (l>255) goto syntaxerror;
      port+=l;
    }
    h->buddy=socket_tcp6();
    if (h->buddy==-1) {
      h->hdrbuf="425 socket() failed.\r\n";
      goto ABEND;
    }
    io_nonblock(h->buddy);
    if (byte_diff(h->peerip,16,ip)) {
      h->hdrbuf="425 Sorry, but I will only connect back to your own IP.\r\n";
      io_close(h->buddy);
      goto ABEND;
    }
    h->hdrbuf="200 Okay, go ahead.\r\n";
    if (io_fd(h->buddy)) {
      struct http_data* x=malloc(sizeof(struct http_data));
      if (!x) goto closeandgo;
      byte_zero(x,sizeof(struct http_data));
      x->buddy=s; x->filefd=-1;
      x->t=FTPACTIVE;
      x->destport=port;
      byte_copy(x->peerip,16,ip);

      io_setcookie(h->buddy,x);
    } else
      goto closeandgo;

    socket_connect6(h->buddy,ip,port,h->myscope_id);

    if (logging) {
      buffer_puts(buffer_1,eprt?"eprt ":"port ");
      buffer_putulong(buffer_1,s);
      buffer_putspace(buffer_1);
      buffer_putulong(buffer_1,h->buddy);
      buffer_putspace(buffer_1);
      buffer_putulong(buffer_1,port);
      buffer_putnlflush(buffer_1);
    }
    io_dontwantread(h->buddy);
    io_wantwrite(h->buddy);
  } else if (case_equals(c,"PWD") || case_equals(c,"XPWD") /* fsck windoze */) {
    c=h->ftppath; if (!c) c="/";
    h->hdrbuf=malloc(50+str_len(c));
    if (h->hdrbuf) {
      c=h->hdrbuf;
      c+=fmt_str(c,"257 \"");
      c+=fmt_str(c,h->ftppath?h->ftppath:"/");
      c+=fmt_str(c,"\" \r\n");
      *c=0;
    } else
      h->hdrbuf="500 out of memory\r\n";
  } else if (case_starts(c,"CWD ")) {
    ftp_cwd(h,c+4);
  } else if (case_equals(c,"CDUP") || case_equals(c,"XCUP")) {
    ftp_cwd(h,"..");
  } else if (case_starts(c,"MDTM ")) {
    c+=5;
    if (ftp_mdtm(h,c)==0)
      c=h->hdrbuf;
  } else if (case_starts(c,"SIZE ")) {
    c+=5;
    if (ftp_size(h,c)==0)
      c=h->hdrbuf;
  } else if (case_starts(c,"MKD ")) {
    c+=4;
    ftp_mkdir(h,c);
  } else if (case_equals(c,"FEAT")) {
    h->hdrbuf="211-Features:\r\n MDTM\r\n REST STREAM\r\n SIZE\r\n211 End\r\n";
  } else if (case_equals(c,"SYST")) {
    h->hdrbuf="215 UNIX Type: L8\r\n";
  } else if (case_starts(c,"REST ")) {
    uint64 x;
    c+=5;
    if (!c[scan_ulonglong(c,&x)]) {
      h->hdrbuf="350 ok.\r\n";
      h->ftp_rest=x;
    } else
      h->hdrbuf="501 invalid number\r\n";
  } else if (case_starts(c,"RETR ")) {
    c+=5;
    if (ftp_retrstor(h,c,s,0)==0)
      c=h->hdrbuf;
  } else if (case_starts(c,"STOR ")) {
    if (nouploads)
      h->hdrbuf="553 no upload allowed here.\r\n";
    else {
      c+=5;
      if (ftp_retrstor(h,c,s,1)==0)
	c=h->hdrbuf;
    }
  } else if (case_starts(c,"LIST")) {
    c+=4;
    if (*c==' ') ++c;
    ftp_list(h,c,1,s);
  } else if (case_starts(c,"NLST")) {
    c+=4;
    if (*c==' ') ++c;
    ftp_list(h,c,0,s);
  } else if (case_equals(c,"NOOP")) {
    h->hdrbuf="200 no reply.\r\n";
  } else if (case_starts(c,"HELP")) {
    h->hdrbuf="214-This is gatling (www.fefe.de/gatling/); No help available.\r\n214 See http://cr.yp.to/ftp.html for FTP help.\r\n";
  } else {
    static int funny;
    switch (++funny) {
    case 1: h->hdrbuf="550 The heck you say.\r\n"; break;
    case 2: h->hdrbuf="550 No, really?\r\n"; break;
    case 3: h->hdrbuf="550 Yeah, whatever...\r\n"; break;
    case 4: h->hdrbuf="550 How intriguing!\r\n"; break;
    default: h->hdrbuf="550 I'm just a simple FTP server, you know?\r\n"; funny=0; break;
    }
  }
ABEND:
  {
    char* d=array_start(&h->r);
    if (c>=d && c<=d+array_bytes(&h->r))
      iob_addbuf(&h->iob,h->hdrbuf,str_len(h->hdrbuf));
    else
      iob_addbuf_free(&h->iob,h->hdrbuf,str_len(h->hdrbuf));
  }
  io_dontwantread(s);
  io_wantwrite(s);
}

#endif /* SUPPORT_FTP */


#ifdef SUPPORT_SMB

#if 0
               _
 ___ _ __ ___ | |__
/ __| '_ ` _ \| '_ \
\__ \ | | | | | |_) |
|___/_| |_| |_|_.__/
#endif

static uint16 mksmbdate(int day,int month,int year) {
  return (year<<(5+4)) + (month<<5) + day;
}

static uint16 mksmbtime(int h,int m,int s) {
  return (h<<(5+6)) + (m<<5) + (s>>1);
}


struct smbheader {
  unsigned char protocol[4];	/* '\xffSMB' */
  unsigned char command;	/* command code */
  union {
    struct {
      unsigned char errorclass;
      unsigned char reserved;
      unsigned short error;
    } doserror;
    unsigned long status;
  } status;
  unsigned char flags;
  unsigned short flags2;
  union {
    unsigned short pad[6];
    struct {
      unsigned short pidhigh;
      unsigned char securitysignature[8];
    } extra;
  };
  unsigned short tid;	/* tree identifier */
  unsigned short pid;	/* caller's process id */
  unsigned short uid;	/* user id */
  unsigned short mid;	/* multiplex id */
  /* first:
  unsigned char wordcount;	// count of parameter words 
  unsigned short parameterwords[1];
  */
  /* then:
   unsigned short bytecount;
   unsigned char buf[bytecount];
   */
};

int smb_handle_SessionSetupAndX(char* pkt,unsigned long len,struct http_data* h) {
  struct smbheader* p=(struct pktheader*)pkt;
  char* s=pkt+sizeof(smbheader);
  char* andx;
  if (len<sizeof(smbheader)) return -1;
  if (h->smbdialect<NTLM012) {
#if 0
    struct {
      unsigned char wordcount;
      unsigned char andxcommand;
      unsigned char andxreserved;
      unsigned short andxoffset;
      unsigned short maxbuffersize;
      unsigned short maxmpxcount;	/* max multiplex pending requests */
      unsigned short vcnumber;		/* 0 */
      unsigned int sessionkey;		/* valid iff vcnumber!=0 */
      unsigned short passwordlength;
      unsigned int reserved;		/* 0 */
      unsigned char accountpassword[];
      string accountname[];
      string primarydomain[];
      string nativeos[];
      string nativelanman[];
    } request;
    struct {
      unsigned char wordcount;
      unsigned char andxcommand;
      unsigned char andxreserved;
      unsigned short andxoffset;
      unsigned short action;	/* bit0 = logged in as GUEST */
      unsigned short bytecount;
      string nativeos[];
      string nativelanman[];
      string primarydomain[];
    } response;
#endif
    return -1;
  } else {
#if 0
    struct {
      UCHAR wordcount;
      UCHAR andxcommand;
      UCHAR andxreserved;
      USHORT andxoffset;
      USHORT maxbuffersize;
      USHORT maxmpxcount;
      USHORT vcnumber;
      ULONG sessionkey;
      USHORT caseinsensitivepasswordlength;
      USHORT casesensitivepasswordlength;
      ULONG reserved;
      ULONG capabilities; /* & 4 -> unicode
			     & 8 -> 64-bit offsets
			     & 0x10 -> understands NT LM 0.12 SMBs
			     & 0x40 -> understands 32-bit errors
			     & 0x80 -> understands level 2 oplocks */
      USHORT bytecount;
      UCHAR caseinsensitivepassword[];
      UCHAR casesensitivepassword[];
      UCHAR reserved2;
      STRING accountname[];
      STRING primarydomain[];
      STRING nativeos[];
      STRING nativelanman[];
    } request;
    struct {
      unsigned char wordcount;
      unsigned char andxcommand;
      unsigned char andxreserved;
      unsigned short andxoffset;
      unsigned short action;	/* bit0 = looged in as GUEST */
      unsigned short securitybloblength;
      unsigned short bytecount;
      unsigned char securityblob[];
      string nativeos[];
      string nativelanman[];
      string primarydomain[];
    } response;
#endif
  }
  return 0;
}

int smbresponse(struct http_data* h,int64 s) {
  char* c=array_start(&h->r);
  int len;
  /* is it SMB? */
  if (byte_diff(c+4,4,"\xffSMB")) {
    /* uh, what does an error look like? */
    /* dunno, samba doesn't say anything, it just ignores the packet. */
    /* if it's good enough for samba, it's good enough for me. */
    return;
  }
  /* is it a request?  Discard replies. */
  if (c[13]&0x80) return;
  len=uint32_read_big(c)&0xffffff;
  /* what kind of request is it? */
  switch (c[8]) {
  case 0x72:
    /* protocol negotiation request */
    {
      int i,j,k;
      int ack,lvl;
      c[3]=88+str_len(workgroup);
      c[13]|=0x80;	/* set answer bit */
      j=uint16_read(c+0x25);
      ack=-1; lvl=-1;
      for (k=0,i=0x27; i<0x27+j; ++k) {
	if (c[i]==2) {
	  if (str_equal(c+i+1,"PC NETWORK PROGRAM 1.0") && lvl<0) { ack=k; lvl=0; } else
	  if (str_equal(c+i+1,"LANMAN2.1") && lvl<1) { ack=k; lvl=1; } else
	  if (str_equal(c+i+1,"NT LM 0.12") && lvl<2) { ack=k; lvl=2; }
	  i+=2+str_len(c+i+1);
	}
      }
      switch (lvl) {
      case -1: case 0:
	h->smbdialect=PCNET10;
	c[0x24]=1;
	c[0x25]=ack; c[0x26]=0;
	c[0x27]=0; c[0x28]=0;
	uint16_pack(c+2,0x29-4);
	write(s,c,0x29);
	return;
      case 1:
	h->smbdialect=LANMAN21;
	c[0x24]=13;
	uint16_pack(c+0x25,ack);
	uint16_pack(c+0x27,0);
	uint16_pack(c+0x29,16*1024);
	uint16_pack(c+0x2B,1);
	uint16_pack(c+0x2D,1);
	uint16_pack(c+0x2F,0);
	uint32_pack(c+0x31,0);
	{
	  struct tm* t;
	  struct timeval tv;
	  struct timezone tz;
	  gettimeofday(&tv,&tz);
	  t=localtime(&tv.tv_sec);
	  uint16_pack(c+0x35,mksmbdate(t->tm_mday,t->tm_mon+1,t->tm_year+1900));
	  uint16_pack(c+0x37,mksmbtime(t->tm_hour,t->tm_min,t->tm_sec));
	  uint16_pack(c+0x39,tz.tz_minuteswest);
	  byte_zero(c+0x3b,4);
	  c[0x3f]=0; c[0x40]=wglen16;	/* byte count */
	  byte_copy(c+0x41,wglen16,workgroup_utf16);
	}
	uint16_pack(c+2,0x41+wglen16-4);
	write(s,c,0x41+wglen16);
	return;
      case 2:
	h->smbdialect=NTLM012;
	c[0x24]=17;
	uint16_pack(c+0x25,ack);
	c[0x27]=0;
	uint16_pack(c+0x28,1);
	uint16_pack(c+0x2a,1);
	uint32_pack(c+0x2c,16384);
	uint32_pack(c+0x30,16384);
	uint32_pack(c+0x34,0);
	uint32_pack(c+0x38,4+8+0x4000);
	c[0x46]=0;
	uint16_pack(c+0x47,wglen16);
	byte_copy(c+0x49,wglen16,workgroup_utf16);

	{
	  struct timeval t;
	  struct timezone tz;
	  unsigned long long ntdate;
	  gettimeofday(&t,&tz);
	  ntdate=10000000ll * ( t.tv_sec + 11644473600ll ) + t.tv_usec * 10ll;
	  uint32_pack(c+0x3c,ntdate&0xffffffff);
	  uint32_pack(c+0x40,ntdate>>32);
	  uint16_pack(c+0x44,tz.tz_minuteswest);
	}
	uint16_pack_big(c+2,0x49+wglen16-4);
	write(s,c,0x49+wglen16);
	return;
      }
    }
    break;
  case 0x73:
    /* Session Setup AndX Request */
    if (smb_handle_SessionSetupAndX(c+4,len,h)==-1)
      return -1;
    break;
  case 0x75:
    /* Tree Connect AndX Request */
  case 0x10:
    /* Check Directory Request */
  case 0x2d:
    /* Open AndX Request */
  case 0x2e:
    /* Read AndX Request */
  case 0x04:
    /* Close Request */
    break;
  }
  return 0;
}

#endif /* SUPPORT_SMB */


static uid_t __uid;
static gid_t __gid;

static int prepare_switch_uid(const char* new_uid) {
  if (new_uid) {
    uid_t u=0;
    gid_t g=0;
    if (new_uid[0]>='0' && new_uid[0]<='9') {
      unsigned long l;
      const char *c=new_uid+scan_ulong(new_uid,&l);
      if (*c && *c!=':' && *c!='.') return -1;
      if ((u=l)!=l) return -1; /* catch overflow */
      if (*c) {
	++c;
	c=c+scan_ulong(c,&l);
	if ((g=l)!=l) return -1; /* catch overflow */
	if (*c) return -1;
      }
    } else {
      struct passwd *p=getpwnam(new_uid);
      if (!p) return -1;
      u=p->pw_uid;
      g=p->pw_gid;
    }
    __uid=u;
    __gid=g;
  }
  return 0;
}

static int switch_uid() {
  if (setgid(__gid)) return -1;
  if (setgroups(1,&__gid)) return -1;
  if (setuid(__uid)) return -1;
  return 0;
}

static long connections;

static void cleanup(int64 fd) {
  struct http_data* h=io_getcookie(fd);
  int buddyfd=-1;
  if (h) {
    buddyfd=h->buddy;

    if (h->t==HTTPREQUEST
#ifdef SUPPORT_FTP
	|| h->t==FTPCONTROL6 || h->t==FTPCONTROL4
#endif
#ifdef SUPPORT_SMB
	|| h->t==SMBREQUEST
#endif
#ifdef SUPPORT_HTTPS
	|| h->t==HTTPSREQUEST || h->t==HTTPSACCEPT
#endif
	  ) --connections;

#if defined(SUPPORT_FTP) || defined(SUPPORT_PROXY)
    if (h->t==FTPSLAVE || h->t==FTPACTIVE || h->t==FTPPASSIVE ||
#ifdef SUPPORT_PROXY
	h->t==PROXYSLAVE ||
#endif
	h->t==HTTPREQUEST
#ifdef SUPPORT_HTTPS
			  || h->t==HTTPSREQUEST || h->t==HTTPSRESPONSE
#endif
	) {
      if (buddyfd!=-1) {
	struct http_data* b=io_getcookie(buddyfd);
	if (b)
	  b->buddy=-1;
      }
      buddyfd=-1;
    }
#endif
    array_reset(&h->r);
    iob_reset(&h->iob);
#ifdef SUPPORT_FTP
    free(h->ftppath);
#endif
#ifdef SUPPORT_HTTPS
    if (h->ssl) SSL_free(h->ssl);
#endif
    free(h);
  }
  io_close(fd);
  if (buddyfd>=0) {
    h=io_getcookie(buddyfd);
    if (h) h->buddy=-1;
    cleanup(buddyfd);
  }
}

#ifdef SUPPORT_CGI
/* gatling is expected to have 10000 file descriptors open.
 * so forking off CGIs is bound to be expensive because after the fork
 * all the file descriptors have to be closed.  So this code makes
 * gatling fork off a child first thing in main().  gatling has a Unix
 * domain socket open to the child.  When gatling needs to start a CGI,
 * it sends a message to the child.  The child then creates a new socket
 * pair, sets up the CGI environment, forks a grandchild, and passes the
 * socket to the grandchild back to gatling over the Unix domain socket. */
static char fsbuf[8192];

char** _envp;

static const char *cgivars[] = {
  "GATEWAY_INTERFACE=",
  "SERVER_PROTOCOL=",
  "SERVER_SOFTWARE=",
  "SERVER_NAME=",
  "SERVER_PORT=",
  "REQUEST_METHOD=",
  "REQUEST_URI=",
  "SCRIPT_NAME=",
  "REMOTE_ADDR=",
  "REMOTE_PORT=",
  "REMOTE_IDENT=",
  "HTTP_USER_AGENT=",
  "HTTP_COOKIE=",
  "HTTP_REFERER=",
  "HTTP_ACCEPT_ENCODING=",
  "AUTH_TYPE=",
  "CONTENT_TYPE=",
  "CONTENT_LENGTH=",
  "QUERY_STRING=",
  "PATH_INFO=",
  "PATH_TRANSLATED=",
  "REMOTE_USER=",
  0
};

void forkslave(int fd,buffer* in) {
  /* receive query, create socketpair, fork, set up environment,
   * pass file descriptor of our side of socketpair */

  /* protocol:
   * in:
   *   uint32 reqlen,dirlen,ralen
   *   char httprequest[reqlen]
   *   char dir[dirlen]		// "www.fefe.de:80"
   *   char remoteaddr[ralen]
   *   uint16 remoteport
   *   uint16 myport
   * out:
   *   uint32 code,alen
   *   char answer[alen]
   */

  uint32 i,reqlen,dirlen,code,ralen;
  uint16 port,myport;
  const char* msg="protocol error";
  int res;

  code=1;
  if ((res=buffer_get(in,(char*)&reqlen,4))==4 &&
      buffer_get(in,(char*)&dirlen,4)==4 &&
      buffer_get(in,(char*)&ralen,4)==4) {
    if (res<1) exit(0);
    if (dirlen<PATH_MAX && reqlen<MAX_HEADER_SIZE) {
      char* httpreq=alloca(reqlen+1);
      char* path=alloca(dirlen+1);
      char* remoteaddr=alloca(ralen+1);
      char* servername,* httpversion,* httpaccept,* authtype,* contenttype,* contentlength,* remoteuser;
      char* path_translated;

      if (buffer_get(in,httpreq,reqlen) == reqlen &&
	  buffer_get(in,path,dirlen) == dirlen &&
	  buffer_get(in,remoteaddr,ralen) == ralen &&
	  buffer_get(in,(char*)&port,2) == 2 &&
	  buffer_get(in,(char*)&myport,2) == 2) {

	httpreq[reqlen]=0;
	path[dirlen]=0;
	remoteaddr[ralen]=0;

#if 0
	buffer_puts(buffer_2,"httpreq: ");
	buffer_put(buffer_2,httpreq,reqlen);
	buffer_puts(buffer_2,"\n\npath: ");
	buffer_put(buffer_2,path,dirlen);
	buffer_puts(buffer_2,"\nremoteip: ");
	buffer_put(buffer_2,remoteaddr,ralen);
	buffer_putnlflush(buffer_2);
#endif

	if (dirlen==0 || chdir(path)==0) {
	  /* now find cgi */
	  char* cginame;

	  cginame=httpreq+5+(httpreq[0]=='P');
	  while (*cginame=='/') ++cginame;
	  for (i=0; cginame+i<httpreq+reqlen; ++i)
	    if (cginame[i]==' ' || cginame[i]=='\r' || cginame[i]=='\n') break;

	  if (cginame[i]==' ') {
	    char* args,* pathinfo;
	    int j,k;
	    struct stat ss;
	    cginame[i]=0; args=0; pathinfo=0;

	    httpversion=alloca(30+(j=str_chr(cginame+i+1,'\n')));
	    k=fmt_str(httpversion,"SERVER_PROTOCOL=");
	    byte_copy(httpversion+k,j,cginame+i+1);
	    if (j && httpversion[k+j-1]=='\r') --j; httpversion[k+j]=0;

	    /* now cginame is something like "test/t.cgi?foo=bar"
	     * but it might also be "test/t.cgi/something/else" or even
	     * "test/t.cgi/something/?uid=23" */

	    /* extract ?foo=bar */
	    j=str_chr(cginame,'?');
	    if (cginame[j]=='?') {
	      args=cginame+j+1;
	      cginame[j]=0;
	    }

	    /* now cginame is test/t.cgi/something */
	    if (stat(cginame,&ss)==0)
	      /* no "/something" */
	      pathinfo=0;
	    else {
	      /* try paths */
	      for (j=0; j<i; ++j) {
		if (cginame[j]=='/') {
		  cginame[j]=0;
		  if (stat(cginame,&ss)==0 && !S_ISDIR(ss.st_mode)) {
		    pathinfo=cginame+j+1;
		    break;
		  }
		  cginame[j]='/';
		  if (errno==ENOENT || errno==ENOTDIR) {
		    msg="404";
		    goto error;
		  }
		}
	      }
	    }

	    {
	      char* x=http_header_blob(httpreq,reqlen,"Host");
	      if (x) {
		j=str_chr(x,'\n'); if (j && x[j-1]=='\r') { --j; }
	      } else {
		x=remoteaddr; j=str_len(x);
	      }
	      servername=alloca(30+j+1);
	      i=fmt_str(servername,"SERVER_NAME=");
	      byte_copy(servername+i,j,x);
	      servername[i+j]=0;

	      x=http_header_blob(httpreq,reqlen,"Accept");
	      if (x) {
		j=str_chr(x,'\n'); if (j && x[j-1]=='\r') { --j; }
		httpaccept=alloca(20+j+1);
		i=fmt_str(httpaccept,"HTTP_ACCEPT=");
		byte_copy(httpaccept+i,j,x);
		httpaccept[i+j]=0;
	      } else
		httpaccept="HTTP_ACCEPT=*/*";

	      if (pathinfo) {
		path_translated=alloca(PATH_MAX+30);
		i=fmt_str(path_translated,"PATH_TRANSLATED=");
		if (!realpath(pathinfo,path_translated+i))
		  path_translated=0;
	      } else
		path_translated=0;

	      x=http_header_blob(httpreq,reqlen,"Authorization");
	      if (x) {
		int k;
		remoteuser=0;

		j=str_chr(x,'\n'); if (j && x[j-1]=='\r') { --j; }
		k=str_chr(x,' ');
		if (k<j) {
		  unsigned long dl;
		  remoteuser=alloca(20+k-j);
		  i=fmt_str(remoteuser,"REMOTE_USER=");
		  scan_base64(x+k+1,remoteuser+i,&dl);
		  remoteuser[i+dl]=0;
		  dl=str_chr(remoteuser+i,':');
		  if (remoteuser[i+dl]==':') remoteuser[i+dl]=0;
		  j=k;
		}
		authtype=alloca(20+j+1);
		i=fmt_str(authtype,"AUTH_TYPE=");
		byte_copy(authtype+i,j,x);
		authtype[i+j]=0;
	      } else
		authtype=remoteuser=0;

	      x=http_header_blob(httpreq,reqlen,"Content-Type");
	      if (x) {
		j=str_chr(x,'\n'); if (j && x[j-1]=='\r') { --j; }
		contenttype=alloca(30+j+1);
		i=fmt_str(contenttype,"CONTENT_TYPE=");
		byte_copy(contenttype+i,j,x);
		contenttype[i+j]=0;
	      } else
		contenttype=0;

	      x=http_header_blob(httpreq,reqlen,"Content-Length");
	      if (x) {
		j=str_chr(x,'\n'); if (j && x[j-1]=='\r') { --j; }
		contentlength=alloca(30+j+1);
		i=fmt_str(contentlength,"CONTENT_LENGTH=");
		byte_copy(contentlength+i,j,x);
		contentlength[i+j]=0;
	      } else
		contentlength=0;
	    }

	    {
	      int sock[2];
	      if (socketpair(AF_UNIX,SOCK_STREAM,0,sock)==0) {
		int r=vfork();
		if (r==-1)
		  msg="vfork failed!";
		else if (r==0) {
		  /* child */
		  pid_t pid;
		  code=0;
		  write(fd,&code,4);
		  write(fd,&code,4);
		  pid=getpid();
		  write(fd,&pid,sizeof(pid));
		  if (io_passfd(fd,sock[0])==0) {
		    char* argv[]={cginame,0};
		    char** envp;
		    int envc;
		    for (i=envc=0; _envp[i]; ++i) {
		      int found=0;
		      for (j=0; cgivars[j]; ++j)
			if (str_start(_envp[i],cgivars[j])) { found=1; break; }
		      if (!found) ++envc;
		    }
		    envp=(char**)alloca(sizeof(char*)*(envc+21));
		    envc=0;

		    for (i=0; _envp[i]; ++i) {
		      int found=0;
		      for (j=0; cgivars[j]; ++j)
			if (str_start(_envp[i],cgivars[j])) { found=1; break; }
		      if (!found) envp[envc++]=_envp[i];
		    }
		    envp[envc++]="SERVER_SOFTWARE=" RELEASE;
		    envp[envc++]=servername;
		    envp[envc++]="GATEWAY_INTERFACE=CGI/1.1";
		    envp[envc++]=httpversion;

		    envp[envc]=alloca(30);
		    i=fmt_str(envp[envc],"SERVER_PORT=");
		    i+=fmt_ulong(envp[envc]+i,myport);
		    envp[envc][i]=0;
		    ++envc;

		    envp[envc++]=httpreq[0]=='G'?"REQUEST_METHOD=GET":"REQUEST_METHOD=POST";
		    envp[envc++]=httpaccept;
		    if (pathinfo) envp[envc++]=pathinfo;
		    if (path_translated) envp[envc++]=path_translated;

		    envp[envc]=alloca(30+str_len(cginame));
		    i=fmt_str(envp[envc],"SCRIPT_NAME=");
		    i+=fmt_str(envp[envc]+i,cginame-1);
		    envp[envc][i]=0;
		    ++envc;

		    if (args) {
		      envp[envc]=alloca(30+str_len(args));
		      i=fmt_str(envp[envc],"QUERY_STRING=");
		      i+=fmt_str(envp[envc]+i,args);
		      envp[envc][i]=0;
		      ++envc;
		    }

		    envp[envc]=alloca(30+str_len(remoteaddr));
		    i=fmt_str(envp[envc],"REMOTE_ADDR=");
		    i+=fmt_str(envp[envc]+i,remoteaddr);
		    envp[envc][i]=0;
		    ++envc;

		    envp[envc]=alloca(30);
		    i=fmt_str(envp[envc],"REMOTE_PORT=");
		    i+=fmt_ulong(envp[envc]+i,port);
		    envp[envc][i]=0;
		    ++envc;

		    if (authtype) envp[envc++]=authtype;
		    if (remoteuser) envp[envc++]=remoteuser;
		    if (contenttype) envp[envc++]=contenttype;
		    if (contentlength) envp[envc++]=contentlength;
		    envp[envc]=0;

		    dup2(sock[1],0);
		    dup2(sock[1],1);
		    dup2(sock[1],2);
		    close(sock[0]); close(sock[1]); close(fd);

		    {
		      char* path,* file;
		      path=cginame;
		      file=strrchr(path,'/');
		      if (file) {
			*file=0;
			++file;
			chdir(path);
			cginame=file;
		      }
		      execve(cginame,argv,envp);
		    }
		  }
		  exit(127);
		} else {
		  /* father */
		  close(sock[0]);
		  close(sock[1]);
		  return;
		}
	      } else
		msg="socketpair failed!";
	    }

	  }
	}
      }
    }
  }
error:
  if (write(fd,&code,4)!=4) exit(0);
  code=strlen(msg);
  write(fd,&code,4);
  {
    pid_t pid=0;
    write(fd,&pid,sizeof(pid));
  }
  write(fd,msg,code);
}
#endif

static volatile int fini;

void sighandler(int sig) {
  fini=(sig==SIGINT?1:2);	/* 2 for SIGHUP */
}

#ifdef SUPPORT_PROXY
static void handle_read_proxypost(int64 i,struct http_data* H) {
  switch (proxy_is_readable(i,H)) {
  case -1:
    {
      struct http_data* h=io_getcookie(H->buddy);
      if (logging) {
	char numbuf[FMT_ULONG];
	numbuf[fmt_ulong(numbuf,i)]=0;

	buffer_putmflush(buffer_1,"proxy_read_error ",numbuf," ",strerror(errno),"\nclose/acceptfail ",numbuf,"\n");
#if 0
	buffer_puts(buffer_1,"proxy_read_error ");
	buffer_putulong(buffer_1,i);
	buffer_putspace(buffer_1);
	buffer_puterror(buffer_1);
	buffer_puts(buffer_1,"\nclose/acceptfail ");
	buffer_putulong(buffer_1,i);
	buffer_putnlflush(buffer_1);
#endif
      }
      H->buddy=-1;
      h->buddy=-1;
      cleanup(i);
    }
    break;
  case -3:
    cleanup(i);
    break;
  }
}

static void handle_read_httppost(int64 i,struct http_data* H) {
  /* read POST data. */
//	printf("read POST data state for %d\n",i);
  if (H->still_to_copy) {
    if (array_bytes(&H->r)>0) {
//	    printf("  but there was still data in H->r!\n");
      io_dontwantread(i);
      io_wantwrite(H->buddy);
    } else if (read_http_post(i,H)==-1) {
      if (logging) {
	char a[FMT_ULONG];
	a[fmt_ulong(a,i)]=0;
	buffer_putmflush(buffer_1,"http_postdata_read_error ",a," ",strerror(errno),"\nclose/acceptfail ",a,"\n");
#if 0
	buffer_puts(buffer_1,"http_postdata_read_error ");
	buffer_putulong(buffer_1,i);
	buffer_putspace(buffer_1);
	buffer_puterror(buffer_1);
	buffer_puts(buffer_1,"\nclose/acceptfail ");
	buffer_putulong(buffer_1,i);
	buffer_putnlflush(buffer_1);
#endif
      }
      cleanup(i);
    } else {
//	    printf("  read something\n");
      io_dontwantread(i);
      io_wantwrite(H->buddy);
    }
  } else {
    /* should not happen */
    io_dontwantread(i);
//	  printf("ARGH!!!\n");
  }
}

static void handle_write_proxypost(int64 i,struct http_data* h) {
  struct http_data* H=io_getcookie(h->buddy);
  /* do we have some POST data to write? */
//	printf("event: write POST data (%llu) to proxy on %d\n",h->still_to_copy,i);
  if (!array_bytes(&H->r)) {
//	  printf("  but nothing here to write!\n");
    io_dontwantwrite(i);	/* nope */
    io_wantread(h->buddy);
  } else {
//	  printf("  yeah!\n");
    if (H) {
      char* c=array_start(&H->r);
      long alen=array_bytes(&H->r);
      long l;
//	    printf("%ld bytes still in H->r (%ld in h->r), still to copy: %lld (%lld in h)\n",alen,(long)array_bytes(&h->r),H->still_to_copy,h->still_to_copy);
      if (alen>h->still_to_copy) alen=h->still_to_copy;
      if (alen==0) goto nothingmoretocopy;
      l=write(i,c,alen);
//	    printf("wrote %ld bytes (wanted to write %ld; had %lld still to copy)\n",l,alen,H->still_to_copy);
      if (l<1) {
	/* ARGH!  Proxy crashed! *groan* */
	if (logging) {
	  buffer_puts(buffer_1,"http_postdata_write_error ");
	  buffer_putulong(buffer_1,i);
	  buffer_putspace(buffer_1);
	  buffer_puterror(buffer_1);
	  buffer_puts(buffer_1,"\nclose/acceptfail ");
	  buffer_putulong(buffer_1,i);
	  buffer_putnlflush(buffer_1);
	}
	cleanup(i);
      } else {
	byte_copy(c,alen-l,c+l);
	array_truncate(&H->r,1,alen-l);
//	      printf("still_to_copy PROXYPOST write handler: %p %llu -> %llu\n",H,H->still_to_copy,H->still_to_copy-l);
	H->still_to_copy-=l;
//	      printf("still_to_copy PROXYPOST write handler: %p %llu -> %llu\n",h,h->still_to_copy,h->still_to_copy-i);
//	      h->still_to_copy-=i;
	if (alen-l==0)
	  io_dontwantwrite(i);
	if (h->still_to_copy) {
	  /* we got all we asked for */
nothingmoretocopy:
	  io_dontwantwrite(i);
	  io_wantread(i);
	  io_dontwantread(h->buddy);
	  io_wantwrite(h->buddy);
	}
      }
    }
  }
}

static void handle_write_httppost(int64 i,struct http_data* h) {
  struct http_data* H=io_getcookie(h->buddy);
  /* write answers from proxy */
  if (H && h->still_to_copy) {
    char* c=array_start(&H->r);
    long alen=array_bytes(&H->r);
    long l;
    if (alen>h->still_to_copy) alen=h->still_to_copy;
    l=write(i,c,alen);
    if (l<1) {
      /* ARGH!  Client hung up on us! *groan* */
      if (logging) {
	buffer_puts(buffer_1,"http_postdata_writetoclient_error ");
	buffer_putulong(buffer_1,i);
	buffer_putspace(buffer_1);
	buffer_puterror(buffer_1);
	buffer_puts(buffer_1,"\nclose/acceptfail ");
	buffer_putulong(buffer_1,i);
	buffer_putnlflush(buffer_1);
      }
      cleanup(i);
    } else {
      byte_copy(c,alen-l,c+l);
      array_truncate(&H->r,1,alen-l);
//	    printf("still_to_copy HTTPPOST write handler: %p %llu -> %llu\n",h,h->still_to_copy,h->still_to_copy-l);
      h->still_to_copy-=l;
      if (alen-l==0)
	io_dontwantwrite(i);
      if (!h->still_to_copy) {
	/* we got all we asked for */
//	      printf("  got all we asked for!\n");
	io_dontwantwrite(i);
	io_wantread(i);
	io_dontwantread(h->buddy);
	io_wantwrite(h->buddy);
      } else {
	io_wantread(h->buddy);
	if (l==alen) io_dontwantwrite(i);
      }
    }
  } else {
    int buddy=h->buddy;
    struct http_data* H=io_getcookie(buddy);
    h->buddy=-1;
    if (H) {
      H->buddy=-1;
      if (logging) {
	buffer_puts(buffer_1,"\nclose/proxydone ");
	buffer_putulong(buffer_1,i);
	buffer_putnlflush(buffer_1);
      }
      cleanup(buddy);
    }
    io_dontwantwrite(i);
  }
}

static void handle_write_proxyslave(int64 i,struct http_data* h) {
  /* the connect() to the proxy just finished or failed */
  struct http_data* H;
  H=io_getcookie(h->buddy);
  if (proxy_write_header(i,h)==-1) {
    if (logging) {
      buffer_puts(buffer_1,"proxy_connect_error ");
      buffer_putulong(buffer_1,i);
      buffer_putspace(buffer_1);
      buffer_puterror(buffer_1);
      buffer_puts(buffer_1,"\nclose/connectfail ");
      buffer_putulong(buffer_1,i);
      buffer_putnlflush(buffer_1);
    }
    H->buddy=-1;
    httperror(H,"502 Gateway Broken","Request relaying error.");
    h->buddy=-1;
    free(h);
    io_close(i);
  }
  /* it worked.  We wrote the header.  Now see if there is
    * POST data to write.  h->still_to_copy is Content-Length. */
//	printf("wrote header to %d for %d; Content-Length: %d\n",(int)i,(int)h->buddy,(int)h->still_to_copy);
  if (h->still_to_copy) {
    h->t=PROXYPOST;
    handle_write_httppost(i,H);
    return;
//    goto httpposthandler;
//	  io_wantwrite(h->buddy);
  } else {
    io_dontwantwrite(i);
    io_wantread(i);
  }
  h->t=PROXYPOST;
}

#endif

#ifdef SUPPORT_FTP
static void handle_read_ftppassive(int64 i,struct http_data* H) {
  /* This is the server socket for a passive FTP data connections.
    * A read event means the peer established a TCP connection.
    * accept() it and close server connection */
  struct http_data* h;
  int n;
  h=io_getcookie(H->buddy);
  assert(h);
  n=socket_accept6(i,H->myip,&H->myport,&H->myscope_id);
  if (n==-1) {
pasverror:
    if (logging) {
      buffer_puts(buffer_1,"pasv_accept_error ");
      buffer_putulong(buffer_1,i);
      buffer_putspace(buffer_1);
      buffer_puterror(buffer_1);
      buffer_puts(buffer_1,"\nclose/acceptfail ");
      buffer_putulong(buffer_1,i);
      buffer_putnlflush(buffer_1);
    }
    h->buddy=-1;
    free(H);
    io_close(i);
  } else {
    if (!io_fd(n)) goto pasverror;
    if (logging) {
      buffer_puts(buffer_1,"pasv_accept ");
      buffer_putulong(buffer_1,i);
      buffer_putspace(buffer_1);
      buffer_putulong(buffer_1,n);
      buffer_puts(buffer_1,"\nclose/accepted ");
      buffer_putulong(buffer_1,i);
      buffer_putnlflush(buffer_1);
    }
    h->buddy=n;
    io_setcookie(n,H);
    io_nonblock(n);
    io_close(i);
    H->t=FTPSLAVE;
#ifdef TCP_NODELAY
    {
      int x=1;
      setsockopt(n,IPPROTO_TCP,TCP_NODELAY,&x,sizeof(x));
    }
#endif
    if (h->f==WAITCONNECT) {
      h->f=LOGGEDIN;
      if (H->f==DOWNLOADING)
	io_wantwrite(h->buddy);
      else
	io_wantread(h->buddy);
    }
  }
}

static void handle_write_ftpactive(int64 i,struct http_data* h) {
  struct http_data* H;
  H=io_getcookie(h->buddy);
  assert(H);
  if (socket_connect6(i,h->peerip,h->destport,h->myscope_id)==-1 && errno!=EISCONN) {
    if (logging) {
      buffer_puts(buffer_1,"port_connect_error ");
      buffer_putulong(buffer_1,i);
      buffer_putspace(buffer_1);
      buffer_puterror(buffer_1);
      buffer_puts(buffer_1,"\nclose/connectfail ");
      buffer_putulong(buffer_1,i);
      buffer_putnlflush(buffer_1);
    }
    H->buddy=-1;
    free(h);
    io_close(i);
  } else {
    if (logging) {
      char buf[IP6_FMT];
      buffer_puts(buffer_1,"port_connect ");
      buffer_putulong(buffer_1,i);
      buffer_putspace(buffer_1);
      buffer_put(buffer_1,buf,fmt_ip6c(buf,h->peerip));
      buffer_putspace(buffer_1);
      buffer_put(buffer_1,buf,fmt_ulong(buf,h->destport));
      buffer_putnlflush(buffer_1);
    }
    h->t=FTPSLAVE;
#ifdef TCP_NODELAY
    {
      int x=1;
      setsockopt(i,IPPROTO_TCP,TCP_NODELAY,&x,sizeof(x));
    }
#endif
    if (h->f != DOWNLOADING)
      io_dontwantwrite(i);
    if (H->f==WAITCONNECT) {
      H->f=LOGGEDIN;
      if (h->f==DOWNLOADING)
	io_wantwrite(H->buddy);
      else
	io_wantread(H->buddy);
    }
  }
}
#endif




static int is_server_connection(enum conntype t) {
  return (t==HTTPSERVER6 || t==HTTPSERVER4
#ifdef SUPPORT_FTP
	|| t==FTPSERVER6 || t==FTPSERVER4
#endif
#ifdef SUPPORT_SMB
	|| t==SMBSERVER6 || t==SMBSERVER4
#endif
#ifdef SUPPORT_HTTPS
	|| t==HTTPSSERVER6 || t==HTTPSSERVER4
#endif
	);
}

#ifdef __broken_itojun_v6__
#warning "working around idiotic openbse ipv6 stupidity - please kick itojun for this!"
  int s4;		/* ipv4 http socket */
#ifdef SUPPORT_FTP
  int f4;		/* ipv4 ftp socket */
#endif
#ifdef SUPPORT_HTTPS
  int httpss4;		/* ipv4 https socket */
#endif
#endif

static void accept_server_connection(int64 i,struct http_data* H,unsigned long ftptimeout_secs,tai6464 nextftp) {
  /* This is an FTP or HTTP(S) or SMB server connection.
    * This read event means that someone connected to us.
    * accept() the connection, establish connection type from
    * server connection type, and put the new connection into the
    * state table */
  char ip[16];
  uint16 port;
  uint32 scope_id;
  int n;
  while (1) {
#ifdef __broken_itojun_v6__
    if (H->t==HTTPSERVER4 || H->t==FTPSERVER4
#ifdef SUPPORT_SMB
					      || H->t==SMBSERVER4
#endif
#ifdef SUPPORT_HTTPS
					      || H->t==HTTPSSERVER4
#endif
								  ) {
      byte_copy(ip,12,V4mappedprefix);
      scope_id=0;
      n=socket_accept4(i,ip+12,&port);
    } else
#endif
      n=socket_accept6(i,ip,&port,&scope_id);
    if (n==-1) break;
    ++connections;
    {
      char buf[IP6_FMT];

      if (logging) {
	buffer_puts(buffer_1,"accept ");
	buffer_putulong(buffer_1,n);
	buffer_puts(buffer_1," ");
	buffer_put(buffer_1,buf,fmt_ip6c(buf,ip));
	buffer_puts(buffer_1," ");
	buffer_putulong(buffer_1,port);
	buffer_puts(buffer_1," ");
	buffer_putulong(buffer_1,connections-1);
	buffer_putnlflush(buffer_1);
      }
    }

    io_nonblock(n);
    if (io_fd(n)) {
      struct http_data* h=(struct http_data*)malloc(sizeof(struct http_data));
      if (h) {
	if (H->t==HTTPSERVER6 || H->t==HTTPSERVER4
#ifdef SUPPORT_SMB
	  || H->t==SMBSERVER6 || H->t==SMBSERVER4
#endif
#ifdef SUPPORT_HTTPS
	  || H->t==HTTPSSERVER6 || H->t==HTTPSSERVER4
#endif
	  )
	  io_wantread(n);
	else
	  io_wantwrite(n);
	byte_zero(h,sizeof(struct http_data));
#ifdef __broken_itojun_v6__
	if (i==s4 || i==f4) {
	  byte_copy(h->myip,12,V4mappedprefix);
	  socket_local4(n,h->myip+12,&h->myport);
	} else
	  socket_local6(n,h->myip,&h->myport,0);
#else
	socket_local6(n,h->myip,&h->myport,0);
#endif
	byte_copy(h->peerip,16,ip);
	h->peerport=port;
	h->myscope_id=scope_id;
	if (H->t==HTTPSERVER4 || H->t==HTTPSERVER6) {
	  h->t=HTTPREQUEST;
	  if (timeout_secs)
	    io_timeout(n,next);
#ifdef SUPPORT_HTTPS
	} else if (H->t==HTTPSSERVER4 || H->t==HTTPSSERVER6) {
	  fchdir(origdir);
	  if (init_serverside_tls(&h->ssl,n)) {
	    if (logging) {
	      char a[FMT_ULONG];
	      a[fmt_ulong(a,n)]=0;
	      buffer_putmflush(buffer_1,"ssl_setup_failed ",a," ",strerror(errno),"\nclose/readerr ",a,"\n");
	    }
	    cleanup(n);
	    continue;
	  }
	  h->t=HTTPSACCEPT;
	  if (timeout_secs)
	    io_timeout(n,next);
#endif
#ifdef SUPPORT_SMB
	} else if (H->t==SMBSERVER4 || H->t==SMBSERVER6) {
	  h->t=SMBREQUEST;
	  if (timeout_secs)
	    io_timeout(n,next);
#endif
#ifdef SUPPORT_FTP
	} else {
	  if (H->t==FTPSERVER6)
	    h->t=FTPCONTROL6;
	  else
	    h->t=FTPCONTROL4;
	  iob_addbuf(&h->iob,"220 Hi there!\r\n",15);
	  h->keepalive=1;
	  if (ftptimeout_secs)
	    io_timeout(n,nextftp);
#endif
	}
	h->buddy=-1;
	h->filefd=-1;
	io_setcookie(n,h);
#ifdef TCP_NODELAY
	{
	  int i=1;
	  setsockopt(n,IPPROTO_TCP,TCP_NODELAY,&i,sizeof(i));
	}
#else
#warning TCP_NODELAY not defined
#endif
      } else
	io_close(n);
    } else
      io_close(n);
  }
  if (errno==EAGAIN)
    io_eagain(i);
  else
#ifdef __broken_itojun_v6__
    carp(H->t==HTTPSERVER4||H->t==FTPSERVER4?"socket_accept4":"socket_accept6");
#else
    carp("socket_accept6");
#endif
}

#ifdef SUPPORT_HTTPS
void handle_ssl_error_code(int sock,int code,int reading) {
//  printf("handle_ssl_error_code(sock %d,code %d,reading %d)\n",sock,code,reading);
  switch (code) {
  case SSL_ERROR_WANT_READ:
    io_wantread(sock);
    io_dontwantwrite(sock);
    return;
  case SSL_ERROR_WANT_WRITE:
    io_wantwrite(sock);
    io_dontwantread(sock);
    return;
  case SSL_ERROR_SYSCALL:
    if (logging) {
      int olderrno=errno;
      buffer_puts(buffer_1,"io_error ");
      buffer_putulong(buffer_1,sock);
      buffer_putspace(buffer_1);
      buffer_puterror(buffer_1);
      buffer_puts(buffer_1,"\nclose/readerr ");
      buffer_putulong(buffer_1,sock);
      buffer_putnlflush(buffer_1);
      errno=olderrno;
    }
    return;
  default:
    if (logging) {
      buffer_puts(buffer_1,"ssl_protocol_error ");
      buffer_putulong(buffer_1,sock);
      buffer_puts(buffer_1,"\nclose/readerr ");
      buffer_putulong(buffer_1,sock);
      buffer_putnlflush(buffer_1);
    }
    return;
  }
}

void do_sslaccept(int sock,struct http_data* h,int reading) {
  int r=SSL_get_error(h->ssl,SSL_accept(h->ssl));
//  printf("do_sslaccept -> %d\n",r);
  if (r==SSL_ERROR_NONE) {
    h->writefail=1;
    h->t=HTTPSREQUEST;
    if (logging) {
      buffer_puts(buffer_1,"ssl_handshake_ok ");
      buffer_putulong(buffer_1,sock);
      buffer_putnlflush(buffer_1);
    }
    return;
  } else
    handle_ssl_error_code(sock,r,reading);
}
#endif

static void handle_read_misc(int64 i,struct http_data* H,unsigned long ftptimeout_secs,tai6464 nextftp) {
  /* This is a TCP client connection waiting for input, i.e.
    *   - an HTTP connection waiting for a HTTP request, or
    *   - an FTP connection waiting for a command, or
    *   - an FTP upload waiting for more data, or
    *   - an SMB connection waiting for the next command */
  char buf[8192];
  int l;
#ifdef SUPPORT_HTTPS
  assert(H->t != HTTPSRESPONSE);
  if (H->t == HTTPSREQUEST) {
    l=SSL_read(H->ssl,buf,sizeof(buf));
//    printf("SSL_read(sock %d,buf %p,n %d) -> %d\n",i,buf,sizeof(buf),l);
    if (l==-1) {
      l=SSL_get_error(H->ssl,l);
//      printf("  error %d %s\n",l,ERR_error_string(l,0));
      if (l==SSL_ERROR_WANT_READ || l==SSL_ERROR_WANT_WRITE) {
	handle_ssl_error_code(i,l,1);
	l=-1;
      } else l=-3;
    }
  } else
#endif
  l=io_tryread(i,buf,sizeof buf);
  if (l==-3) {
#ifdef SUPPORT_FTP
ioerror:
#endif
    if (logging) {
      char a[FMT_ULONG];
      a[fmt_ulong(a,i)]=0;
      buffer_putmflush(buffer_1,"io_error ",a," ",strerror(errno),"\nclose/readerr ",a,"\n");
#if 0
      buffer_puts(buffer_1,"io_error ");
      buffer_putulong(buffer_1,i);
      buffer_puts(buffer_1," ");
      buffer_puterror(buffer_1);
      buffer_puts(buffer_1,"\nclose/readerr ");
      buffer_putulong(buffer_1,i);
      buffer_putnlflush(buffer_1);
#endif
    }
    cleanup(i);
  } else if (l==0) {
    if (logging) {
      buffer_puts(buffer_1,"close/read0 ");
      buffer_putulong(buffer_1,i);
      buffer_putnlflush(buffer_1);
    }
#ifdef SUPPORT_FTP
    if (H->t==FTPSLAVE) {
      /* This is an FTP upload, it just finished. */
      struct http_data* b=io_getcookie(H->buddy);
      assert(b);
      b->buddy=-1;
      iob_reset(&b->iob);
      iob_adds(&b->iob,"226 Got it.\r\n");
      io_dontwantread(H->buddy);
      io_wantwrite(H->buddy);
      if (chmoduploads)
	fchmod(H->filefd,0644);
      if (logging) {
	struct stat ss;
	if (fstat(H->filefd,&ss)==0) {
	  char a[FMT_ULONG];
	  char b[FMT_ULONG];
	  a[fmt_ulong(a,i)]=0;
	  b[fmt_ulong(b,ss.st_size)]=0;
	  buffer_putmflush(buffer_1,"received ",a," ",b,"\n");
#if 0
	  buffer_puts(buffer_1,"received ");
	  buffer_putulong(buffer_1,i);
	  buffer_putspace(buffer_1);
	  buffer_putulonglong(buffer_1,ss.st_size);
	  buffer_putnlflush(buffer_1);
#endif
	}
      }
    }
#endif
    cleanup(i);
  } else if (l>0) {
    /* successfully read some data (l bytes) */
#ifdef SUPPORT_FTP
    if (H->t==FTPCONTROL4 || H->t==FTPCONTROL6) {
      if (ftptimeout_secs)
	io_timeout(i,nextftp);
    } else {
      if (timeout_secs)
	io_timeout(i,next);
    }

    if (H->t==FTPSLAVE) {
      /* receive an upload */
      int r;
      if (ftptimeout_secs)
	io_timeout(H->buddy,nextftp);
      if ((r=write(H->filefd,buf,l))!=l)
	goto ioerror;
    } else
#endif
    {
      /* received a request */
      array_catb(&H->r,buf,l);
      if (array_failed(&H->r)) {
	httperror(H,"500 Server Error","request too long.");
emerge:
	io_dontwantread(i);
	io_wantwrite(i);
      } else if (array_bytes(&H->r)>MAX_HEADER_SIZE) {
	httperror(H,"500 request too long","You sent too much headers");
	array_reset(&H->r);
	goto emerge;
      } else if ((l=header_complete(H))) {
	long alen;
pipeline:
#ifdef SUPPORT_HTTPS
	if (H->t==HTTPREQUEST || H->t==HTTPSREQUEST) {
	  httpresponse(H,i,l);
	  if (H->t == HTTPSREQUEST) H->t=HTTPSRESPONSE;
	}
#else
	if (H->t==HTTPREQUEST)
	  httpresponse(H,i,l);
#endif
#ifdef SUPPORT_HTTPS
#endif
#ifdef SUPPORT_SMB
	else if (H->t==SMBREQUEST) {
	  if (smbresponse(H,i)==-1) {
	    cleanup(i);
	    continue;
	  }
	}
#endif
#ifdef SUPPORT_FTP
	else
	  ftpresponse(H,i);
#endif
#ifdef SUPPORT_PROXY
	if (H->t != HTTPPOST && l < (alen=array_bytes(&H->r)))
#else
	if (l < (alen=array_bytes(&H->r)))
#endif
	{
	  char* c=array_start(&H->r);
	  byte_copy(c,alen-l,c+l);
	  array_truncate(&H->r,1,alen-l);
	  l=header_complete(H);
	  if (l) goto pipeline;
	} else
	  array_reset(&H->r);
      }
    }
  }
}

#ifdef SUPPORT_HTTPS
int64 https_write_callback(int64 sock,const void* buf,uint64 n) {
  int l;
  struct http_data* H=io_getcookie(sock);
  if (!H) return -3;
  H->writefail=!H->writefail;
  if (H->writefail) { errno=EAGAIN; return -1; }
  if (n>65536) n=65536;
  l=SSL_write(H->ssl,buf,n);
  if (l<0) {
    l=SSL_get_error(H->ssl,l);
    handle_ssl_error_code(sock,l,0);
    if (l==SSL_ERROR_WANT_READ || l==SSL_ERROR_WANT_WRITE) {
      l=-1; errno=EAGAIN;
    } else
      l=-3;
  }
  return l;
}
#endif

static void handle_write_misc(int64 i,struct http_data* h,uint64 prefetchquantum) {
  int64 r;
#ifdef SUPPORT_HTTPS
  assert(h->t != HTTPSREQUEST);
  if (h->t == HTTPSRESPONSE)
    r=iob_write(i,&h->iob,https_write_callback);
  else
#endif
  r=iob_send(i,&h->iob);
  if (r==-1)
    io_eagain(i);
  else if (r<=0) {
    if (r==-3) {
      if (logging) {
	char a[FMT_ULONG];
	a[fmt_ulong(a,i)]=0;
	buffer_putmflush(buffer_1,"socket_error ",a," ",strerror(errno),"\nclose/writefail ",a,"\n");
#if 0
	buffer_puts(buffer_1,"socket_error ");
	buffer_putulong(buffer_1,i);
	buffer_puts(buffer_1," ");
	buffer_puterror(buffer_1);
	buffer_puts(buffer_1,"\nclose/writefail ");
	buffer_putulong(buffer_1,i);
	buffer_putnlflush(buffer_1);
#endif
      }
#ifdef SUPPORT_FTP
      if (h->t==FTPSLAVE || h->t==FTPACTIVE) {
	struct http_data* b=io_getcookie(h->buddy);
	assert(b);
	if (b) {
	  b->buddy=-1;
	  iob_reset(&b->iob);
	  iob_adds(&b->iob,"554 socket error.\r\n");
	  io_wantwrite(h->buddy);
	}
      }
#endif
      cleanup(i);
    } else {	/* returned 0, i.e. we wrote it all */
#ifdef SUPPORT_HTTPS
      if (h->t == HTTPSRESPONSE) h->t = HTTPSREQUEST;
#endif
#ifdef SUPPORT_PROXY
#ifdef SUPPORT_HTTPS
      if ((h->t == HTTPREQUEST || h->t == HTTPSREQUEST) && h->buddy!=-1)
#else
      if (h->t == HTTPREQUEST && h->buddy!=-1)
#endif
      {
	io_dontwantwrite(i);
	io_wantread(h->buddy);
	return;
      }
#endif
      if (logging && (h->t == HTTPREQUEST
#ifdef SUPPORT_HTTPS
	  || h->t == HTTPSREQUEST
#endif
	  )) {
	buffer_puts(buffer_1,"request_done ");
	buffer_putulong(buffer_1,i);
	buffer_putnlflush(buffer_1);
      }
      array_trunc(&h->r);
      iob_reset(&h->iob);
      h->hdrbuf=0;
      if (h->keepalive) {
	iob_reset(&h->iob);
	io_dontwantwrite(i);
	io_wantread(i);
      } else {
	if (logging) {
	  buffer_puts(buffer_1,"close/reqdone ");
	  buffer_putulong(buffer_1,i);
	  buffer_putnlflush(buffer_1);
	}
#ifdef SUPPORT_FTP
	if (h->t==FTPSLAVE) {
	  struct http_data* b=io_getcookie(h->buddy);
	  if (b) {
	    b->buddy=-1;
	    iob_reset(&b->iob);
	    iob_adds(&b->iob,"226 Done.\r\n");
	    io_dontwantread(h->buddy);
	    io_wantwrite(h->buddy);
	  } else
	    buffer_putsflush(buffer_2,"ARGH: no cookie or no buddy for FTP slave!\n");
	}
#endif
	cleanup(i);
      }
    }
  } else {
    /* write OK, now would be a good time to do some prefetching */
    h->sent_until+=r;
    if (prefetchquantum) {
      if (h->prefetched_until<h->sent_until || h->prefetched_until+prefetchquantum<h->sent_until) {
	if (prefetchquantum) iob_prefetch(&h->iob,2*prefetchquantum);
	h->prefetched_until+=2*prefetchquantum;
      }
    }
  }
}

static void prepare_listen(int s,void* whatever) {
  if (s!=-1) {
    if (socket_listen(s,16)==-1)
      panic("socket_listen");
    io_nonblock(s);
    if (!io_fd(s))
      panic("io_fd");
    io_setcookie(s,whatever);
    io_wantread(s);
  }
}

int main(int argc,char* argv[],char* envp[]) {
  int s;		/* http socket */
  int f=-1;		/* ftp socket */
#ifdef SUPPORT_SMB
  int smbs=-1;		/* smb socket */
  enum conntype sct=SMBSERVER6;
#endif
  int doftp=0;		/* -1 = don't, 0 = try, but don't fail if not working, 1 = do */
  int dosmb=0;
  enum { HTTP, FTP, SMB, HTTPS } lastopt=HTTP;
  enum conntype ct=HTTPSERVER6;	/* used as cookie to recognize server connections */
#ifdef SUPPORT_FTP
  enum conntype fct=FTPSERVER6;	/* dito */
#endif
#ifdef SUPPORT_HTTPS
  int httpss=-1;	/* https socket */
  enum conntype httpsct=HTTPSSERVER6;
  int dohttps=0;
#endif
#ifdef __broken_itojun_v6__
  enum conntype ct4=HTTPSERVER4;
#ifdef SUPPORT_FTP
  enum conntype fct4=FTPSERVER4;
#endif
#ifdef SUPPORT_HTTPS
  enum conntype httpsct4=HTTPSSERVER4;
#endif
#endif
  uint32 scope_id;
  char ip[16];
  uint16 port,fport,sport;
#ifdef SUPPORT_HTTPS
  uint16 httpsport;
#endif
  tai6464 now,last,tick,nextftp;
  unsigned long ftptimeout_secs=600;
  char* new_uid=0;
  char* chroot_to=0;
  uint64 prefetchquantum=0;

#ifdef SUPPORT_HTTPS
  SSL_load_error_strings();
#endif

#ifdef SUPPORT_CGI
  _envp=envp;
  if (socketpair(AF_UNIX,SOCK_STREAM,0,forksock)==-1)
    panic("socketpair");
  switch (fork()) {
  case -1:
    panic("fork");
  case 0:
    close(forksock[0]);
    {
      int64 savedir;
      buffer fsb;
      if (!io_readfile(&savedir,".")) panic("open()");
      buffer_init(&fsb,read,forksock[1],fsbuf,sizeof fsbuf);
      while (1) {
	pid_t r;
	do {
	  r=waitpid(-1,0,WNOHANG);
	} while (r!=0 && r!=-1);
	forkslave(forksock[1],&fsb);
	fchdir(savedir);
      }
    }
    break;
  default:
    close(forksock[1]);
    break;
  }

#if 0
  {	/* debug test for the forkslave code */
    int64 fd;
    uint32 a; uint16 b;
    char* req="GET /t.cgi/foo/bar?fnord HTTP/1.0\r\nHost: localhost:80\r\n\r\n";
    char* dir="default";
    char* ra="127.0.0.1";
    a=strlen(req); write(forksock[0],&a,4);
    a=strlen(dir); write(forksock[0],&a,4);
    a=strlen(ra); write(forksock[0],&a,4);
    write(forksock[0],req,strlen(req));
    write(forksock[0],dir,strlen(dir));
    write(forksock[0],ra,strlen(ra));
    b=12345; write(forksock[0],&b,2);
    b=80; write(forksock[0],&b,2);

    read(forksock[0],&a,4);
    buffer_puts(buffer_1,"code ");
    buffer_putulong(buffer_1,a);
    buffer_putnlflush(buffer_1);

    read(forksock[0],&a,4);
    if (a) {
      char* c=alloca(a+1);
      read(forksock[0],c,a);
      buffer_put(buffer_1,c,a);
      buffer_putnlflush(buffer_1);
    } else {
      read(forksock[0],&a,4); /* PID */
      fd=io_receivefd(forksock[0]);
      if (fd==-1)
	buffer_putsflush(buffer_2,"received no file descriptor for CGI\n");
      else {
	char buf[1024];
	int l;
	while ((l=read(fd,buf,sizeof buf))) {
	  write(1,buf,l);
	}
      }
    }
  }
  exit(0);
#endif
#endif

  s=socket_tcp6();
#ifdef __broken_itojun_v6__
#ifdef SUPPORT_FTP
  f4=socket_tcp4();
#endif
  s4=socket_tcp4();
#endif

  signal(SIGPIPE,SIG_IGN);

  {
    struct sigaction sa;
    byte_zero(&sa,sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler=sighandler;
    sigaction(SIGINT,&sa,0);
    sigaction(SIGHUP,&sa,0);
  }

  if (!geteuid()) {
    struct rlimit rl;
    long l;
#ifdef RLIMIT_NPROC
    rl.rlim_cur=RLIM_INFINITY; rl.rlim_max=RLIM_INFINITY;
    setrlimit(RLIMIT_NPROC,&rl);
#endif
    for (l=0; l<20000; l+=500) {
      rl.rlim_cur=l; rl.rlim_max=l;
      if (setrlimit(RLIMIT_NOFILE,&rl)==-1) break;
    }
  }

  byte_zero(ip,16);
  port=0; fport=0; sport=0; scope_id=0;

  logging=1;

  for (;;) {
    int i;
    int c=getopt(argc,argv,"P:hnfFi:p:vVdDtT:c:u:Uaw:sSO:C:leE");
    if (c==-1) break;
    switch (c) {
    case 'U':
      nouploads=1;
      break;
    case 'a':
      chmoduploads=1;
      break;
    case 'n':
      logging=0;
      break;
    case 'u':
      new_uid=optarg;
      break;
    case 'c':
      chroot_to=optarg;
      break;
    case 'P':
      i=scan_ulonglong(optarg,&prefetchquantum);
      if (i==0) {
	buffer_puts(buffer_2,"gatling: warning: could not parse prefetch quantum");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,".\n");
      }
      if (optarg[i]=='M') prefetchquantum*=1024*1024;
      if (optarg[i]=='G') prefetchquantum*=1024*1024*1024;
      break;
    case 'i':
      i=scan_ip6if(optarg,ip,&scope_id);
      if (optarg[i]!=0) {
	buffer_puts(buffer_2,"gatling: warning: could not parse IP address ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,".\n");
      }
      break;
    case 'p':
      if (lastopt==FTP)
	i=scan_ushort(optarg,&fport);
      else if (lastopt==SMB)
	i=scan_ushort(optarg,&sport);
#ifdef SUPPORT_HTTPS
      else if (lastopt==HTTPS)
	i=scan_ushort(optarg,&httpsport);
#endif
      else
	i=scan_ushort(optarg,&port);
      if (i==0) {
	buffer_puts(buffer_2,"gatling: warning: could not parse port ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,".\n");
      }
      break;
    case 'v': virtual_hosts=1; break;
    case 'V': virtual_hosts=-1; break;
    case 't': transproxy=1; break;
    case 'd': directory_index=1; break;
    case 'D': directory_index=-1; break;
#ifdef SUPPORT_FTP
    case 'f': doftp=1; lastopt=FTP; break;
    case 'F': doftp=-1; break;
    case 'l':
      askforpassword=1;
      break;
#endif
#ifdef SUPPORT_HTTPS
    case 'e': dohttps=1; lastopt=HTTPS; break;
    case 'E': dohttps=-1; break;
#endif
    case 's': dosmb=1; lastopt=SMB; break;
    case 'S': dosmb=-1; break;
    case 'T':
      i=scan_ulong(optarg,doftp?&ftptimeout_secs:&timeout_secs);
      if (i==0) {
	buffer_puts(buffer_2,"gatling: warning: could not parse timeout in seconds ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,".\n");
      }
      break;
#ifdef SUPPORT_SMB
    case 'w':
      if (str_len(optarg)>12)
	buffer_putsflush(buffer_2,"gatling: workgroup name too long (12 max)\n");
      else
	str_copy(workgroup,optarg);
      break;
#endif
#ifdef SUPPORT_CGI
    case 'C':
      errno=0;
      if (add_cgi(optarg)) {
	if (errno==ENOMEM)
	  buffer_putmflush(buffer_2,"gatling: out of memory\n");
	else
	  buffer_putmflush(buffer_2,"gatling: could not parse `",optarg,"': expected something like `\\.cgi$'\n");
      }
      break;
#endif
#ifdef SUPPORT_PROXY
    case 'O':
      errno=0;
      if (add_proxy(optarg)) {
	if (errno==ENOMEM)
	  buffer_putmflush(buffer_2,"gatling: out of memory\n");
	else
	  buffer_putmflush(buffer_2,"gatling: could not parse `",optarg,"': expected something like `127.0.0.1/8001/\\.jsp'\n");
      }
      break;
#endif
    case 'h':
usage:
      buffer_putsflush(buffer_2,
		  "usage: gatling [-hnvVtdDfFUa] [-i bind-to-ip] [-p bind-to-port] [-T seconds]\n"
		  "               [-u uid] [-c dir] [-w workgroup] [-P bytes] [-O ip/port/regex]\n"
		  "\n"
		  "\t-h\tprint this help\n"
		  "\t-v\tenable virtual hosting mode\n"
		  "\t-V\tdisable virtual hosting mode\n"
		  "\t\t(default is to try both)\n"
		  "\t-t\ttransproxy mode: do not replace :port in Host headers\n"
		  "\t-d\tgenerate directory index\n"
		  "\t-D\tdo not generate directory index\n"
		  "\t\t(default is -d unless in virtual hosting mode)\n"
		  "\t-T n\tset timeout in seconds (0 to disable, default 23)\n"
		  "\t-u uid\tswitch to this UID after binding\n"
		  "\t-c dir\tchroot to dir after binding\n"
		  "\t-n\tdo not produce logging output\n"
		  "\t-f\tprovide FTP; next -p is meant for the FTP port (default: 21)\n"
		  "\t-F\tdo not provide FTP\n"
		  "\t-U\tdisallow FTP uploads, even to world writable directories\n"
		  "\t-a\tchmod go+r uploaded files, so they can be downloaded immediately\n"
		  "\t-P n\tenable experimental prefetching code (may actually be slower)\n"
		  "\t-l\task for password (FTP server; work around buggy proxies)\n"
#ifdef SUPPORT_CGI
		  "\t-C regex\tregex for local CGI execution (\"\\.cgi\")\n"
#endif
#ifdef SUPPORT_PROXY
		  "\t-O ip/port/regex\tregex for proxy mode (\"127.0.0.1/8001/\\.jsp$\")\n"
#endif
#ifdef SUPPORT_SMB
		  "\t-w name\tset SMB workgroup\n"
#endif
#ifdef SUPPORT_HTTPS
		  "\t-e\tprovide encryption (https://...)\n"
		  "\t-E\tdo not provide encryption\n"
#endif
		  );
      return 0;
    case '?':
      break;
    }
  }
#ifdef SUPPORT_SMB
  {
    iconv_t i=iconv_open("UTF-16LE","ISO-8859-1");
    size_t X,Y;
    char* x,* y;
    X=str_len(workgroup)+1;
    Y=sizeof(workgroup_utf16);
    x=workgroup;
    y=workgroup_utf16;
#ifdef __sun__
    if (iconv(i,(const char**)&x,&X,&y,&Y)) panic("UTF-16 conversion of workgroup failed.\n");
#else
    if (iconv(i,&x,&X,&y,&Y)) panic("UTF-16 conversion of workgroup failed.\n");
#endif
    wglen=str_len(workgroup);
    wglen16=sizeof(workgroup_utf16)-Y;
  }
#endif
  if (!directory_index)
    directory_index=virtual_hosts<1;
  else if (directory_index==-1)
    directory_index=0;

  if (timeout_secs) {
    taia_now(&last);
    byte_copy(&next,sizeof(next),&last);
    next.sec.x += timeout_secs;
    byte_copy(&nextftp,sizeof(next),&last);
    nextftp.sec.x += ftptimeout_secs;
    byte_copy(&tick,sizeof(next),&last);
    ++tick.sec.x;
  }

  {
    uid_t euid=geteuid();
    if (port==0)
      port=euid?8000:80;
    if (fport==0)
      fport=euid?2121:21;
#ifdef SUPPORT_SMB
    if (sport==0)
      sport=445;
#endif
#ifdef SUPPORT_HTTPS
    if (httpsport==0)
      httpsport=euid?4433:443;
#endif
  }
#ifdef __broken_itojun_v6__
  if (byte_equal(ip,12,V4mappedprefix) || byte_equal(ip,16,V6any)) {
    if (byte_equal(ip,16,V6any)) {
      if (socket_bind6_reuse(s,ip,port,scope_id)==-1)
	panic("socket_bind6_reuse for http");
#ifdef SUPPORT_FTP
      f=socket_tcp6();
      if (doftp>=0)
	if (socket_bind6_reuse(f,ip,fport,scope_id)==-1) {
	  if (doftp==1)
	    panic("socket_bind6_reuse for ftp");
	  buffer_putsflush(buffer_2,"warning: could not bind to FTP port; FTP will be unavailable.\n");
	  io_close(f); f=-1;
	}
#endif
    } else {
      io_close(s); s=-1;
    }
    if (socket_bind4_reuse(s4,ip+12,port)==-1)
      panic("socket_bind4_reuse");
#ifdef SUPPORT_FTP
    if (doftp>=0)
      if (socket_bind4_reuse(f4,ip+12,port)==-1) {
	if (doftp==1)
	  panic("socket_bind4_reuse");
	buffer_putsflush(buffer_2,"warning: could not bind to FTP port; FTP will be unavailable.\n");
	io_close(f4); f4=-1;
      }
#endif
  } else {
    if (socket_bind6_reuse(s,ip,port,scope_id)==-1)
      panic("socket_bind6_reuse");
    s4=-1;
#ifdef SUPPORT_FTP
    if (doftp>=0)
      if (socket_bind6_reuse(f,ip,port,scope_id)==-1) {
	if (doftp==1)
	  panic("socket_bind6_reuse");
	buffer_putsflush(buffer_2,"warning: could not bind to FTP port; FTP will be unavailable.\n");
	io_close(f); f=-1;
      }
    f4=-1;
#endif
  }
  buffer_putsflush(buffer_2,"WARNING: We are taking heavy losses working around itojun KAME madness here.\n"
		            "         Please consider using an operating system with real IPv6 support instead!\n");
#else
  if (socket_bind6_reuse(s,ip,port,0)==-1)
    panic("socket_bind6_reuse");
#ifdef SUPPORT_FTP
  if (doftp>=0) {
    f=socket_tcp6();
    if (socket_bind6_reuse(f,ip,fport,scope_id)==-1) {
      if (doftp==1)
	panic("socket_bind6_reuse");
      buffer_putsflush(buffer_2,"warning: could not bind to FTP port; FTP will be unavailable.\n");
      io_close(f); f=-1;
    }
  }
#endif
#ifdef SUPPORT_SMB
  if (dosmb>=0) {
    smbs=socket_tcp6();
    if (socket_bind6_reuse(smbs,ip,sport,scope_id)==-1) {
      if (dosmb==1)
	panic("socket_bind6_reuse");
      buffer_putsflush(buffer_2,"warning: could not bind to SMB port; SMB will be unavailable.\n");
      io_close(smbs); smbs=-1;
    }
  }
#endif
#ifdef SUPPORT_HTTPS
  if (dohttps>=0) {
    httpss=socket_tcp6();
    if (socket_bind6_reuse(httpss,ip,httpsport,scope_id)==-1) {
      if (dohttps==1)
	panic("socket_bind6_reuse");
      buffer_putsflush(buffer_2,"warning: could not bind to HTTPS port; HTTPS will be unavailable.\n");
      io_close(httpss); httpss=-1;
    }
  }
#endif
#endif

  if (prepare_switch_uid(new_uid)==-1)
    goto usage;
  if (chroot_to) {
    if (chroot(chroot_to)==-1)
      panic("chroot");
    if (chdir("/")==-1)
      panic("chdir");
  }
  if (new_uid && switch_uid()==-1)
    panic("switch_uid");

  if (!io_readfile(&origdir,".")) panic("open()");
  /* get fd for . so we can always fchdir back */

  {
    char buf[IP6_FMT];
    buffer_puts(buffer_1,"starting_up 0 ");
    buffer_put(buffer_1,buf,fmt_ip6c(buf,ip));
    buffer_puts(buffer_1," ");
    buffer_putulong(buffer_1,port);
    buffer_putnlflush(buffer_1);
    if (f!=-1) {
      buffer_puts(buffer_1,"start_ftp 0 ");
      buffer_put(buffer_1,buf,fmt_ip6c(buf,ip));
      buffer_puts(buffer_1," ");
      buffer_putulong(buffer_1,fport);
      buffer_putnlflush(buffer_1);
    }
#ifdef SUPPORT_SMB
    if (smbs!=-1) {
      buffer_puts(buffer_1,"start_smb 0 ");
      buffer_put(buffer_1,buf,fmt_ip6c(buf,ip));
      buffer_puts(buffer_1," ");
      buffer_putulong(buffer_1,sport);
      buffer_putnlflush(buffer_1);
    }
#endif
#ifdef SUPPORT_HTTPS
    if (httpss!=-1) {
      buffer_puts(buffer_1,"start_https 0 ");
      buffer_put(buffer_1,buf,fmt_ip6c(buf,ip));
      buffer_puts(buffer_1," ");
      buffer_putulong(buffer_1,httpsport);
      buffer_putnlflush(buffer_1);
    }
#endif
  }

#ifdef __broken_itojun_v6__
  prepare_listen(s,&ct);
  prepare_listen(s4,&ct4);
  prepare_listen(f,&fct);
  prepare_listen(f4,&fct4);
#else
  prepare_listen(s,&ct);
#ifdef SUPPORT_FTP
  prepare_listen(f,&fct);
#endif
#ifdef SUPPORT_SMB
  prepare_listen(smbs,&sct);
#endif
#ifdef SUPPORT_HTTPS
  prepare_listen(httpss,&httpsct);
#endif
#endif

  connections=1;

  for (;;) {
    int64 i;

    if (fini==2) {
      --connections;
      io_close(s);
#ifdef __broken_itojun_v6__
      io_close(s4);
#endif
#ifdef SUPPORT_FTP
      io_close(f);
#ifdef __broken_itojun_v6__
      io_close(f4);
#endif
#endif
#ifdef SUPPORT_SMB
      io_close(smbs);
#endif
      buffer_puts(buffer_1,"closing_server_sockets ");
      buffer_putulong(buffer_1,connections);
      buffer_putnlflush(buffer_1);
      fini=0;
    }
    if (!connections) fini=1;
    if (fini) {
      buffer_putsflush(buffer_1,"stopping\n");
      break;
    }

    if (timeout_secs)
      io_waituntil(tick);
    else
      io_wait();

    if (timeout_secs) {
      taia_now(&now);
      if (now.sec.x != last.sec.x) {
	byte_copy(&last,sizeof(now),&now);
	byte_copy(&next,sizeof(now),&now);
	next.sec.x += timeout_secs;
	byte_copy(&nextftp,sizeof(now),&now);
	nextftp.sec.x += ftptimeout_secs;
	byte_copy(&tick,sizeof(next),&now);
	++tick.sec.x;
	while ((i=io_timeouted())!=-1) {
	  if (logging) {
	    char numbuf[FMT_ULONG];
	    numbuf[fmt_ulong(numbuf,i)]=0;
	    buffer_putmflush(buffer_1,"timeout ",numbuf,"\nclose/timeout ",numbuf,"\n");
#if 0
	    buffer_puts(buffer_1,"timeout ");
	    buffer_putulong(buffer_1,i);
	    buffer_puts(buffer_1,"\nclose/timeout ");
	    buffer_putulong(buffer_1,i);
	    buffer_putnlflush(buffer_1);
#endif
	  }
	  cleanup(i);
	}
      }
    }

    /* HANDLE READ EVENTS */
    while ((i=io_canread())!=-1) {
      struct http_data* H=io_getcookie(i);
      if (!H) {
	buffer_putsflush(buffer_1,"no_cookie\n");
	return 111;
      }
      H->sent_until=H->prefetched_until=0;

#ifdef SUPPORT_PROXY
      if (H->t==PROXYPOST)
	handle_read_proxypost(i,H);
      else if (H->t==HTTPPOST)
	handle_read_httppost(i,H);
      else
#endif
#ifdef SUPPORT_FTP
      if (H->t==FTPPASSIVE)
	handle_read_ftppassive(i,H);
      else
#endif
#ifdef SUPPORT_HTTPS
      if (H->t==HTTPSACCEPT)
	do_sslaccept(i,H,1);
      else
#endif
      if (is_server_connection(H->t))
	accept_server_connection(i,H,ftptimeout_secs,nextftp);
      else {
#ifdef SUPPORT_HTTPS
	if (H->t == HTTPSRESPONSE)
	  handle_write_misc(i,H,prefetchquantum);
	else
#endif
	handle_read_misc(i,H,ftptimeout_secs,nextftp);
      }
    }

    /* HANDLE WRITABLE EVENTS */
    while ((i=io_canwrite())!=-1) {
      struct http_data* h=io_getcookie(i);

#ifdef SUPPORT_FTP
      if (h->t==FTPCONTROL4 || h->t==FTPCONTROL6) {
	if (ftptimeout_secs)
	  io_timeout(i,nextftp);
      } else if (timeout_secs) {
	io_timeout(i,next);
	if (h->t==FTPSLAVE) {
	  io_timeout(h->buddy,nextftp);
	}
      }
#else
      if (timeout_secs)
	io_timeout(i,next);
#endif

#ifdef SUPPORT_PROXY
      if (h->t==PROXYSLAVE)
	handle_write_proxyslave(i,h);
      else if (h->t==PROXYPOST)
	handle_write_proxypost(i,h);
      else if (h->t==HTTPPOST)
	handle_write_httppost(i,h);
      else
#endif
#ifdef SUPPORT_HTTPS
      if (h->t==HTTPSACCEPT)
	do_sslaccept(i,h,0);
      else
#endif
#ifdef SUPPORT_FTP
      if (h->t==FTPACTIVE)
	handle_write_ftpactive(i,h);
      else
#endif
#ifdef SUPPORT_HTTPS
	if (h->t == HTTPSREQUEST)
	  handle_read_misc(i,h,ftptimeout_secs,nextftp);
	else
#endif
	handle_write_misc(i,h,prefetchquantum);
    }
  }
  io_finishandshutdown();
  return 0;
}

int epoll_create(int i) { return -1; }
