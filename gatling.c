#undef SUPPORT_SMB
#define SUPPORT_FTP
#define SUPPORT_CGI
/* #define DEBUG to enable more verbose debug messages for tracking fd
 * leaks */
// #define DEBUG

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
#ifdef SUPPORT_SMB
#include <iconv.h>
#endif
#ifdef SUPPORT_CGI
#include <regex.h>
#endif
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

static void carp(const char* routine) {
  buffer_puts(buffer_2,routine);
  buffer_puts(buffer_2,": ");
  buffer_puterror(buffer_2);
  buffer_putnlflush(buffer_2);
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

#ifdef SUPPORT_CGI
  PROXYSLAVE,	/* write request from buddy, relay response */
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
  uint16 myport;
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
};

#ifdef SUPPORT_CGI
/* gatling implements CGI as a proxy.
 * You configure a list of regular expressions, and if a request matches
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

static int add_cgi(const char* c) {
  struct cgi_proxy* x=malloc(sizeof(struct cgi_proxy));
  int i;
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

static int proxy_connection(int sockfd,const char* c) {
  struct cgi_proxy* x=cgis;
  while (x) {
    if (regexec(&x->r,c,0,0,0)==0) {
      int s;
      struct stat ss;
      struct http_data* h;

      if (stat(".cgi",&ss)==-1) continue;
      if (!(h=(struct http_data*)malloc(sizeof(struct http_data)))) continue;
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
      byte_zero(h,sizeof(struct http_data));
      h->t=PROXYSLAVE;
      h->buddy=sockfd;
      io_setcookie(s,h);
      {
	struct http_data* x=io_getcookie(sockfd);
	if (x) {
	  byte_copy(h->peerip,16,x->peerip);
	}
      }
      if (timeout_secs)
	io_timeout(s,next);
      io_wantwrite(s);
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

int proxy_is_readable(int sockfd,struct http_data* H) {
  char buf[8192];
  int i;
  char* x;
  int res=0;
  struct http_data* peer=io_getcookie(H->buddy);
  i=read(sockfd,buf,sizeof(buf));
  if (i==-1) return -1;
  if (i==0) {
    if (peer) peer->buddy=-1;
    H->buddy=-1;
    res=-3;
  } else {
    x=malloc(i);
    byte_copy(x,i,buf);
    if (peer) iob_addbuf_free(&peer->iob,x,i);
  }
  io_dontwantread(sockfd);
  io_wantwrite(H->buddy);
  return res;
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
  if (!*c) return 0;	/* no slashes?  There's something fishy */
  x=alloca(c-name+1);
  byte_copy(x,c-name,name); x[c-name]=0;
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

int header_complete(struct http_data* r) {
  long i;
  long l=array_bytes(&r->r);
  const char* c=array_start(&r->r);
  if (r->t==HTTPREQUEST) {
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

void httperror(struct http_data* r,const char* title,const char* message) {
  char* c;
  if (r->t==HTTPSERVER4 || r->t==HTTPSERVER6 || r->t==HTTPREQUEST) {
    c=r->hdrbuf=(char*)malloc(str_len(message)+str_len(title)+250);
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

int header_diff(const char* s,const char* t) {
  /* like str_diff but s may also end with '\r' or '\n' */
  register int j;
  j=0;
  for (;;) {
    if ((j=(tolower(*s)-tolower(*t)))) break; if (!*t) break; ++s; ++t;
  }
  if (*s=='\r' || *s=='\n') j=-*t;
  return j;
}

char* http_header(struct http_data* r,char* h) {
  long i;
  long l=array_bytes(&r->r);
  long sl=str_len(h);
  char* c=array_start(&r->r);
  for (i=0; i+sl+2<l; ++i)
    if (c[i]=='\n' && case_equalb(c+i+1,sl,h) && c[i+sl+1]==':') {
      c+=i+sl+2;
      if (*c==' ' || *c=='\t') ++c;
      return c;
    }
  return 0;
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
  return (c!='"' && c!='%' && c>=' ');
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

int64 http_openfile(struct http_data* h,char* filename,struct stat* ss,int sockfd) {
  char* s;
  char* args;
  unsigned long i;
  int64 fd;
  int doesgzip,doesbzip2;

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
  if (filename[i]=='?') { filename[i]=0; args=filename+i+1; }
  /* second, we need to un-urlencode the file name */
  /* we can do it in-place, the decoded string can never be longer */
  scan_urlencoded(filename,filename,&i);
  filename[i]=0;
  /* third, change /. to /: so .procmailrc is visible in ls as
   * :procmailrc, and it also thwarts most web root escape attacks */
  for (i=0; filename[i]; ++i)
    if (filename[i]=='/' && filename[i+1]=='.')
      filename[i+1]=':';
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
    if (chdir(s)==-1)
      if (chdir("default")==-1)
	if (virtual_hosts==1)
	  return -1;
  }
  while (filename[1]=='/') ++filename;
#ifdef SUPPORT_CGI
  switch ((i=proxy_connection(sockfd,filename))) {
  case -3: break;
  case -1: return -1;
  default:
    if (i>=0) {
      h->buddy=i;
      return -3;
    }
  }
#else
  (void)sockfd;
#endif
  if (filename[(i=str_len(filename))-1] == '/') {
    /* Damn.  Directory. */
    if (filename[1] && chdir(filename+1)==-1) return -1;
    h->mimetype="text/html";
    if (!open_for_reading(&fd,"index.html",ss)) {
      DIR* d;
      if (!directory_index) return -1;
      if (!(d=opendir("."))) return -1;
      if (!http_dirlisting(h,d,filename,args)) return -1;
#ifdef USE_ZLIB
      if (doesgzip) {
	uLongf destlen=h->blen+30+h->blen/1000;
	char *compressed=malloc(destlen+15);
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
    h->mimetype=mimetype(filename);
    if (!open_for_reading(&fd,filename+1,ss))
      return -1;
#ifdef DEBUG
    if (logging) {
      buffer_puts(buffer_1,"open_file ");
      buffer_putulong(buffer_1,sockfd);
      buffer_putspace(buffer_1);
      buffer_putulong(buffer_1,fd);
      buffer_putspace(buffer_1);
      buffer_puts(buffer_1,filename);
      buffer_putnlflush(buffer_1);
    }
#endif
    if (doesgzip || doesbzip2) {
      int64 gfd;
      char* tmpfilename=alloca(str_len(filename)+5);
      if (doesbzip2) {
	i=fmt_str(tmpfilename,filename+1);
	i+=fmt_str(tmpfilename+i,".bz2");
	tmpfilename[i]=0;
	if (open_for_reading(&gfd,tmpfilename,ss)) {
	  io_close(fd);
	  fd=gfd;
	  h->encoding=BZIP2;
	}
      }
      if (doesgzip && h->encoding==NORMAL) {
	i=fmt_str(tmpfilename,filename+1);
	i+=fmt_str(tmpfilename+i,".gz");
	tmpfilename[i]=0;
	if (open_for_reading(&gfd,tmpfilename,ss)) {
	  io_close(fd);
	  fd=gfd;
	  h->encoding=GZIP;
	}
      }
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
  char* c;
  const char* m;
  time_t ims=0;
  uint64 range_first,range_last;
  h->filefd=-1;

  array_cat0(&h->r);
  c=array_start(&h->r);
  if (byte_diff(c,4,"GET ") && byte_diff(c,5,"HEAD ")) {
e400:
    httperror(h,"400 Invalid Request","This server only understands GET and HEAD.");

    if (logging) {
      buffer_puts(buffer_1,"error_400 ");
      buffer_putulong(buffer_1,s);
      buffer_putsflush(buffer_1,"\n");
    }

  } else {
    char *d;
    int64 fd;
    struct stat ss;
    char* tmp;
    head=c[0]=='H';
    c+=head?5:4;
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
	buffer_puts(buffer_1,head?"HEAD/404 ":"GET/404 ");
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
      if (fd==-2) {
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
	    buffer_puts(buffer_1,head?"HEAD ":"GET ");
	    buffer_putulong(buffer_1,s);
	    buffer_puts(buffer_1," ");
	    buffer_putlogstr(buffer_1,filename);
	    buffer_puts(buffer_1," ");
	    buffer_putulong(buffer_1,h->blen);
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
#ifdef SUPPORT_CGI
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
	  c+=fmt_ulonglong(c,range_last);
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
	    iob_addfile(&h->iob,fd,range_first,range_last-range_first);
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
	  buffer_putulong(buffer_1,range_last-range_first);
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
  h->hdrbuf=forreading?"550 No such file or directory.\r\n":"550 You can't upload here!\r\n";
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
    buffer_putlogstr(buffer_1,x[1]?x+1:"/");
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
    iob_addfile(&b->iob,b->filefd,range_first,range_last-range_first);
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
    i+=fmt_ulonglong(h->hdrbuf+i,ss.st_size);
    i+=fmt_str(h->hdrbuf+i," bytes)\r\n");
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

#if 0
      buffer_puts(buffer_2,"setting b->f to DOWNLOADING for ");
      buffer_putulong(buffer_2,h->buddy);
      buffer_putnlflush(buffer_2);
#endif

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
      x=fmt_ip6c(buf,h->myip);
      x+=fmt_str(buf+x,"/");
      x+=fmt_ulong(buf+x,h->myport);
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
  h->hdrbuf="200 ok.\r\n";
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
  } else if (case_starts(c,"USER ")) {
    c+=5;
    if (case_equals(c,"ftp") || case_equals(c,"anonymous"))
      h->hdrbuf="230 No need for passwords, you're logged in now.\r\n";
    else
      h->hdrbuf="230 I only serve anonymous users.  But I'll make an exception.\r\n";
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
    else {
//      printf("iob_addbuf_free -> %s\n",h->hdrbuf);
      iob_addbuf_free(&h->iob,h->hdrbuf,str_len(h->hdrbuf));
    }
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


void smbresponse(struct http_data* h,int64 s) {
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
	c[0x24]=1;
	c[0x25]=ack; c[0x26]=0;
	c[0x27]=0; c[0x28]=0;
	uint16_pack(c+2,0x29-4);
	write(s,c,0x29);
	return;
      case 1:
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
  }
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

static void cleanup(int64 fd) {
  struct http_data* h=io_getcookie(fd);
  int buddyfd=-1;
#if 0
  if (logging) {
    buffer_puts(buffer_1,"cleanup(");
    buffer_putulonglong(buffer_1,fd);
    buffer_putsflush(buffer_1,")\n");
  }
#endif
  if (h) {
    buddyfd=h->buddy;
#if defined(SUPPORT_FTP) || defined(SUPPORT_CGI)
    if (h->t==FTPSLAVE || h->t==FTPACTIVE || h->t==FTPPASSIVE || h->t==PROXYSLAVE || h->t==HTTPREQUEST) {
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
#ifdef DEBUG
    if (logging) {
      buffer_puts(buffer_1,"cleanup_filefd_close ");
      buffer_putulong(buffer_1,fd);
      buffer_putspace(buffer_1);
      if (h->filefd==-1)
	buffer_puts(buffer_1,"-1");
      else
	buffer_putulong(buffer_1,h->filefd);
      buffer_putnlflush(buffer_1);
    }
#endif
    if (h->filefd!=-1) io_close(h->filefd);
#ifdef SUPPORT_FTP
    free(h->ftppath);
#endif
    free(h);
  }
#if 0
  buffer_puts(buffer_2,"cleaning up fd #");
  buffer_putulong(buffer_2,fd);
  buffer_putnlflush(buffer_2);
#endif
  io_close(fd);
  if (buddyfd>=0) {
#if 0
    buffer_puts(buffer_2,"cleaning up buddy fd #");
    buffer_putulong(buffer_2,buddyfd);
    buffer_putnlflush(buffer_2);
#endif
    h=io_getcookie(buddyfd);
    if (h) h->buddy=-1;
    cleanup(buddyfd);
  }
}

static int fini;

void sighandler(int sig) {
  fini=1;
}

int main(int argc,char* argv[]) {
  int s;
  int f=-1;
#ifdef SUPPORT_SMB
  int smbs=-1;
  enum conntype sct=SMBSERVER6;
#endif
  int doftp=0;
  int dosmb=0;
  enum { HTTP, FTP, SMB } lastopt=HTTP;
  enum conntype ct=HTTPSERVER6;
#ifdef SUPPORT_FTP
  enum conntype fct=FTPSERVER6;
#endif
#ifdef __broken_itojun_v6__
#warning "working around idiotic openbse ipv6 stupidity - please kick itojun for this!"
  int s4;
  enum conntype ct4=HTTPSERVER4;
#ifdef SUPPORT_FTP
  int f4;
  enum conntype fct4=FTPSERVER4;
#endif
#endif
  uint32 scope_id;
  char ip[16];
  uint16 port,fport,sport;
  tai6464 now,last,tick,nextftp;
  unsigned long ftptimeout_secs=600;
  char* new_uid=0;
  char* chroot_to=0;
  uint64 prefetchquantum=0;

  s=socket_tcp6();
#ifdef __broken_itojun_v6__
  f4=socket_tcp4();
  s4=socket_tcp4();
#endif

  signal(SIGPIPE,SIG_IGN);

  {
    struct sigaction sa;
    byte_zero(&sa,sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler=sighandler;
    sigaction(SIGINT,&sa,0);
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
    int c=getopt(argc,argv,"P:hnfFi:p:vVdDtT:c:u:Uaw:sSC:");
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
    case 'f': doftp=1; lastopt=FTP; break;
    case 'F': doftp=-1; break;
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
      if (add_cgi(optarg)) {
	buffer_puts(buffer_2,"gatling: could not parse `");
	buffer_puts(buffer_2,optarg);
	buffer_putsflush(buffer_2,"´: expected something like `127.0.0.1/8001/cgi$´\n");
      }
      break;
#endif
    case 'h':
usage:
      buffer_putsflush(buffer_2,
		  "usage: gatling [-hnvVtdD] [-i bind-to-ip] [-p bind-to-port] [-T seconds]\n"
		  "               [-u uid] [-c dir] [-w workgroup] [-P bytes]\n"
		  "\n"
		  "\t-h\tprint this help\n"
		  "\t-v\tenable virtual hosting mode\n"
		  "\t-V\tdisable virtual hosting mode\n"
		  "\t\t(default is to try both)\n"
		  "\t-t\ttransproxy mode: do not replace :port in Host headers\n"
		  "\t-d\tgenerate directory index\n"
		  "\t-D\tdo not generate directory index\n"
		  "\t-T n\tset timeout in seconds (0 to disable, default 23)\n"
		  "\t-u uid\tswitch to this UID after binding\n"
		  "\t-c dir\tchroot to dir after binding\n"
		  "\t\t(default is -d unless in virtual hosting mode)\n"
		  "\t-n\tdo not produce logging output\n"
		  "\t-f\tprovide FTP; next -p is meant for the FTP port (default: 21)\n"
		  "\t-F\tdo not provide FTP\n"
		  "\t-U\tdisallow FTP uploads, even to world writable directories\n"
		  "\t-a\tchmod go+r uploaded files, so they can be downloaded immediately\n"
		  "\t-P n\tenable experimental prefetching code (may actually be slower)\n"
#ifdef SUPPORT_CGI
		  "\t-C ip/port/regex\tCGI proxy\n"
#endif
#ifdef SUPPORT_SMB
		  "\t-w name\tset SMB workgroup\n"
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

  if (port==0)
    port=geteuid()?8000:80;
  if (fport==0)
    fport=geteuid()?2121:21;
#ifdef SUPPORT_SMB
  if (sport==0)
    sport=445;
#endif
#ifdef __broken_itojun_v6__
  if (byte_equal(ip,12,V4mappedprefix) || byte_equal(ip,16,V6any)) {
    if (byte_equal(ip,16,V6any)) {
      f=socket_tcp6();
      if (socket_bind6_reuse(s,ip,port,scope_id)==-1)
	panic("socket_bind6_reuse for http");
      if (doftp>=0)
	if (socket_bind6_reuse(f,ip,fport,scope_id)==-1) {
	  if (doftp==1)
	    panic("socket_bind6_reuse for ftp");
	  buffer_putsflush(buffer_2,"warning: could not bind to FTP port; FTP will be unavailable.\n");
	  io_close(f); f=-1;
	}
    } else {
      io_close(s); s=-1;
    }
    if (socket_bind4_reuse(s4,ip+12,port)==-1)
      panic("socket_bind4_reuse");
    if (doftp>=0)
      if (socket_bind4_reuse(f4,ip+12,port)==-1) {
	if (doftp==1)
	  panic("socket_bind4_reuse");
	buffer_putsflush(buffer_2,"warning: could not bind to FTP port; FTP will be unavailable.\n");
	io_close(f4); f4=-1;
      }
  } else {
    if (socket_bind6_reuse(s,ip,port,scope_id)==-1)
      panic("socket_bind6_reuse");
    s4=-1;
    if (doftp>=0)
      if (socket_bind6_reuse(f,ip,port,scope_id)==-1) {
	if (doftp==1)
	  panic("socket_bind6_reuse");
	buffer_putsflush(buffer_2,"warning: could not bind to FTP port; FTP will be unavailable.\n");
	io_close(f); f=-1;
      }
    f4=-1;
  }
  buffer_putsflush(buffer_2,"WARNING: We are taking heavy losses working around itojun KAME madness here.\n"
		            "         Please consider using an operating system with real IPv6 support instead!\n");
#else
  if (socket_bind6_reuse(s,ip,port,0)==-1)
    panic("socket_bind6_reuse");
  if (doftp>=0) {
    f=socket_tcp6();
    if (socket_bind6_reuse(f,ip,fport,scope_id)==-1) {
      if (doftp==1)
	panic("socket_bind6_reuse");
      buffer_putsflush(buffer_2,"warning: could not bind to FTP port; FTP will be unavailable.\n");
      io_close(f); f=-1;
    }
  }
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
    buffer_put(buffer_1,buf,fmt_ip6(buf,ip));
    buffer_puts(buffer_1," ");
    buffer_putulong(buffer_1,port);
    buffer_putnlflush(buffer_1);
    if (f!=-1) {
      buffer_puts(buffer_1,"start_ftp 0 ");
      buffer_put(buffer_1,buf,fmt_ip6(buf,ip));
      buffer_puts(buffer_1," ");
      buffer_putulong(buffer_1,fport);
      buffer_putnlflush(buffer_1);
    }
#ifdef SUPPORT_SMB
    if (smbs!=-1) {
      buffer_puts(buffer_1,"start_smb 0 ");
      buffer_put(buffer_1,buf,fmt_ip6(buf,ip));
      buffer_puts(buffer_1," ");
      buffer_putulong(buffer_1,sport);
      buffer_putnlflush(buffer_1);
    }
#endif
  }

#ifdef __broken_itojun_v6__
  if (s!=-1) {
    if (socket_listen(s,16)==-1)
      panic("socket_listen");
    io_nonblock(s);
    if (!io_fd(s))
      panic("io_fd");
    io_setcookie(s,&ct);
    io_wantread(s);
  }
  if (s4!=-1) {
    if (socket_listen(s4,16)==-1)
      panic("socket_listen");
    io_nonblock(s4);
    if (!io_fd(s4))
      panic("io_fd");
    io_setcookie(s4,&ct4);
    io_wantread(s4);
  }
  if (f!=-1) {
    if (socket_listen(f,16)==-1)
      panic("socket_listen");
    io_nonblock(f);
    if (!io_fd(f))
      panic("io_fd");
    io_setcookie(f,&fct);
    io_wantread(f);
  }
  if (f4!=-1) {
    if (socket_listen(f4,16)==-1)
      panic("socket_listen");
    io_nonblock(f4);
    if (!io_fd(f4))
      panic("io_fd");
    io_setcookie(f4,&fct4);
    io_wantread(f4);
  }
#else
  if (socket_listen(s,16)==-1)
    panic("socket_listen");
  io_nonblock(s);
  if (!io_fd(s))
    panic("io_fd");
  io_setcookie(s,&ct);
  io_wantread(s);
#ifdef SUPPORT_FTP
  if (f!=-1) {
    if (socket_listen(f,16)==-1)
      panic("socket_listen");
    io_nonblock(f);
    if (!io_fd(f))
      panic("io_fd");
    io_setcookie(f,&fct);
    io_wantread(f);
  }
#endif
#ifdef SUPPORT_SMB
  if (smbs!=-1) {
    if (socket_listen(smbs,16)==-1)
      panic("socket_listen");
    io_nonblock(smbs);
    if (!io_fd(smbs))
      panic("io_fd");
    io_setcookie(smbs,&sct);
    io_wantread(smbs);
  }
#endif
#endif

  for (;;) {
    int64 i;

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
	    buffer_puts(buffer_1,"timeout ");
	    buffer_putulong(buffer_1,i);
	    buffer_puts(buffer_1,"\nclose/timeout ");
	    buffer_putulong(buffer_1,i);
	    buffer_putnlflush(buffer_1);
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
#ifdef SUPPORT_CGI
      if (H->t==PROXYSLAVE) {
	switch (proxy_is_readable(i,H)) {
	case -1:
	  {
	    struct http_data* h=io_getcookie(H->buddy);
	    if (logging) {
	      buffer_puts(buffer_1,"proxy_read_error ");
	      buffer_putulong(buffer_1,i);
	      buffer_putspace(buffer_1);
	      buffer_puterror(buffer_1);
	      buffer_puts(buffer_1,"\nclose/acceptfail ");
	      buffer_putulong(buffer_1,i);
	      buffer_putnlflush(buffer_1);
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
      } else
#endif
#ifdef SUPPORT_FTP
      if (H->t==FTPPASSIVE) {
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
      } else
#endif
      if (H->t==HTTPSERVER6 || H->t==HTTPSERVER4
#ifdef SUPPORT_FTP
	|| H->t==FTPSERVER6 || H->t==FTPSERVER4
#endif
#ifdef SUPPORT_SMB
	|| H->t==SMBSERVER6 || H->t==SMBSERVER4
#endif
	  ) {
	/* This is an FTP or HTTP or SMB server connection.
	 * This read event means that someone connected to us.
	 * accept() the connection, establish connection type from
	 * server connection type, and put the new connection into the
	 * state table */
	int n;
	while (1) {
#ifdef __broken_itojun_v6__
	  if (H->t==HTTPSERVER4 || H->t==FTPSERVER4
#ifdef SUPPORT_SMB
	                                            || H->t==SMBSERVER4
#endif
	                                                               ) {
	    byte_copy(ip,12,V4mappedprefix);
	    scope_id=0;
	    n=socket_accept4(i,ip+12,&port);
	  } else
#endif
	    n=socket_accept6(i,ip,&port,&scope_id);
	  if (n==-1) break;
	  {
	    char buf[IP6_FMT];

	    if (logging) {
	      buffer_puts(buffer_1,"accept ");
	      buffer_putulong(buffer_1,n);
	      buffer_puts(buffer_1," ");
	      buffer_put(buffer_1,buf,byte_equal(ip,12,V4mappedprefix)?fmt_ip4(buf,ip+12):fmt_ip6(buf,ip));
	      buffer_puts(buffer_1," ");
	      buffer_putulong(buffer_1,port);
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
	      h->myscope_id=scope_id;
	      if (H->t==HTTPSERVER4 || H->t==HTTPSERVER6) {
		h->t=HTTPREQUEST;
		if (timeout_secs)
		  io_timeout(n,next);
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
      } else {
	/* This is a TCP client connection waiting for input, i.e.
	 *   - an HTTP connection waiting for a HTTP request, or
	 *   - an FTP connection waiting for a command, or
	 *   - an FTP upload waiting for more data, or
	 *   - an SMB connection waiting for the next command */
	char buf[8192];
	int l=io_tryread(i,buf,sizeof buf);
	if (l==-3) {
#ifdef SUPPORT_FTP
ioerror:
#endif
	  if (logging) {
	    buffer_puts(buffer_1,"io_error ");
	    buffer_putulong(buffer_1,i);
	    buffer_puts(buffer_1," ");
	    buffer_puterror(buffer_1);
	    buffer_puts(buffer_1,"\nclose/readerr ");
	    buffer_putulong(buffer_1,i);
	    buffer_putnlflush(buffer_1);
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
		buffer_puts(buffer_1,"received ");
		buffer_putulong(buffer_1,i);
		buffer_putspace(buffer_1);
		buffer_putulonglong(buffer_1,ss.st_size);
		buffer_putnlflush(buffer_1);
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
	    } else if (array_bytes(&H->r)>8192) {
	      httperror(H,"500 request too long","You sent too much headers");
	      array_reset(&H->r);
	      goto emerge;
	    } else if ((l=header_complete(H))) {
	      long alen;
pipeline:
	      if (H->t==HTTPREQUEST)
		httpresponse(H,i,l);
#ifdef SUPPORT_SMB
	      else if (H->t==SMBREQUEST)
		smbresponse(H,i);
#endif
#ifdef SUPPORT_FTP
	      else
		ftpresponse(H,i);
#endif
	      if (l < (alen=array_bytes(&H->r))) {
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
    }

    /* HANDLE WRITABLE EVENTS */
    while ((i=io_canwrite())!=-1) {
      struct http_data* h=io_getcookie(i);
      int64 r;
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
#ifdef SUPPORT_CGI
      if (h->t==PROXYSLAVE) {
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
	io_dontwantwrite(i);
	io_wantread(i);
      }
      else
#endif
      if (h->t==FTPACTIVE) {
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
	    buffer_put(buffer_1,buf,fmt_ip6(buf,h->peerip));
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
      } else {
	r=iob_send(i,&h->iob);
	if (r==-1)
	  io_eagain(i);
	else if (r<=0) {
	  if (r==-3) {
	    if (logging) {
	      buffer_puts(buffer_1,"socket_error ");
	      buffer_putulong(buffer_1,i);
	      buffer_puts(buffer_1," ");
	      buffer_puterror(buffer_1);
	      buffer_puts(buffer_1,"\nclose/writefail ");
	      buffer_putulong(buffer_1,i);
	      buffer_putnlflush(buffer_1);
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
	  } else {
#ifdef SUPPORT_CGI
	    if (h->t == HTTPREQUEST && h->buddy!=-1) {
	      io_dontwantwrite(s);
	      io_wantread(h->buddy);
	      continue;
	    }
#endif
	    if (logging && h->t == HTTPREQUEST) {
	      buffer_puts(buffer_1,"request_done ");
	      buffer_putulong(buffer_1,i);
	      buffer_putnlflush(buffer_1);
	    }
	    array_trunc(&h->r);
	    iob_reset(&h->iob);
	    h->hdrbuf=0;
	    if (h->keepalive) {
	      iob_reset(&h->iob);
#ifdef DEBUG
	      if (logging) {
		buffer_puts(buffer_1,"keepalive_cleanup_filefd_close ");
		buffer_putulong(buffer_1,i);
		buffer_putspace(buffer_1);
		if (h->filefd==-1)
		  buffer_puts(buffer_1,"-1");
		else
		  buffer_putulong(buffer_1,h->filefd);
		buffer_putnlflush(buffer_1);
	      }
#endif
	      if (h->filefd!=-1) { io_close(h->filefd); h->filefd=-1; }
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
    }
  }
  io_finishandshutdown();
  return 0;
}
