#include "features.h"
#include "gatling.h"

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
#include "rangecheck.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#ifndef __MINGW32__
#include <sys/resource.h>
#include <sys/socket.h>
#include <pwd.h>
#include <grp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/mman.h>
#include <fnmatch.h>
#include <sys/wait.h>
#endif
#include <stdlib.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include "version.h"
#include <assert.h>
#ifdef SUPPORT_SMB
#include <iconv.h>
#endif
#ifdef SUPPORT_PROXY
#include <regex.h>
#endif
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
// #include <crypt.h>
#include <md5.h>
#include "havealloca.h"
#include "havesetresuid.h"

unsigned long instances=1;
unsigned long timeout_secs=23;
tai6464 now,next;

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

#ifdef DEBUG_EVENTS
void new_io_wantwrite(int64 s,const char* file,unsigned int line) {
  char a[FMT_ULONG];
  char b[FMT_ULONG];
  a[fmt_ulong(a,s)]=0;
  b[fmt_ulong(b,line)]=0;
  buffer_putmflush(buffer_2,"DEBUG: ",file,":",b,": io_wantwrite(",a,")\n");
  io_wantwrite(s);
}

void new_io_dontwantwrite(int64 s,const char* file,unsigned int line) {
  char a[FMT_ULONG];
  char b[FMT_ULONG];
  a[fmt_ulong(a,s)]=0;
  b[fmt_ulong(b,line)]=0;
  buffer_putmflush(buffer_2,"DEBUG: ",file,":",b,": io_dontwantwrite(",a,")\n");
  io_dontwantwrite(s);
}

void new_io_wantread(int64 s,const char* file,unsigned int line) {
  char a[FMT_ULONG];
  char b[FMT_ULONG];
  a[fmt_ulong(a,s)]=0;
  b[fmt_ulong(b,line)]=0;
  buffer_putmflush(buffer_2,"DEBUG: ",file,":",b,": io_wantread(",a,")\n");
  io_wantread(s);
}

void new_io_dontwantread(int64 s,const char* file,unsigned int line) {
  char a[FMT_ULONG];
  char b[FMT_ULONG];
  a[fmt_ulong(a,s)]=0;
  b[fmt_ulong(b,line)]=0;
  buffer_putmflush(buffer_2,"DEBUG: ",file,":",b,": io_dontwantread(",a,")\n");
  io_dontwantread(s);
}

#define io_wantwrite(s) new_io_wantwrite(s,__FILE__,__LINE__)
#define io_wantread(s) new_io_wantread(s,__FILE__,__LINE__)
#define io_dontwantwrite(s) new_io_dontwantwrite(s,__FILE__,__LINE__)
#define io_dontwantread(s) new_io_dontwantread(s,__FILE__,__LINE__)
#endif

const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";

#ifdef SUPPORT_CGI
int forksock[2];
#endif

#if defined(__OpenBSD__) || defined(__NetBSD__)
#define __broken_itojun_v6__
#endif

int virtual_hosts;
int transproxy;
int directory_index;
int logging;
int nouploads;
int chmoduploads;
#ifdef __MINGW32__
char origdir[PATH_MAX];
#else
int64 origdir;
#endif

#ifdef SUPPORT_SMB
char workgroup[20]="FNORD";
int wglen;
char workgroup_utf16[100];
int wglen16;
#endif

static void carp(const char* routine) {
  buffer_putmflush(buffer_2,routine,": ",strerror(errno),"\n");
}

static void panic(const char* routine) {
  carp(routine);
  exit(111);
}

#ifdef SMDEBUG
const char* conntypestring[LAST_UNUNSED];

void setup_smdebug_strings() {
  conntypestring[HTTPSERVER6]="HTTPSERVER6";
  conntypestring[HTTPSERVER4]="HTTPSERVER4";
  conntypestring[HTTPREQUEST]="HTTPREQUEST";

#ifdef SUPPORT_FTP
  conntypestring[FTPSERVER6]="FTPSERVER6";
  conntypestring[FTPSERVER4]="FTPSERVER4";
  conntypestring[FTPCONTROL6]="FTPCONTROL6";
  conntypestring[FTPCONTROL4]="FTPCONTROL4";
  conntypestring[FTPPASSIVE]="FTPPASSIVE";
  conntypestring[FTPACTIVE]="FTPACTIVE";
  conntypestring[FTPACTIVE]="FTPSLAVE";
#endif

#ifdef SUPPORT_SMB
  conntypestring[SMBSERVER6]="SMBSERVER6";
  conntypestring[SMBSERVER4]="SMBSERVER4";
  conntypestring[SMBREQUEST]="SMBREQUEST";
#endif

#ifdef SUPPORT_PROXY
  conntypestring[PROXYSLAVE]="PROXYSLAVE";
  conntypestring[PROXYPOST]="PROXYPOST";
  conntypestring[HTTPPOST]="HTTPPOST";
#endif

#ifdef SUPPORT_HTTPS
  conntypestring[HTTPSSERVER6]="HTTPSSERVER6";
  conntypestring[HTTPSSERVER4]="HTTPSSERVER4";
  conntypestring[HTTPSACCEPT]="HTTPSACCEPT";
  conntypestring[HTTPSREQUEST]="HTTPSREQUEST";
  conntypestring[HTTPSRESPONSE]="HTTPSRESPONSE";
#endif
}
#endif

unsigned long connections;
unsigned long http_connections, https_connections, ftp_connections, smb_connections;
unsigned long cps,cps1;	/* connections per second */
unsigned long rps,rps1;	/* requests per second */
unsigned long eps,eps1;	/* events per second */
unsigned long long tin,tin1;	/* traffic inbound */
unsigned long long tout,tout1;	/* traffic outbound */


#ifdef SUPPORT_THREADED_OPEN
unsigned int threads;
int threadpipe_query[2];
int threadpipe_response[2];

void* worker_thread(void* unused) {
  int src=threadpipe_query[0];
  int dest=threadpipe_response[1];
  (void)unused;
  for (;;) {
    int fd;
    struct http_data* x;
    if (read(src,&fd,sizeof(fd))!=fd) return 0;
    x=io_getcookie(fd);
    if (!x) continue;
    if (fchdir(x->cwd)==-1) continue;
    x->filefd=open(x->name_of_file_to_open,O_RDONLY);
    write(dest,&fd,sizeof(fd));
  }
}

void init_threads(int n) {
  threads=0;
  if (n<=0) return;
  if (threads>0) {
    int i;
    if (pipe(threadpipe_query)==-1 || pipe(threadpipe_response)==-1) return;
    for (i=0; i<n; ++i) {
      pthread_t tmp;
      pthread_create(&tmp,0,worker_thread,0);
      pthread_detach(tmp);
    }
    threads=n;
  }
}
#endif


#if defined(SUPPORT_PROXY) || defined(SUPPORT_CGI)
/* You configure a list of regular expressions, and if a request matches
 * one of them, the request is forwarded to some other IP:port.  You can
 * run another httpd there that can handle CGI, PHP, JSP and whatnot. */
struct cgi_proxy* cgis,* last;

char** _envp;

/* if port==0 then execute the CGI locally */
#endif

#ifdef SUPPORT_CGI
static int add_cgi(const char* c) {
  struct cgi_proxy* x=malloc(sizeof(struct cgi_proxy));
  if (!x) return -1;
  byte_zero(x,sizeof(struct cgi_proxy));
  if (!strcmp(c,"+x"))
    x->file_executable=1;
  else if (regcomp(&x->r,c,REG_EXTENDED|REG_NOSUB)) {
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

void cleanup(int64 fd) {
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
    if (h->t==HTTPREQUEST) --http_connections;
#ifdef SUPPORT_FTP
    if (h->t==FTPCONTROL4 || h->t==FTPCONTROL6) --ftp_connections;
#endif
#ifdef SUPPORT_SMB
    if (h->t==SMBREQUEST) --smb_connections;
#endif
#ifdef SUPPORT_HTTPS
    if (h->t==HTTPSREQUEST) --https_connections;
#endif

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


int open_for_reading(int64* fd,const char* name,struct stat* SS) {
  /* only allow reading of world readable files */
  if (io_readfile(fd,name)) {
#ifdef __MINGW32__
    SS->st_size=GetFileSize((HANDLE)(uintptr_t)*fd,0);
#else
    struct stat ss;
    if (!SS) SS=&ss;
    if (fstat(*fd,SS)==-1 || !(SS->st_mode&S_IROTH)) {
      close(*fd);
      *fd=-1;
      return 0;
    }
#endif
    return 1;
  }
  return 0;
}

#ifdef SUPPORT_FTP
int open_for_writing(int64* fd,const char* name) {
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
int canonpath(char* s) {
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

size_t header_complete(struct http_data* r) {
  long i;
  long l=array_bytes(&r->r);
  const char* c=array_start(&r->r);
  if (r->t==HTTPREQUEST || r->t==HTTPPOST
#ifdef SUPPORT_HTTPS
      || r->t==HTTPSREQUEST
#endif
     )
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

void httperror_realm(struct http_data* r,const char* title,const char* message,const char* realm,int nobody) {
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
      c+=fmt_ulong(c,str_len(message)+str_len(title)-4+17);
      if (realm) {
	c+=fmt_str(c,"\r\nWWW-Authenticate: Basic realm=\"");
	c+=fmt_str(c,realm);
	c+=fmt_str(c,"\"");
      }
      c+=fmt_str(c,"\r\n\r\n");
      if (!nobody) {
	c+=fmt_str(c,"<title>");
	c+=fmt_str(c,title+4);
	c+=fmt_str(c,"</title>\n");
	c+=fmt_str(c,message);
	c+=fmt_str(c,"\n");
      }
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

void httperror(struct http_data* r,const char* title,const char* message,int nobody) {
  httperror_realm(r,title,message,0,nobody);
}

unsigned int fmt_2digits(char* dest,int i) {
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

const char* mimetypesfilename;

char* http_header_blob(char* b,long l,char* h) {
  long i;
  long sl=str_len(h);
  for (i=0; i+sl+2<l; ++i)
    if (b[i]=='\n' && case_equalb(b+i+1,sl,h) && b[i+sl+1]==':') {
      b+=i+sl+2;
      while (*b==' ' || *b=='\t') ++b;
      return b;
    }
  return 0;
}

char* http_header(struct http_data* r,char* h) {
  return http_header_blob(array_start(&r->r),array_bytes(&r->r),h);
}

char* base;

int sort_name_a(de* x,de* y) { return (str_diff(base+x->name,base+y->name)); }
int sort_name_d(de* x,de* y) { return (str_diff(base+y->name,base+x->name)); }
int sort_mtime_a(de* x,de* y) { return x->ss.st_mtime-y->ss.st_mtime; }
int sort_mtime_d(de* x,de* y) { return y->ss.st_mtime-x->ss.st_mtime; }
int sort_size_a(de* x,de* y) { return x->ss.st_size-y->ss.st_size; }
int sort_size_d(de* x,de* y) { return y->ss.st_size-x->ss.st_size; }


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

int validate_smb_packet(char* pkt,unsigned long len) {
  /* we actually received len bytes from the wire, so pkt+len does not
   * overflow; we got len bytes, because the netbios header said there
   * were that many bytes in the packet. */
  struct smbheader* s=(struct smbheader*)pkt;
  char* x;
  /* demand that we have at least a full smbheader and wordcount */
  if (len>=sizeof(struct smbheader)+1 &&
      byte_equal(s->protocol,4,"\xffSMB")) {	/* signature needs to be there */
    x=pkt+sizeof(smbheader);
    for (;;) {
      int done;
      if (!range_arrayinbuf(pkt,len,x,(unsigned char)*x,2))
	return -1;
      done=(x[1]==0xff);	/* 0xff is the end marker for AndX */
      x+=1+(unsigned char)*x*2+2;
      if (!range_bufinbuf(pkt,len,x,uint16_read(x-2)))
	return -1;
      if (done) break;
    }
  } else
    return -1;
  return 0;
}

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

  ++rps1;
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


#ifndef __MINGW32__
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
#ifdef LIBC_HAS_SETRESUID
  if (setresgid(__gid,__gid,__gid)) return -1;
  if (setgroups(1,&__gid)) return -1;
  if (setresuid(__uid,__uid,__uid)) return -1;
#else
  if (setgid(__gid)) return -1;
  if (setgroups(1,&__gid)) return -1;
  if (setuid(__uid)) return -1;
#endif
  return 0;
}
#endif

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
  "AUTH_TYPE=",
  "CONTENT_TYPE=",
  "CONTENT_LENGTH=",
  "QUERY_STRING=",
  "PATH_INFO=",
  "PATH_TRANSLATED=",
  "REMOTE_USER=",
  0
};

int cgienvneeded(const char* httpreq,size_t reqlen) {
  int i,j,envc;
  for (i=envc=0; _envp[i]; ++i) {
    int found=0;
    if (str_start(_envp[i],"HTTP_"))
      found=1;
    else
      for (j=0; cgivars[j]; ++j)
	if (str_start(_envp[i],cgivars[j])) { found=1; break; }
    if (!found) ++envc;
  }

  /* now collect all normal HTTP headers */

  {
    const char* x=httpreq;
    const char* max=x+reqlen;
    for (;x<max && *x!='\n';++x) ;	/* Skip GET */
    for (;x<max;++x)
      if (*x=='\n')
	++envc;
  }
  return envc;
}


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
      char* servername,* httpversion,* authtype,* contenttype,* contentlength,* remoteuser;
      char* path_translated;

      if (buffer_get(in,httpreq,reqlen) == reqlen &&
	  buffer_get(in,path,dirlen) == dirlen &&
	  buffer_get(in,remoteaddr,ralen) == ralen &&
	  buffer_get(in,(char*)&port,2) == 2 &&
	  buffer_get(in,(char*)&myport,2) == 2) {

	httpreq[reqlen]=0;
	path[dirlen]=0;
	remoteaddr[ralen]=0;

	if (dirlen==0 || chdir(path)==0) {
	  /* now find cgi */
	  char* cginame,* origcginame;

	  origcginame=cginame=httpreq+5+(httpreq[0]=='P');
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
	      i=j;
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
		  size_t dl;
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
#ifdef sgi
		int r=fork();
#else
		int r=vfork();
#endif
		if (r==-1)
		  msg="vfork failed!";
		else if (r==0) {
		  /* child */
		  int plusx=0;
		  pid_t pid;
		  code=0;
		  write(fd,&code,4);
		  write(fd,&code,4);
		  pid=getpid();
		  write(fd,&pid,sizeof(pid));
		  if (cginame[(j=strlen(cginame))-1]=='/') {	/* can happen in the -C+x case */
		    char* temp=alloca(j+10);
		    j=fmt_str(temp,cginame);
		    j+=fmt_str(temp+j,"index.html");
		    temp[j]=0;
		    cginame=temp;
		    plusx=1;
		  }
		  if (io_passfd(fd,sock[0])==0) {
		    char* argv[]={cginame,0};
		    char** envp;
		    int envc;

		    envc=cgienvneeded(httpreq,reqlen);

		    envp=(char**)alloca(sizeof(char*)*(envc+20));
		    envc=0;

		    for (i=0; _envp[i]; ++i) {
		      int found=0;
		      if (str_start(_envp[i],"HTTP_"))
			found=1;
		      else
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
		    if (pathinfo) envp[envc++]=pathinfo;
		    if (path_translated) envp[envc++]=path_translated;

		    envp[envc]=alloca(30+str_len(origcginame));
		    i=fmt_str(envp[envc],"SCRIPT_NAME=");
		    i+=fmt_str(envp[envc]+i,origcginame-1);
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

		    {
		      char* x=httpreq;
		      char* max=x+reqlen;
		      char* y;

		      for (;x<max && *x!='\n';++x) ;	/* Skip GET */

		      for (y=++x;x<max;++x)
			if (*x=='\n') {

			  if (x>y && x[-1]=='\r') --x;

			  if (x>y) {
			    char* s=alloca(x-y+7);
			    int i,j;

			    byte_copy(s,5,"HTTP_");
			    j=5;
			    for (i=0; i<x-y; ++i) {
			      if (y[i]==':') {
				++i;
				while (i<x-y && (y[i]==' ' || y[i]=='\t')) ++i;
				s[j]='='; ++j;
				for (; i<x-y; ++i) {
				  s[j]=y[i];
				  ++j;
				}
				s[j]=0;
				envp[envc]=s;
				++envc;
				break;
			      }
			      if (y[i]=='-')
				s[j]='_';
			      else if (y[i]>='a' && y[i]<='z')
				s[j]=y[i]-'a'+'A';
			      else if (y[i]>='A' && y[i]<='Z')
				s[j]=y[i];
			      else {
				s=0; break;
			      }
			      ++j;
			    }
			  }
			  if (*x=='\r') ++x;
			  y=x+1;
			}
		    }

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
		  {
		    static char e[]="HTTP/1.0 503 Gateway Broken\r\nServer: " RELEASE "\r\nContent-Length: 15\r\nContent-Type: text/html\r\n\r\nGateway Broken.";
		    write(1,e,sizeof(e)-1);
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
#ifdef SUPPORT_SERVERSTATUS
    if (H->t==HTTPSERVER4 || H->t==HTTPSERVER6) ++http_connections;
#ifdef SUPPORT_HTTPS
    if (H->t==HTTPSSERVER4 || H->t==HTTPSSERVER6) ++https_connections;
#endif
#ifdef SUPPORT_FTP
    if (H->t==FTPSERVER4 || H->t==FTPSERVER6) ++ftp_connections;
#endif
#ifdef SUPPORT_SMB
    if (H->t==SMBSERVER4 || H->t==SMBSERVER6) ++smb_connections;
#endif
#endif
    ++cps1;
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

    if (io_fd(n)) {
      struct http_data* h=(struct http_data*)malloc(sizeof(struct http_data));
      if (h) {
	io_nonblock(n);
	H->sent=H->received=0;
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
#ifdef __MINGW32__
//	  printf("chdir(\"%s\") -> %d\n",origdir,chdir(origdir));
//	  chdir(origdir);
#else
	  fchdir(origdir);
#endif
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
#ifdef SUPPORT_MULTIPROC
    if (instances>1) break;
#endif
  }
  if (errno==EAGAIN)
    io_eagain(i);
  else
#ifdef __broken_itojun_v6__
    carp(H->t==HTTPSERVER4||H->t==FTPSERVER4?"socket_accept4":"socket_accept6");
#else
    if (errno==EINVAL) {
      static int64 lasteinval;
      if (lasteinval!=i) {
	lasteinval=i;
	carp("socket_accept6");
      }
    }
#endif
}

#ifdef SUPPORT_HTTPS
int handle_ssl_error_code(int sock,int code,int reading) {
//  printf("handle_ssl_error_code(sock %d,code %d,reading %d)\n",sock,code,reading);
  switch (code) {
  case SSL_ERROR_WANT_READ:
    io_wantread(sock);
    io_dontwantwrite(sock);
    return 0;
  case SSL_ERROR_WANT_WRITE:
    io_wantwrite(sock);
    io_dontwantread(sock);
    return 0;
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
    return -1;
  default:
    if (logging) {
      buffer_puts(buffer_1,"ssl_protocol_error ");
      buffer_putulong(buffer_1,sock);
      buffer_puts(buffer_1,"\nclose/readerr ");
      buffer_putulong(buffer_1,sock);
      buffer_putnlflush(buffer_1);
    }
    return -1;
  }
}

void do_sslaccept(int sock,struct http_data* h,int reading) {
  int r=SSL_get_error(h->ssl,SSL_accept(h->ssl));
//  printf("do_sslaccept -> %d\n",r);
  if (r==SSL_ERROR_NONE) {
#if 0
    h->writefail=1;
#endif
    h->t=HTTPSREQUEST;
    if (logging) {
      buffer_puts(buffer_1,"ssl_handshake_ok ");
      buffer_putulong(buffer_1,sock);
      buffer_putnlflush(buffer_1);
    }
    return;
  } else
    if (handle_ssl_error_code(sock,r,reading)==-1)
      cleanup(sock);
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
	io_eagain(i);
	if (handle_ssl_error_code(i,l,1)==-1) {
	  cleanup(i);
	  return;
	}
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
	}
      }
    }
#endif
    cleanup(i);
  } else if (l>0) {
    /* successfully read some data (l bytes) */
    H->received+=l;
    tin1+=l;
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
      if (ftptimeout_secs)
	io_timeout(H->buddy,nextftp);
      if (write(H->filefd,buf,l)!=l)
	goto ioerror;
    } else
#endif
    {
      /* received a request */
      array_catb(&H->r,buf,l);
      if (array_failed(&H->r)) {
	httperror(H,"500 Server Error","request too long.",0);
emerge:
	io_dontwantread(i);
	io_wantwrite(i);
      } else if (array_bytes(&H->r)>MAX_HEADER_SIZE) {
	httperror(H,"500 request too long","You sent too much header data",0);
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
	if (H->t != HTTPPOST) {
#endif
	  if (l < (alen=array_bytes(&H->r))) {
	    char* c=array_start(&H->r);
	    byte_copy(c,alen-l,c+l);
	    array_truncate(&H->r,1,alen-l);
	    l=header_complete(H);

#if 0
	    write(1,"\n\n",2);
	    write(1,array_start(&H->r),array_bytes(&H->r));
	    write(1,"\n\n",2);
#endif

	    if (l) {
	      if (H->r.initialized) --H->r.initialized;
	      goto pipeline;
	    }
	  } else
	    array_reset(&H->r);
#ifdef SUPPORT_PROXY
	}
#endif
      }
    }
  }
}

#ifdef SUPPORT_HTTPS
int64 https_write_callback(int64 sock,const void* buf,uint64 n) {
  int l;
  struct http_data* H=io_getcookie(sock);
  if (!H) return -3;
#if 0
  H->writefail=!H->writefail;
  if (H->writefail) { errno=EAGAIN; return -1; }
#endif
  if (n>65536) n=65536;
  l=SSL_write(H->ssl,buf,n);
  if (l<0) {
    l=SSL_get_error(H->ssl,l);
    if (handle_ssl_error_code(sock,l,0)==-1) {
      cleanup(sock);
      return -3;
    }
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
	char r[FMT_ULONG];
	char s[FMT_ULONG];
	a[fmt_ulong(a,i)]=0;
	r[fmt_ulonglong(r,h->received)]=0;
	s[fmt_ulonglong(s,h->sent)]=0;
	buffer_putmflush(buffer_1,"socket_error ",a," ",strerror(errno),"\nclose/writefail ",a," ",r," ",s,"\n");
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
	buffer_puts(buffer_1," ");
	buffer_putulonglong(buffer_1,h->received);
	buffer_puts(buffer_1," ");
	buffer_putulonglong(buffer_1,h->sent);
	buffer_putnlflush(buffer_1);
	h->received=h->sent=0;
      }
      if (array_bytes(&h->r)>0) --h->r.initialized;
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
    h->sent+=r;
    tout1+=r;
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
    if (!io_fd(s))
      panic("io_fd");
    io_setcookie(s,whatever);
    io_wantread(s);
  }
}

#ifdef SUPPORT_BITTORRENT
int handle_torrent_request(int64 sock,struct http_data* h) {
  /* http://wiki.theory.org/BitTorrentSpecification#Tracker_HTTP.2FHTTPS_Protocol */
  /* http://www.bittorrent.org/protocol.html */
  char* req=array_start(&h->r); /* "GET /announce?info_hash=%c3%f4%31%0e%aa%ec%ae%3d%84%c1%63%70%a2%36%67%6b%24%99%b6%e1&peer_id=-TR0006-u0u5j57kcmm4&port=6887&uploaded=0&downloaded=0&left=243269632&compact=1&numwant=50&key=njyytouhv5fymdafkhzi&event=started\r\n" */
  char* t=strchr(req,'\n');
  char* s=strchr(req,'?');
  if (s && t && s<t) {
    if (t[-1]=='\r') --t;
  } else
    httperror(h,"500 invalid bittorrent request","Invalid BitTorrent request",*req=='H');
  return 0;
}
#endif

int main(int argc,char* argv[],char* envp[]) {
  int s;		/* http socket */
  int f=-1;		/* ftp socket */
#ifdef SUPPORT_SMB
  int smbs=-1;		/* smb socket */
  enum conntype sct=SMBSERVER6;
#endif
  int doftp=0;		/* -1 = don't, 0 = try, but don't fail if not working, 1 = do */
  int dohttp=0;		/* -1 = don't, 0 = try, but don't fail if not working, 1 = do */
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
  tai6464 last,tick,nextftp;
  unsigned long ftptimeout_secs=600;
  char* new_uid=0;
  char* chroot_to=0;
  unsigned long long prefetchquantum=0;
  pid_t* Instances;

#ifdef SMDEBUG
  setup_smdebug_strings();
#endif

#ifdef SUPPORT_HTTPS
  SSL_load_error_strings();
#endif

#if defined(SUPPORT_CGI) || defined(SUPPORT_PROXY)
  _envp=envp;
#endif
#ifdef SUPPORT_CGI
  {
    int found;
    int _argc=argc;
    char* new_uid=0;
    char** _argv=argv;

    found=0;
    for (;;) {
      int c=getopt(_argc,_argv,"HP:hnfFi:p:vVdDtT:c:u:Uaw:sSO:C:leEr:o:N:");
      if (c==-1) break;
      switch (c) {
      case 'c':
	chroot_to=optarg;
	break;
      case 'C':
	found=1;
	break;
      case 'u':
	new_uid=optarg;
	break;
      case '?':
	break;
      }
    }

    optind=0;

    forksock[0]=forksock[1]=-1;
    if (found) {
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
#ifndef __MINGW32__
	  if (chroot_to) { chdir(chroot_to); chroot(chroot_to); }
	  if (new_uid) prepare_switch_uid(new_uid);
#endif
	  if (!io_readfile(&savedir,".")) panic("open()");
	  buffer_init(&fsb,(void*)read,forksock[1],fsbuf,sizeof fsbuf);
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
    }
  }

#if 0
  {	/* debug test for the forkslave code */
    int64 fd;
    uint32 a; uint16 b;
    char* req="GET /?/ HTTP/1.0\r\nHost: localhost:80\r\n\r\n";
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

#ifndef __MINGW32__
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
#endif

  byte_zero(ip,16);
  port=0; fport=0; sport=0; scope_id=0;

  logging=1;

#if !defined(__linux__)
  optind=1;
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  optreset=1;
#endif
#endif

  for (;;) {
    int i;
    int c=getopt(argc,argv,"HP:hnfFi:p:vVdDtT:c:u:Uaw:sSO:C:leEr:o:N:m:");
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
    case 'm':
      mimetypesfilename=optarg;
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
    case 'H': dohttp=-1; break;
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
#ifdef SUPPORT_FALLBACK_REDIR
    case 'r':
      if (strstr(optarg,"://"))
	redir=optarg;
      else
	buffer_putmflush(buffer_2,"gatling: -r needs something like http://fallback.example.com as argument!\n");
      break;
#endif
#ifdef SUPPORT_MULTIPROC
    case 'N':
      i=scan_ulong(optarg,&instances);
      if (i==0) {
	buffer_puts(buffer_2,"gatling: warning: could not parse instances at ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,".\n");
      }
      break;
#endif
#ifdef SUPPORT_THREADED_OPEN
    case 'o':
#endif
    default:
    case '?':
    case 'h':
usage:
      buffer_putsflush(buffer_2,
		  "usage: gatling [-hnvVtdDfFUa] [-i bind-to-ip] [-p bind-to-port] [-T seconds]\n"
		  "               [-u uid] [-c dir] [-w workgroup] [-P bytes] [-O ip/port/regex]\n"
		  "               [-r redirurl] [-N processes]\n"
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
#ifdef SUPPORT_MULTIPROC
		  "\t-N n\tfork n instances of gatling\n"
#endif
#ifdef SUPPORT_CGI
		  "\t-C regex\tregex for local CGI execution (\"\\.cgi\")\n"
#endif
#ifdef SUPPORT_PROXY
		  "\t-O [flag]/ip/port/regex\tregex for proxy mode (\"F/127.0.0.1/8001/\\.jsp$\")\n"
		  "\t\tflags: F - FastCGI mode, J - JSP mode\n"
#endif
#ifdef SUPPORT_SMB
		  "\t-w name\tset SMB workgroup\n"
#endif
#ifdef SUPPORT_HTTPS
		  "\t-e\tprovide encryption (https://...)\n"
		  "\t-E\tdo not provide encryption\n"
#endif
#ifdef SUPPORT_FALLBACK_REDIR
		  "\t-r url\tinstead of a 404, generate a redirect to url+localpart\n"
#endif
		  );
      return 0;
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
#ifdef __MINGW32__
    int euid=0;
#else
    uid_t euid=geteuid();
#endif
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
      if (dohttp==-1) {
	close(s); s=-1;
      } else
	if (socket_bind6_reuse(s,ip,port,scope_id)==-1 || socket_listen(s,16)==-1)
	  panic("socket_bind6_reuse for http");
#ifdef SUPPORT_FTP
      f=socket_tcp6();
      if (doftp>=0)
	if (socket_bind6_reuse(f,ip,fport,scope_id)==-1 || socket_listen(f,16)==-1) {
	  if (doftp==1)
	    panic("socket_bind6_reuse for ftp");
	  buffer_putsflush(buffer_2,"warning: could not bind to FTP port; FTP will be unavailable.\n");
	  io_close(f); f=-1;
	}
#endif
    } else {
      io_close(s); s=-1;
    }
    if (socket_bind4_reuse(s4,ip+12,port)==-1 || socket_listen(s4,16)==-1)
      panic("socket_bind4_reuse");
#ifdef SUPPORT_FTP
    if (doftp>=0)
      if (socket_bind4_reuse(f4,ip+12,port)==-1 || socket_listen(f4,16)==-1) {
	if (doftp==1)
	  panic("socket_bind4_reuse");
	buffer_putsflush(buffer_2,"warning: could not bind to FTP port; FTP will be unavailable.\n");
	io_close(f4); f4=-1;
      }
#endif
  } else {
    if (dohttp==-1) {
      close(s);
      s=-1;
    } else
      if (socket_bind6_reuse(s,ip,port,scope_id)==-1 || socket_listen(s,16)==-1)
	panic("socket_bind6_reuse");
    s4=-1;
#ifdef SUPPORT_FTP
    if (doftp>=0)
      if (socket_bind6_reuse(f,ip,port,scope_id)==-1 || socket_listen(f,16)==-1) {
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
  if (dohttp==-1) {
    close(s);
    s=-1;
  } else
    if (socket_bind6_reuse(s,ip,port,0)==-1 || socket_listen(s,16)==-1)
      panic("socket_bind6_reuse");
#ifdef SUPPORT_FTP
  if (doftp>=0) {
    f=socket_tcp6();
    if (socket_bind6_reuse(f,ip,fport,scope_id)==-1 || socket_listen(f,16)==-1) {
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
    if (socket_bind6_reuse(smbs,ip,sport,scope_id)==-1 || socket_listen(smbs,16)) {
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
    if (socket_bind6_reuse(httpss,ip,httpsport,scope_id)==-1 || socket_listen(httpss,16)) {
      if (dohttps==1)
	panic("socket_bind6_reuse");
      buffer_putsflush(buffer_2,"warning: could not bind to HTTPS port; HTTPS will be unavailable.\n");
      io_close(httpss); httpss=-1;
    }
  }
#endif
#endif

#ifndef __MINGW32__
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
#endif

#ifdef __MINGW32__
  _getcwd(origdir,sizeof(origdir));
//  printf("origdir is \"%s\"\n",origdir);
#else
  if (!io_readfile(&origdir,".")) panic("open()");
  /* get fd for . so we can always fchdir back */
#endif

#ifdef SUPPORT_MULTIPROC

  if (instances>1) {
    unsigned long i;
    --instances;

    if (instances>100) instances=100;
    Instances=alloca(instances*sizeof(pid_t));
    for (i=0; i<instances; ++i) {
      if ((Instances[i]=fork()) == -1)
	panic("fork failed");
      else if (Instances[i] == 0) {
	instances=0;
	break;
      }
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

  } else {
#endif
    Instances=0;
    instances=0;

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

#ifdef SUPPORT_MULTIPROC
  }
#endif

  {
    char buf[IP6_FMT];
    if (s!=-1) {
      buffer_puts(buffer_1,"starting_up 0 ");
      buffer_put(buffer_1,buf,fmt_ip6c(buf,ip));
      buffer_puts(buffer_1," ");
      buffer_putulong(buffer_1,port);
      buffer_putnlflush(buffer_1);
    }
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

  connections=1;

  for (;;) {
    int events;		/* accept new connections asap */
    int64 i;
    events=0;

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

    taia_now(&now);
    if (timeout_secs) {
      if (now.sec.x != last.sec.x) {
	cps=cps1; cps1=0;
	rps=rps1; rps1=0;
	eps=eps1; eps1=0;
	tin=tin1; tin1=0;
	tout=tout1; tout1=0;
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
	  }
	  cleanup(i);
	}
      }
    }

    /* HANDLE READ EVENTS */
    while ((i=io_canread())!=-1) {
      struct http_data* H=io_getcookie(i);

      ++eps1;
      if (!H) {
	char a[FMT_ULONG];
	a[fmt_ulong(a,i)]=0;
	buffer_putmflush(buffer_2,"canthappen ",a,": got read event on socket with no cookie!\n");
	io_dontwantread(i);
	io_close(i);
	continue;
      }

#ifdef SMDEBUG
      {
	char a[FMT_ULONG];
	char b[FMT_ULONG];
	a[fmt_ulong(a,i)]=0;
	b[fmt_ulong(b,H->t)]=0;
	buffer_putmflush(buffer_2,"DEBUG: fd ",a," got READ event ",conntypestring[H->t]?conntypestring[H->t]:b,"!\n");
      }
#endif

      if (++events==10) {
	events=0;
	if (s!=-1) accept_server_connection(s,(struct http_data*)&ct,ftptimeout_secs,nextftp);
#ifdef SUPPORT_FTP
	if (f!=-1) accept_server_connection(f,(struct http_data*)&fct,ftptimeout_secs,nextftp);
#endif
#ifdef SUPPORT_HTTPS
	if (httpss!=-1) accept_server_connection(httpss,(struct http_data*)&httpsct,ftptimeout_secs,nextftp);
#endif
#ifdef __broken_itojun_v6__
	if (s4!=-1) accept_server_connection(s4,(struct http_data*)&ct4,ftptimeout_secs,nextftp);
#ifdef SUPPORT_FTP
	if (f4!=-1) accept_server_connection(f4,(struct http_data*)&fct4,ftptimeout_secs,nextftp);
#endif
#ifdef SUPPORT_HTTPS
	if (httpss4!=-1) accept_server_connection(httpss4,(struct http_data*)&httpsct4,ftptimeout_secs,nextftp);
#endif
#endif
      }

      if (H->t == HTTPREQUEST
#ifdef SUPPORT_FTP
	  || H->t == FTPSLAVE
#endif
#ifdef SUPPORT_SMB
	  || H->t == SMBREQUEST
#endif
#ifdef SUPPORT_HTTPS
	  || H->t == HTTPSRESPONSE
#endif
	 )
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
      ++eps1;
      if (!h) {
	char a[FMT_ULONG];
	a[fmt_ulong(a,i)]=0;
	buffer_putmflush(buffer_2,"canthappen ",a,": got write event on socket with no cookie!\n");
	io_dontwantwrite(i);
	io_close(i);
	continue;
      }

#ifdef SMDEBUG
      {
	char a[FMT_ULONG];
	char b[FMT_ULONG];
	a[fmt_ulong(a,i)]=0;
	b[fmt_ulong(b,h->t)]=0;
	buffer_putmflush(buffer_2,"DEBUG: fd ",a," got WRITE event ",conntypestring[h->t]?conntypestring[h->t]:b,"!\n");
      }
#endif

      if (++events==10) {
	events=0;
	accept_server_connection(s,(struct http_data*)&ct,ftptimeout_secs,nextftp);
#ifdef SUPPORT_FTP
	if (f!=-1) accept_server_connection(f,(struct http_data*)&fct,ftptimeout_secs,nextftp);
#endif
#ifdef SUPPORT_HTTPS
	if (httpss!=-1) accept_server_connection(httpss,(struct http_data*)&httpsct,ftptimeout_secs,nextftp);
#endif
#ifdef __broken_itojun_v6__
	if (s4!=-1) accept_server_connection(s4,(struct http_data*)&ct4,ftptimeout_secs,nextftp);
#ifdef SUPPORT_FTP
	if (f4!=-1) accept_server_connection(f4,(struct http_data*)&fct4,ftptimeout_secs,nextftp);
#endif
#ifdef SUPPORT_HTTPS
	if (httpss4!=-1) accept_server_connection(httpss4,(struct http_data*)&httpsct4,ftptimeout_secs,nextftp);
#endif
#endif
      }

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
#ifdef SUPPORT_MULTIPROC
  if (instances) {
    unsigned long i;
    for (i=0; i<instances; ++i)
      kill(Instances[i],15);
  }
#endif
  io_finishandshutdown();
  return 0;
}

#if 0
int epoll_create(int i) { return -1; }
#endif
