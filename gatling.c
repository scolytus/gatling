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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include "version.h"

#ifdef USE_ZLIB
#include <zlib.h>
#endif

#define RELEASE "Gatling/" VERSION

int virtual_hosts;
int transproxy;
int directory_index;
int logging;
int64 origdir;

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

struct http_data {
  array r;
  io_batch iob;
  char myip[16];
  uint16 myport;
  char* hdrbuf,* bodybuf;
  const char *mimetype;
  int hlen,blen;
  int keepalive;
  int filefd;
  enum encoding encoding;
};

int header_complete(struct http_data* r) {
  long i;
  long l=array_bytes(&r->r);
  const char* c=array_start(&r->r);
  for (i=0; i+1<l; ++i) {
    if (c[i]=='\n' && c[i+1]=='\n')
      return i+2;
    if (i+3<l &&
	c[i]=='\r' && c[i+1]=='\n' &&
	c[i+2]=='\r' && c[i+3]=='\n')
      return i+4;
  }
  return 0;
}

static char oom[]="HTTP/1.0 500 internal error\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nout of memory\n";

void httperror(struct http_data* r,const char* title,const char* message) {
  char* c;
  c=r->hdrbuf=(char*)malloc(str_len(message)+str_len(title)+250);
  if (!c) {
    r->hdrbuf=oom;
    r->hlen=str_len(r->hdrbuf);

    buffer_putsflush(buffer_1,"error_oom\n");

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
    r->hlen=c - r->hdrbuf;
  }
  iob_addbuf(&r->iob,r->hdrbuf,r->hlen);
}

static struct mimeentry { const char* name, *type; } mimetab[] = {
  { "html",	"text/html" },
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

static unsigned int fmt_2digits(char* dest,int i) {
  dest[0]=(i/10)+'0';
  dest[1]=(i%10)+'0';
  return 2;
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
    if (lstat(d->d_name,&x->ss)==-1) { array_fail(&b); break; }
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
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
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
    array_cats(&c,"<td>");
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

int64 http_openfile(struct http_data* h,char* filename,struct stat* ss) {
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
    if (byte_equal(h->myip,12,V4mappedprefix))
      i=fmt_ip4(s,h->myip+12);
    else
      i=fmt_ip6(s,h->myip);
    i+=fmt_str(s+i," ");
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
  if (filename[(i=str_len(filename))-1] == '/') {
    /* Damn.  Directory. */
    if (filename[1] && chdir(filename+1)==-1) return -1;
    h->mimetype="text/html";
    if (!io_readfile(&fd,"index.html")) {
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
	  h->blen=destlen+10-2-4;
	} else {
	  free(compressed);
	}
      }
#endif
      return -2;
    }
    if (doesbzip2) {
      int64 gfd;
      if (io_readfile(&gfd,"index.html.bz2")) {
	io_close(fd);
	fd=gfd;
	h->encoding=BZIP2;
      }
    }
    if (doesgzip) {
      int64 gfd;
      if (io_readfile(&gfd,"index.html.gz")) {
	io_close(fd);
	fd=gfd;
	h->encoding=GZIP;
      }
    }
  } else {
    h->mimetype=mimetype(filename);
    if (!io_readfile(&fd,filename+1))
      return -1;
    if (doesgzip || doesbzip2) {
      int64 gfd;
      char* tmpfilename=alloca(str_len(filename)+5);
      if (doesbzip2) {
	i=fmt_str(tmpfilename,filename+1);
	i+=fmt_str(tmpfilename+i,".bz2");
	tmpfilename[i]=0;
	if (io_readfile(&gfd,tmpfilename)) {
	  io_close(fd);
	  fd=gfd;
	  h->encoding=BZIP2;
	}
      }
      if (doesgzip && h->encoding==NORMAL) {
	i=fmt_str(tmpfilename,filename+1);
	i+=fmt_str(tmpfilename+i,".gz");
	tmpfilename[i]=0;
	if (io_readfile(&gfd,tmpfilename)) {
	  io_close(fd);
	  fd=gfd;
	  h->encoding=GZIP;
	}
      }
    }
  }
  if (fstat(fd,ss)==-1 || S_ISDIR(ss->st_mode)) {
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

void httpresponse(struct http_data* h,int64 s) {
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
    fd=http_openfile(h,c,&ss);
    if (fd==-1) {
e404:
      httperror(h,"404 Not Found","No such file or directory.");

      if (logging) {
	buffer_puts(buffer_1,head?"HEAD/404 ":"GET/404 ");
	buffer_putulong(buffer_1,s);
	buffer_puts(buffer_1," ");
	buffer_putlogstr(buffer_1,c);
	buffer_puts(buffer_1," 0 ");
	buffer_putlogstr(buffer_1,(tmp=http_header(h,"User-Agent"))?tmp:"[no_user_agent]");
	buffer_puts(buffer_1," ");
	buffer_putlogstr(buffer_1,(tmp=http_header(h,"Referrer"))?tmp:"[no_referrer]");
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
	    buffer_puts(buffer_1,head?"HEAD ":"GET ");
	    buffer_putulong(buffer_1,s);
	    buffer_puts(buffer_1," ");
	    buffer_putlogstr(buffer_1,filename);
	    buffer_puts(buffer_1," ");
	    buffer_putulong(buffer_1,h->blen);
	    buffer_puts(buffer_1," ");
	    buffer_putlogstr(buffer_1,(tmp=http_header(h,"User-Agent"))?tmp:"[no_user_agent]");
	    buffer_puts(buffer_1," ");
	    buffer_putlogstr(buffer_1,(tmp=http_header(h,"Referrer"))?tmp:"[no_referrer]");
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
	  iob_addbuf(&h->iob,h->hdrbuf,h->hlen);
	  if (!head)
	    iob_addbuf(&h->iob,h->bodybuf,h->blen);
	}
      } else {
	if (fstat(fd,&ss)==-1) {
	  io_close(fd);
	  goto e404;
	}
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
	      httperror(h,"416 Bad Range","The requested range can not be satisfied.");
	      goto fini;
	    }
	  }
	}
	c=h->hdrbuf=(char*)malloc(500);
	if (ss.st_mtime<=ims) {
	  c+=fmt_str(c,"HTTP/1.1 304 Not Changed");
	  head=1;
	} else
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
	if (range_last<range_first) {
	  free(c);
	  httperror(h,"416 Bad Range","The requested range can not be satisfied.");
	  buffer_puts(buffer_1,"error_416 ");
	} else {
	  c+=fmt_str(c,"\r\nConnection: ");
	  c+=fmt_str(c,h->keepalive?"keep-alive":"close");
	  c+=fmt_str(c,"\r\n\r\n");
	  iob_addbuf(&h->iob,h->hdrbuf,c - h->hdrbuf);
	  if (!head) {
	    iob_addfile(&h->iob,fd,range_first,range_last);
	    h->filefd=fd;
	  }
	  if (logging) {
	    if (h->hdrbuf[9]=='3') {
	      buffer_puts(buffer_1,head?"HEAD/304 ":"GET/304 ");
	    } else {
	      buffer_puts(buffer_1,head?"HEAD ":"GET ");
	    }
	  }
	}

	if (logging) {
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
	  buffer_putlogstr(buffer_1,(tmp=http_header(h,"Referrer"))?tmp:"[no_referrer]");
	  buffer_putsflush(buffer_1,"\n");
	}
      }
    }
  }
fini:
  io_dontwantread(s);
  io_wantwrite(s);
}

int main(int argc,char* argv[]) {
  int s=socket_tcp6();
#ifdef __OpenBSD__
#warning "working around idiotic openbse ipv6 stupidity - please kick itojun for this!"
  int s4=socket_tcp4();
#endif
  uint32 scope_id;
  char ip[16];
  uint16 port;
  tai6464 now,last,next,tick;
  unsigned long timeout_secs=23;

  signal(SIGPIPE,SIG_IGN);

  if (!geteuid()) {
    struct rlimit rl;
    long l;
    rl.rlim_cur=RLIM_INFINITY; rl.rlim_max=RLIM_INFINITY;
    setrlimit(RLIMIT_NPROC,&rl);
    for (l=0; ; l+=500) {
      rl.rlim_cur=l; rl.rlim_max=l;
      if (setrlimit(RLIMIT_NOFILE,&rl)==-1) break;
    }
  }

  byte_zero(ip,16);
  port=0; scope_id=0;

  logging=1;

  for (;;) {
    int i;
    int c=getopt(argc,argv,"hni:p:vVdDtT:");
    if (c==-1) break;
    switch (c) {
    case 'n':
      logging=0;
      break;
    case 'i':
      i=scan_ip6(optarg,ip);
      if (optarg[i]=='%') {
	/* allow "fe80::220:e0ff:fe69:ad92%eth0" */
	scope_id=socket_getifidx(optarg+i+1);
	if (scope_id==0) {
	  buffer_puts(buffer_2,"gatling: warning: network interface ");
	  buffer_puts(buffer_2,optarg+i+1);
	  buffer_putsflush(buffer_2," not found.\n");
	}
      } else if (optarg[i]!=0) {
	buffer_puts(buffer_2,"gatling: warning: could not parse IP address ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,".\n");
      }
      break;
    case 'p':
      i=scan_ushort(optarg,&port);
      if (i==0) {
	buffer_puts(buffer_2,"gatling: warning: could not parse port ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,".\n");
      }
      break;
    case 'v':
      virtual_hosts=1;
      break;
    case 'V':
      virtual_hosts=-1;
      break;
    case 't':
      transproxy=1;
      break;
    case 'd':
      directory_index=-1;
      break;
    case 'D':
      directory_index=1;
      break;
    case 'T':
      i=scan_ulong(optarg,&timeout_secs);
      if (i==0) {
	buffer_puts(buffer_2,"gatling: warning: could not parse timeout in seconds ");
	buffer_puts(buffer_2,optarg+i+1);
	buffer_putsflush(buffer_2,".\n");
      }
      break;
    case 'h':
      buffer_putsflush(buffer_2,
		  "usage: gatling [-hvVtdD] [-i bind-to-ip] [-p bind-to-port] [-T seconds]\n"
		  "\n"
		  "\t-h\tprint this help\n"
		  "\t-v\tenable virtual hosting mode\n"
		  "\t-V\tdisable virtual hosting mode\n"
		  "\t\t(default is to try both)\n"
		  "\t-t\ttransproxy mode: do not replace :port in Host headers\n"
		  "\t-d\tgenerate directory index\n"
		  "\t-D\tdo not generate directory index\n"
		  "\t-T n\tset timeout in seconds (0 to disable, default 23)\n"
		  "\t\t(default is -d unless in virtual hosting mode)\n"
		  );
      return 0;
    case '?':
      break;
    }
  }
  if (!directory_index)
    directory_index=virtual_hosts<1;
  else if (directory_index==-1)
    directory_index=0;

  if (timeout_secs) {
    taia_now(&last);
    byte_copy(&next,sizeof(next),&last);
    next.sec.x += timeout_secs;
    byte_copy(&tick,sizeof(next),&last);
    ++tick.sec.x;
  }

  if (!io_readfile(&origdir,".")) panic("open()");
  /* get fd for . so we can always fchdir back */

  if (port==0)
    port=geteuid()?8000:80;
#ifdef __OpenBSD__
  if (byte_equal(ip,12,V4mappedprefix) || byte_equal(ip,16,V6any)) {
    if (byte_equal(ip,16,V6any)) {
      if (socket_bind6_reuse(s,ip,port,scope_id)==-1)
	panic("socket_bind6_reuse");
    } else {
      close(s); s=-1;
    }
    if (socket_bind4_reuse(s4,ip+12,port)==-1)
      panic("socket_bind4_reuse");
  } else {
    if (socket_bind6_reuse(s,ip,port,scope_id)==-1)
      panic("socket_bind6_reuse");
    s4=-1;
  }
  buffer_putsflush(buffer_2,"WARNING: We are taking heavy losses working around itojun/OpenBSD madness here.\n"
		            "         Please consider using an operating system with real IPv6 support instead!\n");
#else
  if (port==0) {
    if (socket_bind6_reuse(s,ip,port=80,0)==-1)
      if (socket_bind6_reuse(s,ip,port=8000,0)==-1)
	panic("socket_bind6_reuse");
  } else
    if (socket_bind6_reuse(s,ip,port,0)==-1)
      panic("socket_bind6_reuse");
#endif

  {
    char buf[IP6_FMT];
    buffer_puts(buffer_1,"starting_up 0 ");
    buffer_put(buffer_1,buf,fmt_ip6(buf,ip));
    buffer_puts(buffer_1," ");
    buffer_putulong(buffer_1,port);
    buffer_putnlflush(buffer_1);
  }

#ifdef __OpenBSD__
  if (s!=-1) {
    if (socket_listen(s,16)==-1)
      panic("socket_listen");
    io_nonblock(s);
    if (!io_fd(s))
      panic("io_fd");
    io_wantread(s);
  }
  if (s4!=-1) {
    if (socket_listen(s4,16)==-1)
      panic("socket_listen");
    io_nonblock(s4);
    if (!io_fd(s4))
      panic("io_fd");
    io_wantread(s4);
  }
#else
  if (socket_listen(s,16)==-1)
    panic("socket_listen");
  io_nonblock(s);
  if (!io_fd(s))
    panic("io_fd");
  io_wantread(s);
#endif

  for (;;) {
    int64 i;
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
	byte_copy(&tick,sizeof(next),&now);
	++tick.sec.x;
	while ((i=io_timeouted())!=-1) {
	  if (logging) {
	    buffer_puts(buffer_1,"timeout ");
	    buffer_putulong(buffer_1,i);
	    buffer_puts(buffer_1,"\nclose ");
	    buffer_putulong(buffer_1,i);
	    buffer_putnlflush(buffer_1);
	  }
	  io_close(i);
	}
      }
    }

    while ((i=io_canread())!=-1) {
#ifdef __OpenBSD__
      if (i==s || i==s4) {
#else
      if (i==s) {
#endif
	int n;
#ifdef __OpenBSD__
	while (1) {
	  if (i==s4) {
	    byte_copy(ip,12,V4mappedprefix);
	    scope_id=0;
	    n=socket_accept4(i,ip+12,&port);
	  } else
	    n=socket_accept6(i,ip,&port,&scope_id);
	  if (n==-1) break;
#else
	while ((n=socket_accept6(s,ip,&port,&scope_id))!=-1) {
#endif
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
	    io_wantread(n);
	    if (h) {
	      byte_zero(h,sizeof(struct http_data));
#ifdef __OpenBSD__
	      if (i==s4) {
		byte_copy(h->myip,12,V4mappedprefix);
		socket_local4(i,h->myip+12,&h->myport);
	      } else
		socket_local6(s,h->myip,&h->myport,0);
#else
	      socket_local6(s,h->myip,&h->myport,0);
#endif
	      io_setcookie(n,h);
	      if (timeout_secs)
		io_timeout(n,next);
	    } else
	      io_close(n);
	  } else {
	    io_close(n);
	  }
	}
	if (errno==EAGAIN)
	  io_eagain(i);
	else
#ifdef __OpenBSD__
	  carp(i==s4?"socket_accept4":"socket_accept6");
#else
	  carp("socket_accept6");
#endif
      } else {
	char buf[8192];
	struct http_data* h=io_getcookie(i);
	int l=io_tryread(i,buf,sizeof buf);
	if (l==-3) {
	  if (h) {
	    array_reset(&h->r);
	    iob_reset(&h->iob);
	    if (h->hdrbuf!=oom) free(h->hdrbuf); h->hdrbuf=0;
	    free(h->bodybuf); h->bodybuf=0;
	  }
	  if (logging) {
	    buffer_puts(buffer_1,"io_error ");
	    buffer_putulong(buffer_1,i);
	    buffer_puts(buffer_1," ");
	    buffer_puterror(buffer_1);
	    buffer_puts(buffer_1,"\nclose ");
	    buffer_putulong(buffer_1,i);
	    buffer_putnlflush(buffer_1);
	  }
	  io_close(i);
	} else if (l==0) {
	  if (h) {
	    array_reset(&h->r);
	    iob_reset(&h->iob);
	    free(h->hdrbuf); h->hdrbuf=0;
	  }
	  if (logging) {
	    buffer_puts(buffer_1,"close ");
	    buffer_putulong(buffer_1,i);
	    buffer_putnlflush(buffer_1);
	  }
	  io_close(i);
	} else if (l>0) {
	  if (timeout_secs)
	    io_timeout(i,next);
	  array_catb(&h->r,buf,l);
	  if (array_failed(&h->r)) {
	    httperror(h,"500 Server Error","request too long.");
emerge:
	    io_dontwantread(i);
	    io_wantwrite(i);
	  } else if (array_bytes(&h->r)>8192) {
	    httperror(h,"500 request too long","You sent too much headers");
	    goto emerge;
	  } else if ((l=header_complete(h)))
	    httpresponse(h,i);
	}
      }
    }
    while ((i=io_canwrite())!=-1) {
      struct http_data* h=io_getcookie(i);
      int64 r=iob_send(i,&h->iob);
/*      printf("iob_send returned %lld\n",r); */
      if (r==-1)
	io_eagain(i);
      else if (r<=0) {
	if (h->filefd!=-1) close(h->filefd);
	if (r==-3) {
	  if (logging) {
	    buffer_puts(buffer_1,"socket_error ");
	    buffer_putulong(buffer_1,i);
	    buffer_puts(buffer_1," ");
	    buffer_puterror(buffer_1);
	    buffer_putnlflush(buffer_1);
	  }
	} else {
	  if (logging) {
	    buffer_puts(buffer_1,"request_done ");
	    buffer_putulong(buffer_1,i);
	    buffer_putnlflush(buffer_1);
	  }
	}
	array_trunc(&h->r);
	iob_reset(&h->iob);
	free(h->hdrbuf); h->hdrbuf=0;
	if (h->keepalive) {
	  io_dontwantwrite(i);
	  io_wantread(i);
	} else {
	  if (logging) {
	    buffer_puts(buffer_1,"close ");
	    buffer_putulong(buffer_1,i);
	    buffer_putnlflush(buffer_1);
	  }
	  io_close(i);
	}
      } else
	if (timeout_secs)
	  io_timeout(i,next);
    }
  }
}
