#define _FILE_OFFSET_BITS 64
#define _BSD_SOURCE
#include "gatling.h"

#ifdef SUPPORT_SMB

#include "byte.h"
#include "rangecheck.h"
#include "str.h"

#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <iconv.h>
#include <sys/statvfs.h>
#include <fnmatch.h>
#include <dirent.h>

#include <stdio.h>

#if 0
               _
 ___ _ __ ___ | |__
/ __| '_ ` _ \| '_ \
\__ \ | | | | | |_) |
|___/_| |_| |_|_.__/
#endif

#if 0
struct smbheader {
  unsigned char protocol[4];	/* '\xffSMB' */
  unsigned char command;	/* command code */
  unsigned long status;
  unsigned char flags;
  unsigned short flags2;
  union {
    unsigned short pad[6];
    struct {
      unsigned short pidhigh;
      unsigned char securitysignature[8];
    } extra;
  };
  unsigned char reserved[2];
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
#endif

static int hasandx(unsigned char code) {
  return !strchr("\x04\x72\x71\x2b\x32\x80",code);
}

static const size_t netbiosheadersize=4;
static const size_t smbheadersize=32;

struct smb_response {
  char* buf;
  size_t allocated,used,andxtypeofs;
};

#ifdef DEBUG
void hexdump(char* buf,size_t len) {
  size_t i,j;
  char y[9];
  y[8]=0;
  printf("sending:\n");
  for (i=j=0; i<len; ++i) {
    y[j]=buf[i];
    if (y[j]<' ') y[j]='.';
    if (++j==8) j=0;
    printf("%02x",(unsigned char)(buf[i]));
    if (i%8<7)
      putchar(' ');
    else
      printf("   %s\n",y);
  }
  y[j]=0;
  printf("%*s%s\n",(int)((9-j)*3-1),"",y);
}
#endif

static int init_smb_response(struct smb_response* sr,unsigned char* in_response_to,size_t size) {
  if (size<200) size=200;
  sr->buf=malloc(sr->allocated=size);
  if (!sr->buf) return -1;

  sr->used=netbiosheadersize+smbheadersize;

  uint32_pack_big(sr->buf,32);	// size field in NMB header
  byte_copy(sr->buf+netbiosheadersize,smbheadersize-8,
	    "\xffSMB"	// magic
	    "x"		// smb command, filled in later; ofs 4
	    "\x00\x00\x00\x00"	// STATUS_SUCCESS
	    "\x80"	// Flags: response+case sensitive
	    "\x41\xc0"	// Flags2: unicode+long names allowed
	    "\x00\x00"	// Process ID High: 0
	    "\x00\x00\x00\x00\x00\x00\x00\x00"	// Signature
	    "\x00\x00"	// Reserved
	   );		// TID, PID, UID, MID; ofs 24

  sr->buf[netbiosheadersize+4]=in_response_to[4];
  uint16_pack(sr->buf+netbiosheadersize+24,uint16_read((char*)in_response_to+24));
  uint16_pack(sr->buf+netbiosheadersize+26,uint16_read((char*)in_response_to+26));
  uint16_pack(sr->buf+netbiosheadersize+28,0);
  uint16_pack(sr->buf+netbiosheadersize+30,uint16_read((char*)in_response_to+30));

  sr->andxtypeofs=netbiosheadersize+4;

  return 0;
}

static int add_smb_response(struct smb_response* sr,char* buf,size_t size,unsigned char type) {
  if (sr->allocated+size<size) return -1;
  if (sr->used+size>sr->allocated) {
    size_t n=sr->allocated+size;
    void* x;
    n=((n-1)|0xfff)+1;
    if (!n) return -1;
    x=realloc(sr->buf,n);
    if (!x) return -1;
    sr->buf=x;
    sr->allocated=n;
  }
  sr->buf[sr->andxtypeofs]=type;
  if (sr->andxtypeofs!=netbiosheadersize+4)
    uint16_pack(sr->buf+sr->andxtypeofs+2,sr->used-netbiosheadersize);
  byte_copy(sr->buf+sr->used,size,buf);
  sr->andxtypeofs=sr->used+1;
  sr->used+=size;
  if (sr->used%2)
    sr->buf[++sr->used]=0;
  uint32_pack_big(sr->buf,sr->used-4);	// update netbios size field
  return 0;
}

static void set_smb_error(struct smb_response* sr,uint32_t error,unsigned char req) {
  add_smb_response(sr,"\x00\x00",3,req);
  assert(sr->allocated>=0x20);
  uint32_pack(sr->buf+4+5,error);
}

static int validate_smb_packet(unsigned char* pkt,unsigned long len) {
  /* we actually received len bytes from the wire, so pkt+len does not
   * overflow; we got len bytes, because the netbios header said there
   * were that many bytes in the packet. */
  unsigned char* x;
  /* demand that we have at least a full smbheader and wordcount */
  if (len>=smbheadersize+1 &&
      byte_equal(pkt,4,"\xffSMB")) {	/* signature needs to be there */
    if (!hasandx(pkt[4])) return 0;
    x=(unsigned char*)pkt+smbheadersize;
    for (;;) {
      int done;
      if (x[0]<2 || !range_arrayinbuf(pkt,len,x,*x,2))
	return -1;
      done=(x[1]==0xff);	/* 0xff is the end marker for AndX */
      if (done) return 0;
      {
	uint16_t next=uint16_read((char*)x+3);
	if (pkt+next < x+x[0]*2) return -1;
	x=pkt+next;
      }
      if (!range_bufinbuf(pkt,len,(char*)x,5))
	return -1;
    }
  } else
    return -1;
  return 0;
}

static int smb_handle_SessionSetupAndX(unsigned char* pkt,unsigned long len,struct smb_response* sr) {
  static char nr[2*3+sizeof("Unix_" RELEASE)*2+100*2]=
    "\x03"	// Word Count 3
    "\xff"	// AndXCommand
    "\x00"	// Reserved
    "xx"	// AndXOffset; ofs 3
    "\x01\x00"	// Action: logged in as GUEST
    "xx"	// Byte Count; ofs 7
    "\x00"	// bizarre padding byte
    "U\x00n\x00i\x00x\x00\x00\x00"	// "Unix"
    "G\x00""a\x00t\x00l\x00i\x00n\x00g\x00 \x00";

  size_t i,payloadlen;

  payloadlen=sizeof("Unix_" RELEASE)*2 + wglen16 + 1;

  if (len<2*13 || pkt[0] != 13) return -1;	/* word count for this message is always 13 */

  uint16_pack(nr+3,sr->used+2*3+payloadlen);
  uint16_pack(nr+7,payloadlen);

  /* should be zero filled already so we only write the even bytes */
  for (i=0; i<sizeof(RELEASE)-sizeof("Gatling "); ++i)
    nr[8+2+(sizeof("Unix_Gatling")+i)*2]=VERSION[i];

  byte_copy(nr+8+2+(sizeof("Unix_Gatling")+i+1)*2,wglen16+2,workgroup_utf16);

  return add_smb_response(sr,nr,8+uint16_read(nr+7),0x73);
}

static struct timezone tz;

static void uint64_pack(char* dest,unsigned long long l) {
  uint32_pack(dest,l&0xffffffff);
  uint32_pack(dest+4,l>>32);
}

static void uint64_pack_ntdate(char* dest,time_t date) {
  uint64_pack(dest,10000000ll * (date + 11644473600ll));
}

static int smb_handle_negotiate_request(unsigned char* c,size_t len,struct smb_response* sr) {
  size_t i,j,k;
  int ack;
  static char nr[2*17+100*2]=
    "\x11"	// word count 17
    "xx"	// dialect index; ofs 1
    "\x02"	// security mode, for NT: plaintext passwords XOR unicode
    "\x01\x00"	// Max Mpx Count 1
    "\x01\x00"	// Max VCs 1
    "\x04\x41\x00\x00"	// Max Buffer Size (16644, like XP)
    "\x00\x00\x01\x00"	// Max Raw Buffer (65536, like XP)
    "\x01\x02\x03\x04"	// Session Key
    "\x5c\x40\x00\x00"	// Capabilities, the bare minimum
    "xxxxxxxx"	// system time; ofs 24
    "xx"	// server time zone; ofs 32
    "\x00"	// key len
    "xx"	// byte count; ofs 35
    ;		// workgroup name; ofs 37

  if (len<3) return -1;
  j=uint16_read((char*)c+1);
  if (len<3+j) return -1;
  ack=-1;
  for (k=0,i=3; i<3+j; ++k) {
    if (c[i]!=2) return -1;
    if (str_equal((char*)c+i+1,"NT LM 0.12")) { ack=k; break; }
    i+=2+str_len((char*)c+i+1);
  }
  if (ack==-1) return -1;	// wrong dialect
  uint16_pack(nr+1,ack);

  {
    struct timeval t;
    unsigned long long ntdate;
    gettimeofday(&t,&tz);
    ntdate=10000000ll * ( t.tv_sec + 11644473600ll ) + t.tv_usec * 10ll;
    uint32_pack(nr+24,ntdate&0xffffffff);
    uint32_pack(nr+24+4,ntdate>>32);
    uint16_pack(nr+32,tz.tz_minuteswest);
  }

  uint16_pack(nr+35,wglen16);
  byte_copy(nr+37,wglen16,workgroup_utf16);

  return add_smb_response(sr,nr,38+wglen16,0x72);
}

static int smb_handle_TreeConnectAndX(unsigned char* c,size_t len,struct smb_response* sr) {
  static char nr[2*3+100]=
    "\x03"	// Word Count 3
    "\xff"	// AndXCommand
    "\x00"	// Reserved
    "xx"	// AndXOffset; ofs 3
    "\x00\x00"	// Optional Support: none
    "xx"	// Byte Count; ofs 7
    "A:\x00"	// "Service", this is what Samba puts there
    "e\x00x\x00t\x00""3\x00\x00\x00";	// "Native Filesystem"

  if (len<2*4 || c[0] != 4) return -1;	/* word count for this message is always 4 */

  uint16_pack(nr+3,sr->used+2*3+1+sizeof("A: e x t 3  "));
  uint16_pack(nr+7,sizeof("A: e_x_t_3_ "));
  return add_smb_response(sr,nr,9+uint16_read(nr+7),0x75);
}

static int smb_handle_echo(unsigned char* c,size_t len,struct smb_response* sr) {
  uint16 nmemb,membsize;
  char* buf;
  size_t i;
  if (len<2*1 || c[0] != 1) return -1;	/* word count for this message is always 1 */
  nmemb=uint16_read((char*)c+1);
  membsize=uint16_read((char*)c+3);
  if (nmemb*membsize>1024) return -1;
  buf=alloca(nmemb*membsize+3);
  buf[0]=0;
  uint16_pack(buf+1,nmemb*membsize);
  for (i=0; i<nmemb; ++i)
    byte_copy(buf+3+i*membsize,membsize,c+5);
  return add_smb_response(sr,buf,nmemb*membsize+3,0x2b);
}

static int smb_handle_TreeDisconnect(unsigned char* c,size_t len,struct smb_response* sr) {
  if (len<3 || c[0]!=0 || c[1]!=0 || c[2]!=0) return -1;	/* word count for this message is always 0 */
  return add_smb_response(sr,(char*)c,3,0x71);
}

iconv_t wc2utf8;
iconv_t utf82wc2;

enum {
  STATUS_INVALID_HANDLE=0xC0000008,
  ERROR_NO_MEMORY=0xc0000017,
  ERROR_ACCESS_DENIED=0xC0000022,
  ERROR_OBJECT_NAME_NOT_FOUND=0xc0000034,
  ERROR_NOT_SUPPORTED=0xc00000bb,
  ERROR_NETWORK_ACCESS_DENIED=0xc00000ca,
  STATUS_TOO_MANY_OPENED_FILES=0xC000011F,
};

enum smb_open_todo {
  WANT_OPEN,
  WANT_STAT,
  WANT_CHDIR,
};

/* ssize is the size in bytes, including L'\0' */
/* returns number of converted chars in dest, including \0, or 0 on error */
size_t utf16tolatin1(char* dest,size_t dsize,uint16_t* src,size_t ssize) {
  size_t i;
  size_t max=dsize;
  if (ssize/2<max) max=ssize/2;
  for (i=0; i<max; ++i) {
    uint16_t x=uint16_read((char*)&src[i]);
    if (x>0xff) return 0;
    dest[i]=x;
  }
  if (i==dsize) return 0;
  dest[i]=0;
  return i+1;
}

size_t utf16toutf8(char* dest,size_t dsize,uint16_t* src,size_t ssize) {
  size_t X,Y;
  char* x,* y;
  x=(char*)src;
  y=dest;
  X=ssize;
  Y=dsize;
  memset(dest,0,dsize);
  if (iconv(wc2utf8,&x,&X,&y,&Y)) return 0;
  return dsize-Y;
}

size_t utf8toutf16(char* dest,size_t dsize,char* src,size_t ssize) {
  size_t X,Y;
  char* x,* y;
  x=src;
  y=dest;
  X=ssize;
  Y=dsize;
  memset(dest,0,dsize);
  if (iconv(utf82wc2,&x,&X,&y,&Y)) return 0;
  return dsize-Y;
}


int smb_open(struct http_data* h,unsigned short* remotefilename,size_t fnlen,struct stat* ss,enum smb_open_todo todo) {
  char localfilename[1024];
  int64 fd;
  size_t i,j;
  char* x;
  if (ip_vhost(h)==-1 || fnlen/2>sizeof(localfilename))
    return -1;

  fd=-1;
  for (j=0; fd==-1 && j<2; ++j) {
    if (j==0) {
      /* first try latin1 */
      if (utf16tolatin1(localfilename,sizeof(localfilename),remotefilename,fnlen)==0)
	continue;
    } else {
      if (utf16toutf8(localfilename,sizeof(localfilename),remotefilename,fnlen)==0)
	break;
    }
//    printf("trying \"%s\"\n",localfilename);
    for (i=0; localfilename[i]; ++i) {
      if (localfilename[i]=='\\')
	localfilename[i]='/';
    }
    x=(char*)localfilename;
    while ((x=strstr(x,"/.")))
      x[1]=':';
    x=(char*)localfilename;
    while (*x=='/') ++x;
    if (todo==WANT_STAT) {
      if (stat(x,ss)==0) {
	fd=0;
	break;
      }
    } else if (todo==WANT_OPEN) {
      if (open_for_reading(&fd,x,ss))
	break;
    } else if (todo==WANT_CHDIR) {
      if (!*x || chdir(x)==0) {
	fd=0;
	break;
      }
    }
  }

  return fd;
}

// TODO
static int smb_handle_OpenAndX(struct http_data* h,unsigned char* c,size_t len,uint32_t pid,struct smb_response* sr) {
  static char nr[34]=
    "\x0f"	// word count 15
    "\xff"	// AndXCommand
    "\x00"	// Reserved
    "xx"	// AndXOffset; ofs 3
    "xx"	// FID; ofs 5
    "\x00\x00"	// file attributes; normal file
    "xxxx"	// ctime; ofs 9
    "xxxx"	// file size; ofs 13
    "\x00\x00"	// granted access: read, compatibility mode, caching permitted
    "\x00\x00"	// file type: disk file or directory
    "\x00\x00"	// ipc state
    "\x01\x00"  // action: file existed and was opened
    "\x00\x00\x00\x00"	// server FID (?!?)
    "\x00\x00"	// reserved
    "\x00\x00"	// byte count 0
    ;
  if (len<2*15 || c[0]!=15) return -1;
  /* see if it is an open for reading */
  if ((c[7]&7) || ((c[17]&3)!=1)) {
    /* we only support read access */
//    printf("non-read-access requested: %x %x!\n",c[7],c[17]);
    set_smb_error(sr,ERROR_ACCESS_DENIED,0x2d);
    return 0;
  }
  /* now look at file name */
  {
    size_t fnlen=uint16_read((char*)c+31);
    uint16_t* remotefilename=(uint16_t*)(c+34);
    struct stat ss;
    struct handle* hdl;
    int fd;
    if (fnlen%2) --fnlen;
    if (fnlen>2046 || ((uintptr_t)remotefilename%2)) return -1;
    hdl=alloc_handle(&h->h);
    if (!hdl) {
//      printf("could not open file handle!");
      set_smb_error(sr,STATUS_TOO_MANY_OPENED_FILES,0x2d);
      return 0;
    }

    fd=smb_open(h,remotefilename,fnlen,&ss,WANT_OPEN);
    if (fd==-1) {
      set_smb_error(sr,ERROR_OBJECT_NAME_NOT_FOUND,0x2d);
      close_handle(hdl);
      return 0;
    }
    hdl->fd=fd;
    hdl->pid=pid;
    hdl->size=ss.st_size;
    hdl->cur=0;
    hdl->filename=malloc(fnlen+2);
    if (hdl->filename) {
      memcpy(hdl->filename+1,remotefilename,fnlen);
      hdl->filename[0]=fnlen;
    }

    uint16_pack(nr+3,sr->used+15*2+3);
    uint16_pack(nr+5,hdl->handle);
    uint32_pack(nr+9,ss.st_mtime);
    uint32_pack(nr+13,ss.st_size);
  }

  return add_smb_response(sr,nr,15*2+3,0x2d);
}

static int smb_handle_CreateAndX(struct http_data* h,unsigned char* c,size_t len,uint32_t pid,struct smb_response* sr) {
  static char nr[34]=
    "\x0f"	// word count 15
    "\xff"	// AndXCommand
    "\x00"	// Reserved
    "xx"	// AndXOffset; ofs 3
    "xx"	// FID; ofs 5
    "\x00\x00"	// file attributes; normal file
    "xxxx"	// ctime; ofs 9
    "xxxx"	// file size; ofs 13
    "\x00\x00"	// granted access: read, compatibility mode, caching permitted
    "\x00\x00"	// file type: disk file or directory
    "\x00\x00"	// ipc state
    "\x01\x00"  // action: file existed and was opened
    "\x00\x00\x00\x00"	// server FID (?!?)
    "\x00\x00"	// reserved
    "\x00\x00"	// byte count 0
    ;
  if (len<2*24 || c[0]!=24) return -1;
  /* see if it is an open for reading */
  if ((c[7]&7) || ((c[17]&3)!=1)) {
    /* we only support read access */
//    printf("non-read-access requested: %x %x!\n",c[7],c[17]);
    set_smb_error(sr,ERROR_ACCESS_DENIED,0x2d);
    return 0;
  }
  /* now look at file name */
  {
    size_t fnlen=uint16_read((char*)c+31);
    uint16_t* remotefilename=(uint16_t*)(c+34);
    struct stat ss;
    struct handle* hdl;
    int fd;
    if (fnlen%2) --fnlen;
    if (fnlen>2046 || ((uintptr_t)remotefilename%2)) return -1;
    hdl=alloc_handle(&h->h);
    if (!hdl) {
//      printf("could not open file handle!");
      set_smb_error(sr,STATUS_TOO_MANY_OPENED_FILES,0x2d);
      return 0;
    }

    fd=smb_open(h,remotefilename,fnlen,&ss,WANT_OPEN);
    if (fd==-1) {
      set_smb_error(sr,ERROR_OBJECT_NAME_NOT_FOUND,0x2d);
      close_handle(hdl);
      return 0;
    }
    hdl->fd=fd;
    hdl->pid=pid;
    hdl->size=ss.st_size;
    hdl->cur=0;
    hdl->filename=malloc(fnlen+2);
    if (hdl->filename) {
      memcpy(hdl->filename+1,remotefilename,fnlen);
      hdl->filename[0]=fnlen;
    }

    uint16_pack(nr+3,sr->used+15*2+3);
    uint16_pack(nr+5,hdl->handle);
    uint32_pack(nr+9,ss.st_mtime);
    uint32_pack(nr+13,ss.st_size);
  }

  return add_smb_response(sr,nr,15*2+3,0x2d);
}

static uint32_t mymax(uint32_t a,uint32_t b) {
  return a>b?a:b;
}

static int smb_handle_ReadAndX(struct http_data* h,unsigned char* c,size_t len,uint32_t pid,struct smb_response* sr) {
  static char nr[24+4]=
    "\x0c"	// word count 12
    "\xff"	// AndXCommand
    "\x00"	// Reserved
    "xx"	// AndXOffset; ofs 3
    "xx"	// Remaining; ofs 5
    "\x00\x00"	// data compaction mode
    "\x00\x00"	// reserved
    "xx"	// data length low; ofs 11
    "xx"	// data offset; ofs 13
    "\x00\x00\x00\x00"	// data length high (*64k)
    "\x00\x00\x00\x00\x00\x00"	// reserved
    "xx"	// byte count; ofs 24
    ;
  uint16_t handle;
  uint16_t count;
#if 0
  uint32_t relofs;
#endif
  struct handle* hdl;
  int r;
  if (len<2*10 || (c[0]!=10 && c[0]!=12)) return -1;
  
  handle=uint16_read((char*)c+5);
  if (!(hdl=deref_handle(&h->h,pid,handle))) {
    set_smb_error(sr,STATUS_INVALID_HANDLE,0x2e);
    return 0;
  }

  hdl->cur=uint32_read((char*)c+7);
  if (c[0]==12)
    hdl->cur |= ((unsigned long long)uint32_read((char*)c+21))<<32;
#if 0
  relofs=uint32_read((char*)c+7);

  printf("cur %llu, size %llu, relofs %ld -> ",hdl->cur,hdl->size,relofs);
  if (relofs<0) {
    if (hdl->cur<-relofs) hdl->cur=0; else hdl->cur+=relofs;
  } else if (hdl->cur+relofs<hdl->size)
    hdl->cur+=relofs;
  else
    hdl->cur=hdl->size;

  printf("%llu\n",hdl->cur);
#endif

  if (uint32_read((char*)c+15))
    count=64000;
  else
    count=mymax(uint16_read((char*)c+13),uint16_read((char*)c+11));
  if (count>65500) count=65500;

  if (count>hdl->size-hdl->cur) count=hdl->size-hdl->cur;

  uint16_pack(nr+3,0);	// no andx for read
  if (1) {
    off_t rem=hdl->size-hdl->cur-count;
    uint16_pack(nr+5,rem>0xffff?0xffff:rem);
  } else
    uint16_pack(nr+5,0xffff);
  uint16_pack(nr+11,count);
  uint16_pack(nr+13,sr->used+12*2);
  uint16_pack(nr+25,count);

  r=add_smb_response(sr,nr,12*2+3,0x2e);
  if (r==0) {
#ifdef DEBUG
    hexdump(sr->buf,sr->used);
#endif
    uint32_pack_big(sr->buf,sr->used-4+count);	// update netbios size field
    iob_addbuf_free(&h->iob,sr->buf,sr->used);
    iob_addfile(&h->iob,hdl->fd,hdl->cur,count);
    hdl->cur+=count;
  }
  return r;
}

static int smb_handle_Trans2(struct http_data* h,unsigned char* c,size_t len,uint32_t pid,struct smb_response* sr) {
  uint16_t subcommand;
  uint16_t paramofs,paramcount;
  uint16_t dataofs;
  uint16_t loi=0;
  struct handle* hdl;
  struct stat ss;
  uint32_t attr;

  uint16_t* filename=0;
  uint16_t fnlen=0;

  if (len<2*15 || c[0]!=15) return -1;
  subcommand=uint16_read((char*)c+29);
  paramofs=uint16_read((char*)c+21);
  paramcount=uint16_read((char*)c+19);
  dataofs=uint16_read((char*)c+25);
  if (dataofs > len+smbheadersize) return -1;
  if (paramofs+paramcount > dataofs) return -1;
  if (subcommand==7 || subcommand==5) {	// QUERY_FILE_INFO, QUERY_PATH_INFO
    if (subcommand==7) {
      // QUERY_FILE_INFO
      if (paramcount<4) return -1;
      if (!(hdl=deref_handle(&h->h,pid,uint16_read((char*)c-smbheadersize+paramofs)))) {
	set_smb_error(sr,STATUS_INVALID_HANDLE,0x32);
	return 0;
      }
      if (fstat(hdl->fd,&ss)==-1)
	goto filenotfound;
      if (hdl->filename) {
	fnlen=hdl->filename[0];
	filename=hdl->filename+1;
      }
      loi=uint16_read((char*)c-smbheadersize+paramofs+2);
    } else if (subcommand==5) {
      // QUERY_PATH_INFO
      filename=(uint16_t*)(c-smbheadersize+paramofs+6);
      if ((uintptr_t)filename % 2)
	goto filenotfound;
      if (paramcount<8) return -1;
      fnlen=paramcount-6;
      if (smb_open(h,filename,fnlen,&ss,WANT_STAT)==-1)
	goto filenotfound;
      loi=uint16_read((char*)c-smbheadersize+paramofs);
    } else {
filenotfound:
      set_smb_error(sr,ERROR_OBJECT_NAME_NOT_FOUND,0x32);
      return 0;
    }
    if (S_ISDIR(ss.st_mode))
      attr=0x10;	// directory
    else
      attr=0x80;	// plain file
    switch (loi) {
    case 0x101:		// SMB_QUERY_FILE_BASIC
      {
	char* buf;
	size_t datacount=5+0x24;	// 4x8 for dates, 4 for file attributes
	buf=alloca(20+100+datacount);
	byte_copy(buf,21,
	  "\x0a"		// word count
	  "\x02\x00"	// total parameter count
	  "xx"		// total data count; ofs 3
	  "\x00\x00"	// reserved
	  "\x02\x00"	// parameter count
	  "xx"		// parameter offset; ofs 9
	  "\x00\x00"	// parameter displacement
	  "xx"		// data count (same as total data count); ofs 13
	  "xx"		// data offset; ofs 15
	  "\x00\x00"	// data displacement
	  "\x00"		// setup count
	  "\x00");	// reserved
	uint16_pack(buf+3,datacount);
	uint16_pack(buf+9,sr->used-4+24);
	uint16_pack(buf+13,datacount);
	uint16_pack(buf+15,sr->used+24);
	uint16_pack(buf+21,datacount);
	buf[23]=0;
	uint16_pack(buf+24,0);	// ea error offset
	uint16_pack(buf+26,0);	// padding
	uint64_pack_ntdate(buf+28,ss.st_ctime);
	uint64_pack_ntdate(buf+28+8,ss.st_atime);
	uint64_pack_ntdate(buf+28+8+8,ss.st_mtime);
	uint64_pack_ntdate(buf+28+8+8+8,ss.st_mtime);
	uint32_pack(buf+60,attr);	// normal file
	return add_smb_response(sr,buf,21+datacount,0x32);
      }
    case 0x0107:	// SMB_QUERY_FILE_ALL_INFO
      {
	char* buf;
	size_t datacount=78+fnlen;
	buf=alloca(20+100+datacount);
	byte_copy(buf,21,
	  "\x0a"		// word count
	  "\x02\x00"	// total parameter count
	  "xx"		// total data count; ofs 3
	  "\x00\x00"	// reserved
	  "\x02\x00"	// parameter count
	  "xx"		// parameter offset; ofs 9
	  "\x00\x00"	// parameter displacement
	  "xx"		// data count (same as total data count); ofs 13
	  "xx"		// data offset; ofs 15
	  "\x00\x00"	// data displacement
	  "\x00"		// setup count
	  "\x00");	// reserved
	uint16_pack(buf+3,datacount);
	uint16_pack(buf+9,sr->used-4+24);
	uint16_pack(buf+13,datacount);
	uint16_pack(buf+15,sr->used+24);
	uint16_pack(buf+21,datacount);
	buf[23]=0;
	uint16_pack(buf+24,0);	// ea error offset
	uint16_pack(buf+26,0);	// padding
	uint64_pack_ntdate(buf+28,ss.st_ctime);
	uint64_pack_ntdate(buf+28+8,ss.st_atime);
	uint64_pack_ntdate(buf+28+8+8,ss.st_mtime);
	uint64_pack_ntdate(buf+28+8+8+8,ss.st_mtime);
	uint32_pack(buf+60,attr);	// normal file
	uint64_pack(buf+68,(unsigned long long)ss.st_blocks*ss.st_blksize);
	uint64_pack(buf+76,ss.st_size);
	uint32_pack(buf+84,ss.st_nlink);
	byte_zero(buf+88,8);
	uint32_pack(buf+96,fnlen);
	if (fnlen)
	  byte_copy(buf+100,fnlen,filename);
	return add_smb_response(sr,buf,21+datacount,0x32);
      }
    default:
      set_smb_error(sr,ERROR_ACCESS_DENIED,0x32);
      return 0;
    }
  } else if (subcommand==1) {	// FIND_FIRST2
    size_t i,l=dataofs-paramofs-12;
    size_t maxdatacount;
    char* globlatin1,* globutf8;
    uint16_t attr,flags;
    DIR* d;
    if (sr->used>16*1024) {
outofmemory:
      set_smb_error(sr,ERROR_NO_MEMORY,0x32);
      return 0;
    }
    if (paramcount<18)
      return -1;		// need at least six chars for "/*" in unicode
    maxdatacount=uint16_read((char*)c+7);
    attr=uint16_read((char*)c-smbheadersize+paramofs);
    flags=uint16_read((char*)c-smbheadersize+paramofs+4);
    loi=uint16_read((char*)c-smbheadersize+paramofs+6);
    if (loi!=0x104) {
      set_smb_error(sr,ERROR_NOT_SUPPORTED,0x32);
      return 0;
    }
    filename=(uint16*)(c-smbheadersize+paramofs+12);

    {
      /* we want to minimize copies, so we realloc enough space into the
       * smb buffer right from the start. */
      char* tmp=realloc(sr->buf,sr->used+maxdatacount+100);
      if (!tmp) goto outofmemory;
      sr->buf=tmp;
    }
    sr->allocated=sr->used+maxdatacount+100;

    if ((uintptr_t)filename % 2)
      goto filenotfound;
    if (filename[l])
      return -1;		// want null terminated filename
    if (uint16_read((char*)&filename[l-1])=='\\' || uint16_read((char*)&filename[l-1])=='/')
      goto filenotfound;	// can't glob if filename ends in \ or /
    if (uint16_read((char*)&(filename[0]))!='\\')
      goto filenotfound;
    for (i=l; i>0; --i)
      if (uint16_read((char*)&filename[i])=='\\') {
	filename[i]=0;
	break;
      }
    fnlen=i*2;
    if (smb_open(h,filename+1,fnlen,0,WANT_CHDIR)==-1)
      goto filenotfound;
    filename+=i+1; l-=i;
    globlatin1=alloca(l+1);
    if (utf16tolatin1(globlatin1,l-i+1,filename,(l+1)*2)) {
      globlatin1=0;
      puts("could not convert glob expression to latin1!");
    } else
//      printf("glob expression \"%s\"\n",globlatin1);
    globutf8=alloca((l+1)*3);
    if (utf16toutf8(globutf8,(l+1)*3,filename,(l+1)*3)) {
      globutf8=0;
//      puts("could not convert glob expression to utf-8!");
    }
    if (globlatin1 && globutf8 && !strcmp(globutf8,globlatin1)) globutf8=0;
    if (!globlatin1 && !globutf8)
      goto filenotfound;

    d=opendir(".");
    if (d) {
      struct dirent* de;
      struct stat ss;
      size_t actualnamelen;
      size_t searchcount=0;
      char* cur=0,* max=0,* base=0,* trans2=0,* smbhdr,* last=0;
      smbhdr=sr->buf+4;

      while ((de=readdir(d))) {

	if (de->d_type!=DT_DIR && de->d_type!=DT_REG) continue;
	if (de->d_type==DT_DIR && !(attr&0x10)) continue;

	if (de->d_name[0]=='.') continue;
	if (de->d_name[0]==':') de->d_name[0]='.';
	if ((globlatin1 && !fnmatch(globlatin1,de->d_name,0)) ||
	    (globutf8 && !fnmatch(globutf8,de->d_name,0))) {
	  if (stat(de->d_name,&ss)==-1) continue;
//	  printf("globbed ok: %s\n",de->d_name);
	  if (!base) {
	    trans2=sr->buf+sr->used;
	    add_smb_response(sr,
		"\x0a"	// word count
		"\x0a\x00"	// total param count
		"xx"	// total data count; ofs 3
		"\x00\x00"	// reserved
		"\x0a\x00"	// param count
		"xx"	// param ofs; ofs 9
		"\x00\x00"	// param displacement (?!)
		"xx"	// data count; ofs 13
		"xx"	// data offset; ofs 15
		"\x00\x00"	// data displacement
		"\x00"	// setup count
		"\x00"	// reserved
		"xx"	// byte count; ofs 21
		"\x00"	// padding
		// FIND_FIRST2 Parameters
		"\x01\x00"	// search id 1
		"xx"	// search count (?!?); ofs 26
		"\x01\x00"	// end of search; ofs 28
		"\x00\x00"	// ea error offset
		"xx"	// last name offset; ofs 32
		"\x00\x00"	// padding
		// FIND_FIRST2 Data
		,36,0x32);
	    cur=base=sr->buf+sr->used;
	    max=sr->buf+sr->allocated;
	  }
	  if (max-cur < 0x5e +strlen(de->d_name)*2 ||
	      !(actualnamelen=utf8toutf16(cur+0x5e,max-cur-0x5e,de->d_name,strlen(de->d_name)))) {
	    // not enough space!  abort!  abort!
	    trans2[26]=0;
	    break;
	  }
	  last=cur;
	  if (loi==0x104) {
	    size_t padlen=0x5e +actualnamelen;
	    if (padlen%4) padlen+=2;
	    uint32_pack(cur,padlen);
	    cur+=4;
	    uint32_pack(cur,0); cur+=4;	// "file index", samba sets this to 0
	    uint64_pack_ntdate(cur,ss.st_ctime); cur+=8;
	    uint64_pack_ntdate(cur,ss.st_atime); cur+=8;
	    uint64_pack_ntdate(cur,ss.st_mtime); cur+=8;
	    uint64_pack_ntdate(cur,ss.st_mtime); cur+=8;
	    uint64_pack(cur,ss.st_size); cur+=8;
	    uint64_pack(cur,ss.st_blksize*ss.st_blocks); cur+=8;
	    uint32_pack(cur,S_ISDIR(ss.st_mode)?0x10:0x80); cur+=4;
	    uint32_pack(cur,actualnamelen); cur+=4;
	    uint32_pack(cur,0); cur+=4;	// ea list length
	    cur[0]=0;	// short file name len
	    cur[1]=0;	// reserved
	    cur+=2;
	    byte_zero(cur,24);	// the short name
	    cur+=24+actualnamelen;
	    if ((uintptr_t)cur%4) cur+=2;
	    ++searchcount;
	    sr->used=cur-sr->buf;
	    assert(sr->used<sr->allocated);
	  }
	}
      }
      closedir(d);
      uint16_pack(trans2+3,cur-base);
      uint16_pack(trans2+9,trans2+20-sr->buf);
      uint16_pack(trans2+13,cur-base);
      uint16_pack(trans2+15,base-smbhdr);
      uint16_pack(trans2+21,base-smbhdr-12);
      uint16_pack(trans2+26,searchcount);	// search count...!?
      uint16_pack(trans2+32,last-base);
      uint32_pack_big(sr->buf,sr->used-4);
//      printf("sr->used = %u\n",sr->used);
      return 0;
    }
    goto filenotfound;

  } else
    return -1;
}

static int smb_handle_Close(struct http_data* h,unsigned char* c,size_t len,uint32_t pid,struct smb_response* sr) {
  struct handle* hdl;
  if (len<2*3 || c[0]!=3) return -1;
  if (!(hdl=deref_handle(&h->h,pid,uint16_read((char*)c+1)))) {
    set_smb_error(sr,STATUS_INVALID_HANDLE,0x4);
    return 0;
  }
  close_handle(hdl);
  return add_smb_response(sr,"\x00\x00\x00",3,0x4);
}

static int smb_handle_QueryDiskInfo(unsigned char* c,size_t len,struct smb_response* sr) {
  struct statvfs sv;
  char buf[11];
  unsigned long long l,k;
  size_t i;
  if (len<3 || c[0]!=0) return -1;
  if (fstatvfs(origdir,&sv)==-1) {
    set_smb_error(sr,ERROR_ACCESS_DENIED,0x80);
    return 0;
  }
  l=(unsigned long long)sv.f_blocks*sv.f_bsize;
  k=(unsigned long long)sv.f_bavail*sv.f_bsize;
  for (i=0; l>0xffff; ++i) l>>=1;

  buf[0]=5;
  /* ok, this protocol sucks royally; it works in clusters, and you can
   * only express total and free space in clusters, AND you only have 16
   * bits. */
  if (i>30) {
    i=30;
    uint16_pack(buf+1,0xffff);
    if ((k>>i)>0xffff)
      uint16_pack(buf+7,0xffff);
    else
      uint16_pack(buf+7,k>>i);
  } else {
    uint16_pack(buf+1,l);
    uint16_pack(buf+7,k>>i);
    if (i<9+15) {
      uint16_pack(buf+5,1<<9);
      uint16_pack(buf+3,1<<(i-9));
    } else {
      uint16_pack(buf+3,1<<15);
      uint16_pack(buf+3,1<<(i-15));
    }
  }
  uint16_pack(buf+9,0);
  return add_smb_response(sr,buf,11,0x80);
}

int smbresponse(struct http_data* h,int64 s) {
  unsigned char* c=array_start(&h->r);
  unsigned char* smbheader;
  size_t len,cur;
  struct smb_response sr;
  unsigned char andxtype;

  ++rps1;
  h->keepalive=0;
  /* is it SMB? */
  if ((size_t)array_bytes(&h->r)<4+smbheadersize)
    /* uh, what does an error look like? */
    /* dunno, samba doesn't say anything, it just ignores the packet. */
    /* if it's good enough for samba, it's good enough for me. */
    return 0;
  len=uint32_read_big((char*)c)&0xffffff;
  if (len<smbheadersize) return 0;

  if (validate_smb_packet(c+netbiosheadersize,len)==-1)
    return -1;

  /* is it a request?  Discard replies. */
  if (c[13]&0x80) return 0;

  init_smb_response(&sr,c+netbiosheadersize,len);

  c+=netbiosheadersize;
  smbheader=c;

  /* loop over AndX crap */
  andxtype=c[4];
  for (cur=smbheadersize; cur<len && andxtype!=0xff; ) {

    /* what kind of request is it? */
    switch (andxtype) {
    case 0x04:
      /* Close Request */
      if (smb_handle_Close(h,c+cur,len-cur,uint16_read((char*)smbheader+0x1a),&sr)==-1)
	goto kaputt;
      break;

    case 0x10:
      /* Check Directory Request */
      break;

    case 0x2b:
      if (smb_handle_echo(c+cur,len-cur,&sr)==-1)
	goto kaputt;
      break;

    case 0x2d:
      /* Open AndX Request */
      if (smb_handle_OpenAndX(h,c+cur,len-cur,uint16_read((char*)smbheader+0x1a),&sr)==-1)
	goto kaputt;
      break;

    case 0x2e:
      /* Read AndX Request */
      if (smb_handle_ReadAndX(h,c+cur,len-cur,uint16_read((char*)smbheader+0x1a),&sr)==-1)
	goto kaputt;
      goto added;

    case 0x32:
      /* Trans2 Request; hopefully QUERY_FILE_INFO */
      if (smb_handle_Trans2(h,c+cur,len-cur,uint16_read((char*)smbheader+0x1a),&sr)==-1)
	goto kaputt;
      break;

    case 0x71:
      /* Tree Disconnect Request */
      if (smb_handle_TreeDisconnect(c+cur,len-cur,&sr)==-1)
	goto kaputt;
      break;

    case 0x72:
      /* protocol negotiation request */
      if (smb_handle_negotiate_request(c+cur,len-cur,&sr)==-1)
	goto kaputt;
      break;

    case 0x73:
      /* Session Setup AndX Request */
      if (smb_handle_SessionSetupAndX(c+cur,len-cur,&sr)==-1)
	goto kaputt;
      break;


    case 0x75:
      /* Tree Connect AndX Request */
      if (smb_handle_TreeConnectAndX(c+cur,len-cur,&sr)==-1)
	goto kaputt;
      break;

    case 0x80:
      if (smb_handle_QueryDiskInfo(c+cur,len-cur,&sr)==-1)
	goto kaputt;
      break;

    case 0xa2:
      if (smb_handle_CreateAndX(h,c+cur,len-cur,uint16_read((char*)smbheader+0x1a),&sr)==-1)
	goto kaputt;

    }
    if (!hasandx(andxtype)) break;
    andxtype=c[cur+1];
    if (andxtype==0xff) break;
    if (cur+5>len)
      goto kaputt;
    else {
      size_t next=uint16_read((char*)smbheader+cur+3);
      if (next<=cur || next>len)
	goto kaputt;
      cur=next;
    }
  }

#ifdef DEBUG
  hexdump(sr.buf,sr.used);
#endif

  iob_addbuf_free(&h->iob,sr.buf,sr.used);
added:
  io_dontwantread(s);
  io_wantwrite(s);
  h->keepalive=1;
  return 0;
kaputt:
  free(sr.buf);
  return -1;
}

#endif /* SUPPORT_SMB */


