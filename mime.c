#include "mmap.h"
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdio.h>

struct arena {
  struct arena* next;
  unsigned long n;
  void* ptrs[(4096/sizeof(void*))-2];
};

static void ainit(struct arena* a) {
  a->n=0; a->next=0;
}

static void* amalloc(struct arena* a,size_t n) {
  void* x;
  while (a->n==(sizeof(a->ptrs)/sizeof(a->ptrs[0])) && a->next) a=a->next;
  if (a->n==(sizeof(a->ptrs)/sizeof(a->ptrs[0]))) {
    if (!(a->next=malloc(sizeof(struct arena)))) return 0;
    ainit(a->next);
    a=a->next;
  }
  if ((a->ptrs[a->n]=x=malloc(n))) ++a->n;
  return x;
}

#if 0
static void afree(struct arena* a,void* x) {
  for (; a; a=a->next) {
    unsigned int i;
    for (i=0; i<a->n; ++i)
      if (a->ptrs[i]==x) {
	free(x);
	a->ptrs[i]=a->ptrs[a->n-1];
	--a->n;
      }
  }
}
#endif

static void free_arena(struct arena* a) {
  for (; a; a=a->next) {
    unsigned int i;
    struct arena* x;
    for (i=0; i<a->n; ++i)
      free(a->ptrs[i]);
    x=a->next;
  }
}


struct pool {
  struct arena a;
  char* dat;
  size_t rest;
};

static void pinit(struct pool* p) {
  ainit(&p->a);
  p->rest=0;
}

static void* pmalloc(struct pool* p,size_t n) {
  void* x;
  if (n>p->rest) {
    if (n>4096) return amalloc(&p->a,n);
    if (!(p->dat=amalloc(&p->a,p->rest=16*1024))) return 0;
  }
  x=p->dat;
  p->dat+=n;
  p->rest-=n;
  return x;
}

static void pfree(struct pool* p) {
  free_arena(&p->a);
}



static const char* nextline(const char* x,const char* end) {
  for (; x<end; ++x)
    if (*x=='\n') return x+1;
  return x;
}

static const char* skipws(const char* x,const char* end) {
  for (; x<end && (*x==' ' || *x=='\t'); ++x) ;
  return x;
}

static const char* skipnonws(const char* x,const char* end) {
  for (; x<end && *x!=' ' && *x!='\t' && *x!='\n'; ++x) ;
  return x;
}

static char* memdup(struct pool* p,const char* x,const char* end) {
  char* y=0;
  if (x<end) {
    y=pmalloc(p,end-x+1);
    if (y) {
      memcpy(y,x,end-x);
      y[end-x]=0;
    }
  }
  return y;
}

static struct mimeentry { const char* name, *type; }* mimetypes;
static struct pool* mimepool;

static void parse_mime_types(const char* filename) {
  int res;
  size_t maplen;
  const char* map=mmap_read(filename,&maplen);
  unsigned int allocated=0,used=0;
  struct mimeentry* nmt=0;
  res=0;
  if (map) {
    const char* mimetype;
    const char* extension;
    const char* end=map+maplen;
    const char* x,* l;
    struct pool* p=malloc(sizeof(struct pool));
    if (!p) goto kaputt;
    pinit(p);
    for (l=map; l<end; l=nextline(l,end)) {
      x=skipws(l,end);
      if (x>=end) break; if (*x=='#' || *x=='\n') continue;

      mimetype=x;
      x=skipnonws(x,end);
      if (x>=end) break; if (*x=='#' || *x=='\n') continue;

      mimetype=memdup(p,mimetype,x);

      x=skipws(x,end);
      if (x>=end) break; if (*x=='#' || *x=='\n') continue;

      while (x<end) {
	extension=x;
	x=skipnonws(x,end);
	if (x>extension) {
	  extension=memdup(p,extension,x);
	  if (!extension) continue;
//	  printf("%s -> %s\n",extension,mimetype);

	  if (used+1 > allocated) {
	    struct mimeentry* tmp;
	    allocated+=16;
	    tmp=realloc(nmt,allocated*sizeof(nmt[0]));
	    if (!tmp) {
	      free(nmt);
	      pfree(p);
	      free(p);
	      nmt=0;
	      goto kaputt;
	    }
	    nmt=tmp;
	  }
	  nmt[used].name=extension;
	  nmt[used].type=mimetype;
	  ++used;

	}
	x=skipws(x,end);
	if (x>=end || *x=='#' || *x=='\n') break;
      }
      if (x>=end) break;
    }
    if (mimepool) { pfree(mimepool); free(mimepool); }
    mimepool=p;
kaputt:
    mmap_unmap((char*)map,maplen);
  }
  if (nmt) {
    nmt[used].name=nmt[used].type=0;
    free(mimetypes);
    mimetypes=nmt;
  }
}

const char* find_mime_type(const char* extension,const char* filename,time_t now) {
  static time_t last;
  static struct stat lasts;
  unsigned int i;
  if (now>last+10) {
    struct stat cur;
    last=now;
    if (stat(filename,&cur)==0 && cur.st_mtime != lasts.st_mtime) {
      lasts=cur;
      parse_mime_types(filename);
    }
  }
  if (mimetypes)
    for (i=0; mimetypes[i].name; ++i)
      if (!strcmp(mimetypes[i].name,extension))
	return mimetypes[i].type;
  return 0;
}

#ifdef MIME_MAIN
int main() {
  unsigned int i;
  parse_mime_types("/etc/mime.types");
  for (i=0; mimetypes[i].name; ++i)
    printf("%s -> %s\n",mimetypes[i].name,mimetypes[i].type);
  printf("\n\n ------\n\n");
  parse_mime_types("/etc/mime.types");
  for (i=0; mimetypes[i].name; ++i)
    printf("%s -> %s\n",mimetypes[i].name,mimetypes[i].type);
  free(mimetypes);
  pfree(mimepool);
  free(mimepool);
  return 0;
}
#endif
