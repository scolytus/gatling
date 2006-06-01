#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

size_t hash(const char* word) {
  size_t x;
  for (x=0; *word; ++word) {
    x = x*5^*word;
  }
  return x;
}

#define HASHTABSIZE 65536

struct node {
  char* word,* ip,* port,* timestamp;
  struct node* next;
}* hashtab[HASHTABSIZE];

void* allocassert(void* x) {
  if (!x) {
    fprintf(stderr,"out of memory!\n");
    exit(1);
  }
  return x;
}

struct node** lookup(char* word) {
  struct node** x;
  for (x=&hashtab[hash(word)%HASHTABSIZE]; *x; x=&(*x)->next)
    if (!strcmp(word,(*x)->word))
      break;
  return x;
}

char printfbuf[4096];

int main() {
  char line[8192];
  char* dat;
  char* timestamp;
  setvbuf(stdout,printfbuf,_IOFBF,sizeof printfbuf);
  while (fgets(line,sizeof(line),stdin)) {
    int tslen;
    /* chomp */
    {
      int i;
      for (i=0; i<sizeof(line) && line[i]; ++i)
	if (line[i]=='\n') break;
      line[i]=0;
    }
    /* find out what kind of time stamp there is */
    tslen=0;
    if (line[0]=='@') {
      /* multilog timestamp */
      char* x=strchr(line,' ');
      if (x) {
	tslen=x-line;
	if (tslen!=25) tslen=0;
      }
    } else if (isdigit(line[0])) {
      char* x=strchr(line,' ');
      if (x && x==line+10) {
	x=strchr(x+1,' ');
	if (x && x==line+29) tslen=29;
      }
    }
    if (tslen) {
      dat=line+tslen+1;
      line[tslen]=0;
      timestamp=line;
    } else {
      dat=line;
      timestamp="";
    }
    /* element two is the unique key */
    {
      char* fields[20];
      char* x=dat;
      int i;
      /* split into fields */
      for (i=0; i<20; ++i) {
	char* y=strchr(x,' ');
	if (!y) break;
	*y=0;
	fields[i]=x;
	x=y+1;
      }
      fields[i]=x; ++i;
      if (!strcmp(fields[0],"accept")) {
	struct node** N;
	struct node* x;
	if (i<2) continue;
	N=lookup(fields[1]);
	if (!(x=*N)) {
	  *N=malloc(sizeof(**N));
	  (*N)->next=0;
	  x=*N;
	} else {
	  free(x->word);
	  free(x->ip);
	  free(x->port);
	  free(x->timestamp);
	}
	x->word=allocassert(strdup(fields[1]));
	x->ip=allocassert(strdup(fields[2]));
	x->port=allocassert(strdup(fields[3]));
	x->timestamp=allocassert(strdup(line));
      } else if (!strncmp(fields[0],"close/",6)) {
	struct node** N;
	N=lookup(fields[1]);
	if (*N) {
	  struct node* y=(*N)->next;
	  struct node* x=*N;
	  free(x->word);
	  free(x->ip);
	  free(x->port);
	  free(x->timestamp);
	  free(x);
	  *N=y;
	}
      } else if (!strncmp(fields[0],"GET",3) || !strncmp(fields[0],"POST",4) || !strncmp(fields[0],"HEAD",4)) {
	if (i>6) {	/* otherwise it's a format violation and we ignore the line */
	  struct node** N;
	  N=lookup(fields[1]);
	  printf("%s %s %s http%s://%s%s %s %s %s\n",
		 timestamp,fields[0],*N?(*N)->ip:"::",
		 strstr(fields[0],"SSL")?"s":"",fields[6],fields[2],fields[3],fields[4],fields[5]);
	}
      }
    }
  }
  return 0;
}
