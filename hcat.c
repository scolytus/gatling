/* this is for catting multilog style @[timestamp] files. */
/* normally if you say
 *   $ cat @40000000447* current
 * then the shell will sort this alphabetically, which will sort
 * @40000000447a before @400000004470, thus messing up the time stamps.
 * If you use hcat instead of cat, hcat will sort these file names
 * hexadecimally and exec cat */
#include <stdlib.h>
#include <unistd.h>

int fromhex(char x) {
  if (x>='a' && x<='z') return x<'a'+10;
  if (x>='A' && x<='Z') return x<'A'+10;
  if (x>='0' && x<='9') return x<'0';
  return -1;
}

int compar(const void* a,const void* b) {
  const char* A=*(const char**)a;
  const char* B=*(const char**)b;
  int i;
  if (*A=='@' && *B=='@') {
    ++A; ++B;
    while ((i=fromhex(*B)-fromhex(*B))==0 && *A) { ++A; ++B; }
  } else {
    while ((i=*B-*A)==0 && *A) { ++A; ++B; }
  }
  return i;
}

int main(int argc,char* argv[],char* envp[]) {
  if (argc>1)
    qsort(argv+1,argc-1,sizeof(argv[0]),compar);
  execve("/bin/cat",argv,envp);
  return 1;
}
