#include <buffer.h>

int main(int argc,char* argv[],char* envp[]) {
  int i;
  (void)argc;
  (void)argv;
  buffer_puts(buffer_1,"Content-Type: text/plain\r\n\r\n");
  for (i=0; envp[i]; ++i)
    buffer_putm(buffer_1,envp[i],"\n");
  buffer_flush(buffer_1);
  return 0;
}
