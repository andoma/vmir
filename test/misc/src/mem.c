#include <stdint.h>
#include <stdlib.h>


int
main(void)
{
  uint32_t *hej = malloc(32);
  void *vec[10];
  for(int i = 0; i < 10; i++)
    vec[i] = malloc(i * 10);
  *hej = 30;
  hej = realloc(hej, 10000);

  if(*hej != 30)
    abort();
  free(hej);

  for(int i = 9; i >= 0; i--)
    free(vec[i]);

  for(int i = 0; i < 10; i++)
    vec[i] = malloc(i * 10);

  vec[3] = realloc(vec[3], 1235);
  vec[3] = realloc(vec[3], 123);
  vec[3] = realloc(vec[3], 12300);
  free(vec[5]);
  vec[5] = NULL;

  vec[7] = realloc(vec[7], 0);
  __vmir_heap_print();

  for(int i = 9; i >= 0; i--)
    free(vec[i]);
  __vmir_heap_print();
  exit(0);

}
