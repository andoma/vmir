#include <stdlib.h>

struct beta {
  const char *info;
  int values[4];

};


struct alpha {
  struct beta b[4];
};


struct alpha a = {
  {
    { "row1", 1,2,3,4 },
    { "row2", 5,6,7,8 },
    { "row3", 11,12,13,14 },
    { "row4", 15,16,17,18 }
  },
};

int x = 3;
int y = 2;


int main(void)
{
  int z = a.b[x].values[y];
  if(z != 17)
    abort();
  exit(0);
}
