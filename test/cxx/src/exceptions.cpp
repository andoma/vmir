#include <stdio.h>
#include <string.h>

struct MyError {

  MyError(const char *msg, int code) {
    strcpy(msg_, msg);
    code_ = code;
  };

  char msg_[80];
  int code_;
};



int a = 30;
int b = 40;

void foo() {

  if(a != b)
    throw(MyError("not the same value", 123));
  throw(3);
}

int bar(void)
{
  try {

    foo();

    return 1;
  } catch(int e) {
    return e;
  } catch(long e) {
    return e * 100;
  } catch(MyError e) {
    printf("Catched error: %s\n", e.msg_);


    try {
      throw((long)3);
    } catch(char x) {
      printf("x=%d\n", x);
    }
    printf("end of the myerror catch\n");

    return 5009;
  }
}


extern "C" {
  int main(void)
  {
    return bar();
  }
}
