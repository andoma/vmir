// this file contains BMP chars encoded in UTF-8
#include <stdio.h>
//#include <wchar.h>

int main()
{
    unsigned int* s = (unsigned int*)L"hello$$你好¢¢世界€€world";
    unsigned int *p;
    for (p = s; *p; p++) printf("%04X ", (unsigned) *p);
    printf("\n");
    return 0;
}
