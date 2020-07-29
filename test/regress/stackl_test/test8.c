//#include <string.h>

int f2();
int f1(int a, int b);

int f1(int a, int b)
{
    printf("%d", a + b);
    puts("\n");
    return a + b;
}
int main()
{
    int ret;
    printf("%d", 0);
    puts("\n");
    f1(5, 8);
    ret = f2();
    printf("%d", 3);
    puts("\n");
    printf("%d", ret);
    puts("\n");
    ret = 2*f2() - 3;
    printf("%d", ret);
    puts("\n");
}
int f2()
{
    printf("%d", 2);
    puts("\n");
    return 4;
}
