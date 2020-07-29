//#include <string.h>
//#include <system.h>

// test expressions and all operators
//
int DoNotPrintMe()
{
    printf("failure\n");
    return 1;  
}

int DoPrintMe(int ret)
{
    printf("success\n");
    return ret;  
}

int main()
{
    int x;
    int y;
    int z;

    // EQUAL
    if (5 == 5)
        if (5 == 6)
            printf("EQ 1 broken\n");
        else
            printf("EQ works\n");
    else
        printf("EQ 2 broken\n");

    // NE
    x = 5;
    y = 6;
    z = 5;
    if (x != y)
        if (x != z)
            printf("NE 1 broken\n");
        else
            printf("NE works\n");
    else
        printf("NE 2 broken\n");

    // AND
    if (5 && 4)
        if (4 && 0)
           printf("AND 1 broken\n");
       else
           printf("AND works\n");
    else
        printf("AND 2 broken\n");

    // OR
    if ( (0 || 1) && (1 || 0) && (1 || 1))
        if (0 || 0)
           printf("OR 1 broken\n");
       else
           printf("OR works\n");
    else
        printf("OR 2 broken\n");

    // GT
    if (5 > 4)
        if (4 > 4 || 4 > 5)
           printf("GT 1 broken\n");
       else
           printf("GT works\n");
    else
        printf("GT 2 broken\n");

    // LT
    if (4 < 5)
        if (4 < 4 || 5 < 4)
           printf("LT 1 broken\n");
       else
           printf("LT works\n");
    else
        printf("LT 2 broken\n");

    // GE
    if (5 >=4 && 4 >= 4)
        if (4 >= 5)
           printf("GE 1 broken\n");
       else
           printf("GE works\n");
    else
        printf("GE 2 broken\n");

    // LE
    if (4 <= 5 && 4 <= 4)
        if (5 < 4)
           printf("LE 1 broken\n");
       else
           printf("LE works\n");
    else
        printf("LE 2 broken\n");

    // PLUS
    x = 2;
    y = x + 1;
    if (y == 3)
        printf("PLUS works\n");
    else
        printf("PLUS broken\n");

    // MINUS
    z = 11-y;
    if (z == 8)
        printf("MINUS works\n");
    else
        printf("MINUS broken\n");

    // TIMES
    z = x*3;
    if (z == 6)
        printf("TIMES works\n");
    else
        printf("TIMES broken\n");

    // DIVIDE
    x = 2;
    y = 11/x;
    if (y == 5)
        printf("DIVIDE works\n");
    else
        printf("DIVIDE broken\n");

    // MOD
    z = 13;
    x = z % 5;
    if (x == 3)
        printf("MOD works\n");
    else
        printf("MOD broken\n");

    // XOR
    x = 0x5A5AA5A5;
    z = x ^ 0x0F0F;
    if (z == 0x5A5AAAAA)
        printf("XOR works\n");
    else
        printf("XOR broken\n");

    // Bitwise AND
    x = 0x5A5AA5A5;
    z = x & 0x0F0F;
    if (z == 0x0505)
        printf("Bitwise AND works\n");
    else
        printf("Bitwise AND broken\n");

    // Bitwise OR
    x = 0x5A5AA5A5;
    z = x | 0x0F0F;
    if (z == 0x5A5AAFAF)
        printf("Bitwise OR works\n");
    else
        printf("Bitwise OR broken\n");

    // shift left
    z = 0x0555 << 1;
    if (z == 0x0AAA)
        printf("shift left works\n");
    else
        printf("shift left broken\n");
    
    // shift right
    x = z >> 1;
    if (x == 0x0555)
        printf("shift right works\n");
    else
        printf("shift right broken\n");

    // NEG
    x = 11;
    z = -x + 20;
    if (z == 9)
        printf("NEG works\n");
    else
        printf("NEG broken\n");

    // NOT
    x = 0x5A5AA5A5;
    z = !x;
    if (z == 0)
        printf("NOT 1 works\n");
    else
        printf("NOT 1 broken\n");

    z = 0;
    x = !z;
    if (x)
        printf("NOT 2 works\n");
    else
        printf("NOT 2 broken\n");

    // COMP
    x = 0x5A5AA5A5;
    z = ~x;

    if (z == 0xA5A55A5A)
        printf("COMP works\n");
    else
        printf("COMP broken\n");

    // PLUS_EQ
    z = 5;
    z += 7;
    if (z == 12)
        printf("PLUS_EQ works\n");
    else
        printf("PLUS_EQ broken\n");

    // MINUS_EQ
    z = 5;
    z -= 7;
    if (z == -2)
        printf("MINUS_EQ works\n");
    else
        printf("MINUS_EQ broken\n");

    // TIMES_EQ
    z = 5;
    z *= 7;
    if (z == 35)
        printf("TIMES_EQ works\n");
    else
        printf("TIMES_EQ broken\n");

    // DIVIDE_EQ
    z = 35;
    z /= 7;
    if (z == 5)
        printf("DIVIDE_EQ works\n");
    else
        printf("DIVIDE_EQ broken\n");

    // MOD_EQ
    z = 37;
    z %= 7;
    if (z == 2)
        printf("MOD_EQ works\n");
    else
        printf("MOD_EQ broken\n");

    // OR_EQ
    z = 0x0A5A5;
    z |= 0xFF;
    if (z == 0x0A5FF)
        printf("OR_EQ works\n");
    else
        printf("OR_EQ broken\n");

    // AND_EQ
    z = 0x0A5A5;
    z &= 0xFF;
    if (z == 0xA5)
        printf("AND_EQ works\n");
    else
        printf("AND_EQ broken\n");

    // XOR_EQ
    z = 0x0A5A5;
    z ^= 0xFF;
    if (z == 0x0A55A)
        printf("XOR_EQ works\n");
    else
        printf("XOR_EQ broken\n");

    // LEFT_EQ
    z = 0x0555;
    z <<= 2;
    if (z == 0x1554)
        printf("LEFT_EQ works\n");
    else
        printf("LEFT_EQ broken\n");

    // RIGHT_EQ
    z = 0x1554;
    z >>= 2;
    if (z == 0x0555)
        printf("RIGHT_EQ works\n");
    else
        printf("RIGHT_EQ broken\n");

    // post INC
    z = 35;
    x = z++;
    if (x == 35 && z == 36)
        printf("post INC works\n");
    else
        printf("post INC broken\n");

    // post DEC
    z = 37;
    x = z--;
    if (x == 37 && z == 36)
        printf("post DEC works\n");
    else
        printf("post DEC broken\n");

    // pre INC
    z = 36;
    x = ++z;
    if (x == 37 && z == 37)
        printf("pre INC works\n");
    else
        printf("pre INC broken\n");

    // pre DEC
    z = 36;
    x = --z;
    if (x == 35 && z == 35)
        printf("pre DEC works\n");
    else
        printf("pre DEC broken\n");
    
    // equals in expr
    z = 36;
    z = (x = 5);
    if (z==5 && x==5)
        printf("equals in expr works\n");
    else
        printf("equals in expr broken\n");

    // Check short circuit nature of || and &&
    //
    if(0 && DoNotPrintMe())
        printf("failure\n");
    if(1 || DoNotPrintMe())
        printf("success\n");
    if(1 && DoPrintMe(0))
        printf("failure\n");
    if(0 || DoPrintMe(0))
        printf("failure\n");
    if(1 && DoPrintMe(1))
        printf("success\n");
    if(0 || DoPrintMe(1))
        printf("success\n");
}

