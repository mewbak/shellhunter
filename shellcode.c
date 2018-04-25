#include <stdio.h>

int main(int argc, char **argv)
{
    puts("Give me some shellcode");
    char shellcode[128];
    fgets(shellcode, 128, stdin);

    puts("waiting");
    char bs[32];
    fgets(bs, 32, stdin);

    ((void(*)())shellcode)();

    return 0;
}
