#include <stdio.h>
void overflow()
{
   char buf[256];
   gets(buf);
}


int main(int argc, char *argv[])
{
   overflow();
}
