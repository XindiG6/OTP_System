/*********************************
**Program:OTP
**Author: Xindi Guo
**Date: 12/6/2019
**Description: create a random key that from 27 letters based on the required length
*********************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char** argv)
{
    int i = 0;
    int length;
    // make sure there are enough args
    if (argc < 2)
    {
        printf("Usage: keygen keyLength\n");
        exit(1);
    }

    // covert string to int
    sscanf(argv[1], "%d", &length);

    if (length < 1)
    {
        printf("keygen: invalid keyLength\n");
        exit(1);
    }

    // seed the rand() function
    srand(time(NULL));
    char ch;
    // loop length number of times
    for (i = 0; i < length; i++)
    {
        // generate a random letter
        ch=(rand()%26)+'A';
        printf("%c", ch);
    }
    printf("\n");
    return 0;
}

