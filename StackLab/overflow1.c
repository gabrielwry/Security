
#include <stdio.h>
#include <unistd.h>
#include <string.h>


void customerservice(char *arg)
{
        char buf[196];

        strcpy (buf, arg);

        printf ("Thank you for contacting customer service. You are so important to us that we wrote a program to serve you.\n");
        printf ("Please hold for %u minutes while I drop your call\n", (int)strlen(buf));

        return;
}



int main(int argc, char **argv)
{
        if (argc != 2)
        {
                printf ("Welcome to customer service.\n");
                printf ("All agents are currently idle. Please call back later with some spare time (as an argument).\n");
                return -1;
        }

        customerservice (argv[1]);

        printf ("We were naturally unable to complete your call. Goodbye!\n");

        return 0;

}
