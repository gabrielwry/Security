/* Betrayal */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>


void brutus(char *caesar)
{
        char buf[4];

        if (strlen(caesar) > 20)
        {
                printf ("Et tu, Brute?\n");
                return;
        }

        strcpy (buf, caesar);

        printf ("Alea iacta est: %d\n", (int)strlen(buf));

        return;
}


extern char **environ;

int main(int argc, char **argv)
{
        int i = 0;
        if (argc != 2)
        {
                printf ("I can haz one argument?\n");
                return -1;
        }
        /* Clear all environment variables so people don't sneak nasty things into my memory >:( */
        while (environ[i])
        {
                memset (environ[i], 0, strlen(environ[i]));
                i++;
        }
        clearenv(); /* Flush out the environment table */
        for (i = 0; i < strlen(argv[0]); i++)
        {
                if (!isalnum (argv[0][i]) && strchr("-_/",argv[0][i]) == NULL)
                        return -2;
        }

        brutus(argv[1]);

        return 0;

}
