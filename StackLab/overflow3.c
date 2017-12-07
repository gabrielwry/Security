
/* Property of USER */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

/* I am an innocent program. Please don't overflow me */

int zerg(char *arg)
{
        char buf[12];
        static int i, sum;

        if (strlen (arg) > 24) /* Argument too long! */
        {
                printf ("[ZERG] String too long!\n");
                return -1;
        }

        /* Compute checksum */
        for (i = 0, sum = 0; i < strlen(arg); i++)
                sum += (int)arg[i];

        if ( (sum & 0xff) != 0)
        {
                printf ("[ZERG] Sum of incoming buffer is not divisible by 256 :-(\n");
                exit (1);
        }

        /* Check the first 10 characters */
        if (strncmp (arg, "RUSHKEKEKE", 10))
        {
                printf ("[ZERG] No warning issued for the incoming Zergling rush :-(\n");
                exit (1);
        }

        strcpy (buf, arg);

        printf ("[ZERG] Buffer received %d characters!\n", strlen(buf));

        return 0;
}


extern char **environ;

/* Nobody ever calls me :-( */
int farmville(void)
{
        char buf[227];
        static int i, sum = 0, c;

        while ( (c = getc(stdin)) != EOF)
        {
                if (c == '\n')
                        break;
                buf[i++] = c;
        }

        for (i = 0; i < strlen(buf); i++)
                sum += (int)buf[i];

        if ( (sum & 0xff) != 0)
        {
                printf ("[FARMVILLE] Sum of incoming buffer is not divisible by 256 :-(\n");
                exit (1);
        }

        printf ("[FARMVILLE] Spammed the walls of %d Facebook friends!\n", strlen(buf));

        return 0;
}


int main(int argc, char **argv)
{
        int i = 0;

        if (argc != 2)
        {
                printf ("Need exactly one argument\n");
                return -1;
        }
        /* Clear all environment variables so people don't sneak nasty things into my memory >:( */
        while (environ[i])
        {
                memset (environ[i], 0, strlen(environ[i]));
                i++;
        }
        clearenv();

        for (i = 0; i < strlen(argv[0]); i++)
        {
                if (!isalnum (argv[0][i]) && strchr("-_/",argv[0][i]) == NULL)
                        return -2;
        }

        zerg (argv[1]);

        return 0;
}
