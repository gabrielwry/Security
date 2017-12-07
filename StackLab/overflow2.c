
/* Property of USER */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>


void lolcat(char *meow, char *arg, char *woof)
{
        char buf[185];
        int i;

        if (strlen(meow) > 16)
        {
                printf ("Argument 1 iz too long!\n");
                return;
        }

        for (i = 0; i < strlen(arg); i++)
        {
                if (!isalnum (arg[i]))
                {
                        printf ("Argument 2 iz tainted!\n");
                        return;
                }
        }
        if (strlen(woof) > 16)
        {
                printf ("Argument 3 iz too long!\n");
                return;
        }

        sprintf (buf, "HAI HACKER. U SAYS %s%s%s", meow, arg, woof);
        printf ("U WRAITES %d BAITES\n", (int)strlen(buf));

        return;
}


extern char **environ;

int main(int argc, char **argv)
{
        int i = 0;
        if (argc != 4)
        {
                printf ("I can haz three arguments?\n");
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

        lolcat (argv[1], argv[2], argv[3]);

        printf ("KTHXBYE.\n");

        return 0;

}
