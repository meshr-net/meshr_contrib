#include <glob.h>
#include <stdio.h>

int main( int argc, char **argv )
{
    glob_t  globbuf;

    glob( "*recipient", 0, NULL, &globbuf);

    if ( globbuf.gl_pathc == 0 )
        printf("there were no matching files\n");
    else
        printf("the first of the matching files is: %s\n", globbuf.gl_pathv[0]);

    globfree(&globbuf);

    return 0;
}