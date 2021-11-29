#include "utility.h"
#include "string.h"
#include <ctype.h>
#include "constants.h"
#include <stdio.h>
#include <stdlib.h>

int getPercentageInt(float percentage,int num)
{
    int x = (int)((num*percentage)/100);
    return x;
}

char * print_centre(char *str, int len)
{
    char tmp[MAX_BUFFER_SIZE];
    char tmp_format[MAX_BUFFER_SIZE];
    sprintf(tmp_format,"%%-.%ds",len);

    sprintf(tmp,tmp_format,str);
    int padlen = (len - strlen(tmp)) / 2 ;
    char * tmp2=(char *)calloc(MAX_BUFFER_SIZE,sizeof(tmp2));
    sprintf(tmp2,"%*s%s%*s", padlen, "", tmp, padlen, "");
    return tmp2;
}

char *trim(char *str)
{
    size_t len = 0;
    char *frontp = str;
    char *endp = NULL;

    if( str == NULL ) { return NULL; }
    if( str[0] == '\0' ) { return str; }

    len = strlen(str);
    endp = str + len;

    /* Move the front and back pointers to address the first non-whitespace
     * characters from each end.
     */
    while( isspace((unsigned char) *frontp) ) { ++frontp; }
    if( endp != frontp )
    {
        while( isspace((unsigned char) *(--endp)) && endp != frontp ) {}
    }

    if( frontp != str && endp == frontp )
            *str = '\0';
    else if( str + len - 1 != endp )
            *(endp + 1) = '\0';

    /* Shift the string so that it starts at str so that if it's dynamically
     * allocated, we can still free it on the returned pointer.  Note the reuse
     * of endp to mean the front of the string buffer now.
     */
    endp = str;
    if( frontp != str )
    {
            while( *frontp ) { *endp++ = *frontp++; }
            *endp = '\0';
    }

    return str;
}