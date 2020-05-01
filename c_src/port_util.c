#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "port_util.h"

int decode_string(char *buf, int *index, char **str)
{
    int type;
    int len;

    *str = NULL;

    if (ei_get_type(buf, index, &type, &len)) return 5;

    *str = malloc(len + 1);

    if (ei_decode_string(buf, index, *str)) return 8;
    (*str)[len] = '\0';

    return 0;
}

/*-----------------------------------------------------------------
 * Data marshalling functions
 *----------------------------------------------------------------*/
int read_cmd(byte **buf, int *size)
{
    int len;

    if (read_exact(*buf, 2) != 2)
        return -1;
    len = ((unsigned char)(*buf)[0] << 8) | (unsigned char)(*buf)[1];

    if (len > *size) {
        byte *tmp = (byte *) realloc(*buf, len);
        if (tmp == NULL)
            return -1;
        else
            *buf = tmp;
        *size = len;
    }

    return read_exact(*buf, len);
}

int write_cmd(ei_x_buff *buff)
{
    byte li;

    li = (buff->index >> 8) & 0xff;
    write_exact(&li, 1);
    li = buff->index & 0xff;
    write_exact(&li, 1);

    return write_exact(buff->buff, buff->index);
}

int read_exact(byte *buf, int len)
{
    int i, got=0;

    do {
        if ((i = read(0, buf+got, len-got)) <= 0) {
            return i;
        }
        got += i;
    } while (got<len);

    return len;
}

int write_exact(byte *buf, int len)
{
    int i, wrote = 0;

    do {
        if ((i = write(1, buf+wrote, len-wrote)) <= 0)
            return i;
        wrote += i;
    } while (wrote<len);

    return len;
}
