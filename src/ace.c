#include <stdio.h>

#include "htm.h"
#include "codec.h"

int
main (int argc, char **argv)
{
    elf_proc_data *epd = NULL;

    epd = codec_load_elf_binary("/bin/ls");

    return 0;
}

