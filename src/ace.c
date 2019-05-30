#include <stdio.h>

#include "htm.h"
#include "utils.h"
#include "codec.h"

int
main (int argc, char **argv)
{
    char *path = NULL;
    elf_func_list *fcn_list = NULL;

    if (argc < 2) {
        ERR("User didn't provide path to ELF binary.\n");
        return 1;
    }

    path = argv[1];
    
    if (codec_load_elf_binary((const char *)path)) {
        ERR("Codec failed to load %s\n", path);
        return 1;
    }

    fcn_list = codec_get_elf_fcn_addrs();
    printf("%u fcns\n", fcn_list->cnt);
    uint32_t i;
    for (i=0; i<fcn_list->cnt; i++) {
        printf("%u: %s 0x%08x\n", i, fcn_list->fcns[i].name, fcn_list->fcns[i].base_addr);
    }

    codec_cleanup();

    return 0;
}

