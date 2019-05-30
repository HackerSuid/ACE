#ifndef CODEC_H_
#define CODEC_H_ 1

#include <libelf.h>
#include <gelf.h>

int
codec_load_elf_binary (const char *path);

typedef struct
{
    const char *name;
    uint32_t base_addr;
} elf_func;

typedef struct
{
    uint32_t cnt;
    elf_func *fcns;
} elf_func_list;

elf_func_list *
codec_get_elf_fcn_addrs (void);

void
codec_cleanup (void);

#endif

