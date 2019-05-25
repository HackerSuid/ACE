#ifndef CODEC_H_
#define CODEC_H_ 1

#include <libelf.h>
#include <gelf.h>

typedef struct
{
    GElf_Shdr scn_hdr;
    Elf_Data *scn_data;
} elf_scn_info;

typedef struct
{
    elf_scn_info rel_plt, plt, got_plt;
    elf_scn_info dyn_sym, sym_tab, sh_strtab;
} elf_proc_data;

elf_proc_data *
codec_load_elf_binary (const char *path);

#endif

