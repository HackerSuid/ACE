/* require set/putenv() feature from 2001 edition of POSIX/IEEE standard */
#define _POSIX_C_SOURCE 200112L

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
/* open syscall */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
/* close syscall */
#include <unistd.h>
/* libelf headers */
#include <libelf.h>
#include <gelf.h>
#include <err.h>
#include <sysexits.h>

#include "codec.h"

/* from libhtmc */
#include "utils.h"

typedef struct
{
    GElf_Shdr scn_hdr;
    Elf_Data *scn_data;
} elf_scn_info;

typedef struct
{
    elf_scn_info rel_plt;
    elf_scn_info plt, got_plt;
    elf_scn_info dyn_sym, sym_tab, sh_strtab;
} elf_proc_data;

elf_proc_data *epd;
int32_t raw_fd;
Elf *elf_fd;
size_t strtab_ndx;

#define ADD_FCN(fcn_list, func_name, addr) \
    (fcn_list)->fcns[(++(fcn_list)->cnt)-1].name = (func_name); \
    (fcn_list)->fcns[(fcn_list)->cnt-1].base_addr = (addr)

int
obtain_dyn_func_addrs(elf_func_list *fcn_list);

int
codec_load_elf_binary(const char *path)
{
    GElf_Ehdr ehdr;
    GElf_Shdr shdr;
    Elf_Scn *scn = NULL;
    char *scn_name = NULL;
    size_t shnum, shstrndx;

    /* Internal version check for libelf. */
    if (elf_version(EV_CURRENT) == EV_NONE) {
        errx(
            EX_SOFTWARE,
            "libelf version check failed: %s",
            elf_errmsg(-1)
        );
        return 1;
    }
    /* Obtain an open file descriptor to the ELF binary file. */
    if ((raw_fd = open(path, O_RDWR, 0)) < 0) {
        err(EX_NOINPUT, "Failed to open %s", path);
        return 1;
    }
    /* Obtain ELF descriptor to use for reading & writing. */
    if ((elf_fd = elf_begin(raw_fd, ELF_C_RDWR, NULL)) == NULL) {
        errx(
            EX_SOFTWARE,
            "Failed to obtain ELF descriptor: %s\n",
            elf_errmsg(-1)
        );
        return 1;
    }
    /* Parse the ELF header. */
    if (gelf_getehdr(elf_fd, &ehdr) == NULL) {
        errx(
            EX_SOFTWARE,
            "Failed to obtain ELF header: %s",
            elf_errmsg(-1)
        );
        return 1;
    }
    /* Obtain the number of ELF sections. */
    if (elf_getshdrnum(elf_fd, &shnum) != 0) {
        errx(
            EX_SOFTWARE,
            "Failed to determine number of ELF sections: %s",
            elf_errmsg(-1)
        );
        return 1;
    }

    /* Obtain the section index of the string table for section names. */
    if (elf_getshdrstrndx(elf_fd, &shstrndx) != 0) {
        errx(
            EX_SOFTWARE,
            "Failed to locate the section header string table index: %s",
            elf_errmsg(-1)
        );
        return 1;
    }

    epd = (elf_proc_data *)calloc(sizeof(elf_proc_data), 1);
    if (!epd) {
        ERR("Failed to allocate memory for ELF data.");
        return 1;
    }

    /* Search for sections relevant to procedures. */
    while ((scn = elf_nextscn(elf_fd, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            errx(
                EX_SOFTWARE,
                "Failed to get section table header: %s",
                elf_errmsg(-1)
            );
            return 1;
        }
        if ((scn_name = elf_strptr(elf_fd, shstrndx, shdr.sh_name)) == NULL) {
            errx(
                EX_SOFTWARE,
                "Failed to lookup section name: %s",
                elf_errmsg(-1)
            );
            return 1;
        }
        if (shdr.sh_type == SHT_REL || shdr.sh_type == SHT_RELA) {
            epd->rel_plt.scn_data = elf_getdata(scn, NULL);
            memcpy(
                &epd->rel_plt.scn_hdr,
                &shdr, sizeof(GElf_Shdr));
        }
        if (shdr.sh_type == SHT_PROGBITS &&
            !strcmp(".plt", scn_name)) {
            epd->plt.scn_data = elf_getdata(scn, NULL);
            memcpy(
                &epd->plt.scn_hdr,
                &shdr, sizeof(GElf_Shdr));
        }
        if (!strcmp(".got.plt", scn_name)) {
            epd->got_plt.scn_data = elf_getdata(scn, NULL);
            memcpy(
                &epd->got_plt.scn_hdr,
                &shdr, sizeof(GElf_Shdr));
        }
        if (shdr.sh_type == SHT_DYNSYM) {
            epd->dyn_sym.scn_data = elf_getdata(scn, NULL);
            memcpy(
                &epd->dyn_sym.scn_hdr,
                &shdr, sizeof(GElf_Shdr));
        }
        if (shdr.sh_type == SHT_SYMTAB) {
            epd->sym_tab.scn_data = elf_getdata(scn, NULL);
            memcpy(
                &epd->sym_tab.scn_hdr,
                &shdr, sizeof(GElf_Shdr));
        }
        if (shdr.sh_type == SHT_STRTAB &&
            !strcmp(".strtab", scn_name)) {
            epd->sh_strtab.scn_data = elf_getdata(scn, NULL);
            memcpy(
                &epd->sh_strtab.scn_hdr,
                &shdr, sizeof(GElf_Shdr));
            strtab_ndx = elf_ndxscn(scn);
        }
    }
    return 0;
}

elf_func_list *
codec_get_elf_fcn_addrs(void)
{
    GElf_Sym sym;
    char *func_name = NULL;
    uint32_t i;

    uint32_t num_dyn_syms =
        (uint32_t)(epd->dyn_sym.scn_hdr.sh_size /
        epd->dyn_sym.scn_hdr.sh_entsize);
    uint32_t num_nondyn_syms =
        (uint32_t)(epd->sym_tab.scn_hdr.sh_size /
        epd->sym_tab.scn_hdr.sh_entsize);

    elf_func_list *fcn_list = (elf_func_list *)calloc(
        sizeof(elf_func_list), 1);
    fcn_list->fcns = (elf_func *)calloc(
        sizeof(elf_func), num_dyn_syms+num_nondyn_syms);

    DEBUG("%u local symbols:\n", num_nondyn_syms);
    for (i=0; i<num_nondyn_syms; i++) {
        gelf_getsym(epd->sym_tab.scn_data, i, &sym);
        if (GELF_ST_TYPE(sym.st_info)==STT_FUNC && sym.st_size>0) {
            ADD_FCN(fcn_list,
                elf_strptr(elf_fd, strtab_ndx, sym.st_name),
                sym.st_value);
            DEBUG("%u: %s\n",
                fcn_list->cnt-1,
                fcn_list->fcns[fcn_list->cnt-1].name);
        }
    }
    DEBUG("%u dynamic symbols:\n", num_dyn_syms);
    for (i=0; i<num_dyn_syms; i++) {
        gelf_getsym(epd->dyn_sym.scn_data, i, &sym);
        if (GELF_ST_TYPE(sym.st_info)==STT_FUNC) {
            ADD_FCN(fcn_list,
                elf_strptr(
                    elf_fd,
                    epd->dyn_sym.scn_hdr.sh_link,
                    sym.st_name),
                sym.st_value);
            DEBUG("%u: %s\n",
                fcn_list->cnt-1,
                fcn_list->fcns[fcn_list->cnt-1].name);
        }
    }

    if (obtain_dyn_func_addrs(fcn_list)) {
        ERR("Failed to obtain dynamic function addresses.\n");
        return NULL;
    }

    return fcn_list;
}

/* relocation entry with or without an addend */
union reloc_entry_type
{
    GElf_Rel rel_entry;
    GElf_Rela rela_entry;
};

/* calculate the virtual memory addresses of dynamic functions
by having the dynamic linker process their relocation entries,
and updating their global offset table entries. */
int
obtain_dyn_func_addrs(elf_func_list *fcn_list)
{
    union reloc_entry_type rel_type;
    /* holds r_info & offsetof rel or rela entries */
    GElf_Rel rel;
    uint32_t i;
    uint32_t num_relocs =
        (uint32_t)(epd->rel_plt.scn_hdr.sh_size / 
        epd->rel_plt.scn_hdr.sh_entsize);

    DEBUG("%u relocation entries.\n", num_relocs);
    for (i=0; i<num_relocs; i++) {
        if (epd->rel_plt.scn_hdr.sh_type == SHT_REL) {
            gelf_getrel(
                epd->rel_plt.scn_data,
                i, &rel_type.rel_entry);
            rel.r_info = rel_type.rel_entry.r_info;
            rel.r_offset = rel_type.rel_entry.r_offset;
        } else {
            gelf_getrela(
                epd->rel_plt.scn_data,
                i, &rel_type.rela_entry);
            rel.r_info = rel_type.rela_entry.r_info;
            rel.r_offset = rel_type.rela_entry.r_offset;
        }

        if (GELF_R_TYPE(rel.r_info)==R_X86_64_JUMP_SLOT ||
            GELF_R_TYPE(rel.r_info)==R_386_JMP_SLOT) {
            DEBUG("0x%08lx\n", rel.r_offset);
        }
    }

    /* in order to make it easier to obtain dynamically linked
    function machine code, tell the dynamic linker to resolve
     GOT entries for PLT functions during initialization. */
    setenv("LD_BIND_NOW", "1", 1);

    return 0;
}

void
codec_cleanup(void)
{
    elf_end(elf_fd);
    close(raw_fd);
}

