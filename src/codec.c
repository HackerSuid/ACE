#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
/* open syscall */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
/* libelf headers */
#include <libelf.h>
#include <gelf.h>
#include <err.h>
#include <sysexits.h>

#include "codec.h"

/* from libhtmc */
#include "utils.h"

elf_proc_data *
codec_load_elf_binary(const char *path)
{
    elf_proc_data *epd = NULL;
    int32_t raw_fd;
    Elf *elf_fd = NULL;
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
        return NULL;
    }
    /* Obtain an open file descriptor to the ELF binary file. */
    if ((raw_fd = open(path, O_RDWR, 0)) < 0) {
        err(EX_NOINPUT, "Failed to open %s", path);
        return NULL;
    }
    /* Obtain ELF descriptor to use for reading & writing. */
    if ((elf_fd = elf_begin(raw_fd, ELF_C_RDWR, NULL)) == NULL) {
        errx(
            EX_SOFTWARE,
            "Failed to obtain ELF descriptor: %s\n",
            elf_errmsg(-1)
        );
        return NULL;
    }
    /* Parse the ELF header. */
    if (gelf_getehdr(elf_fd, &ehdr) == NULL) {
        errx(
            EX_SOFTWARE,
            "Failed to obtain ELF header: %s",
            elf_errmsg(-1)
        );
        return NULL;
    }
    /* Obtain the number of ELF sections. */
    if (elf_getshdrnum(elf_fd, &shnum) != 0) {
        errx(
            EX_SOFTWARE,
            "Failed to determine number of ELF sections: %s",
            elf_errmsg(-1)
        );
        return NULL;
    }

    /* Obtain the section index of the string table for section names. */
    if (elf_getshdrstrndx(elf_fd, &shstrndx) != 0) {
        errx(
            EX_SOFTWARE,
            "Failed to locate the section header string table index: %s",
            elf_errmsg(-1)
        );
        return NULL;
    }

    epd = (elf_proc_data *)calloc(sizeof(elf_proc_data), 1);
    if (!epd) {
        ERR("Failed to allocate memory for ELF data.");
        return NULL;
    }

    /* Search for sections relevant to procedures. */
    while ((scn = elf_nextscn(elf_fd, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            errx(
                EX_SOFTWARE,
                "Failed to get section table header: %s",
                elf_errmsg(-1)
            );
            return NULL;
        }
        if ((scn_name = elf_strptr(elf_fd, shstrndx, shdr.sh_name)) == NULL) {
            errx(
                EX_SOFTWARE,
                "Failed to lookup section name: %s",
                elf_errmsg(-1)
            );
            return NULL;
        }
        if (shdr.sh_type == SHT_REL &&
            !strcmp(".rel.plt", scn_name)) {
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
            !strcmp(".shstrtab", scn_name)) {
            epd->sh_strtab.scn_data = elf_getdata(scn, NULL);
            memcpy(
                &epd->sh_strtab.scn_hdr,
                &shdr, sizeof(GElf_Shdr));
        }
    }

    return epd;
}

