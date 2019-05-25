AC_INIT([ace], [1.0], [hackersuid@gmail.com])
# subdir-objects must be enabled
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_MACRO_DIRS([m4])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_CC
LT_INIT
PKG_CHECK_MODULES([CHECK], [check])
AC_SEARCH_LIBS(
    [elf_version, elf_begin, elf_kind],
    [elf], [], [
        AC_MSG_ERROR(
            [Could not find libelf library!])
    ]
)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
    Makefile
    src/Makefile
])
AC_OUTPUT

