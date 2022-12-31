#ifndef __command_h
#define __command_h

#include <string.h>
#include <stdbool.h>

typedef struct command_t {
    const char *name;
    int (*command)(int argc, char **argv);
} command_t;

int command_dispatch(command_t *commands, const char *command, bool partial_match, int argc, char **argv);

#endif
