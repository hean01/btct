#include <stdlib.h>
#include "command.h"
#include <stdio.h>
int
command_dispatch(command_t *commands, const char *command, bool partial_match, int argc, char **argv)
{
    command_t *cmd = commands;
    while (cmd && cmd->name != NULL)
    {
        if ((!partial_match && strcmp(command, cmd->name) !=0)
            || (partial_match && strncmp(command, cmd->name, strlen(cmd->name)) != 0))
        {
            cmd++;
            continue;
        }
        return cmd->command(argc, argv);
    }

    return -1;
}
