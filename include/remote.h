/*****************************************************************************
 ** Isaac -- Ivozng simplified Asterisk AMI Connector
 **
 ** Copyright (C) 2013 Irontec S.L.
 ** Copyright (C) 2013 Ivan Alonso (aka Kaian)
 **
 ** This program is free software: you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, either version 3 of the License, or
 ** (at your option) any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **
 *****************************************************************************/
/**
 * @file remote.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions declaration to manage client connection with Isaac CLI
 *
 * Most of this functions are copied or adapted from Asterisk or Astmanproxy
 * code (or at least the idea).
 *
 */
#ifndef __ISAAC_REMOTE_H_
#define __ISAAC_REMOTE_H_
#include <histedit.h>

//! End of client completion
#define AST_CLI_COMPLETE_EOF	"_EOF_"
#define MAX_HISTORY_COMMAND_LENGTH 256
#define EL_BUF_SIZE 512

struct remote_sig_flags
{
    unsigned int need_reload :1;
    unsigned int need_quit :1;
    unsigned int need_quit_handler :1;
};


/**
 * @brief Try to connect to CLI socket
 *
 * This function is used when isaac is invoked with -x parameter.
 * It will check if the unix socket for CLIs exists and can connnect to it
 *
 * @return 0 on connect success, 1 otherwise
 */
extern int
remote_tryconnect();

extern int
remote_display_match_list(char **matches, int len, int max);

extern char *
remote_complete(EditLine *editline, int ch);

extern int
remote_consolehandler(char *s);

extern void
remote_control(char* data);

extern char *
remote_prompt(EditLine *e);

extern void
remote_quit_handler(int num);

extern int
remote_el_initialize(void);

extern int
remote_el_read_char(EditLine *editline, char *cp);

extern char **
remote_el_strtoarr(char *buf);

extern int
remote_el_sort_compare(const void *i1, const void *i2);

extern int
remote_el_write_history(char *filename);

extern int
remote_el_read_history(char *filename);

#endif /* __ISAAC_REMOTE_H_ */
