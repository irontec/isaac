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

#ifndef REMOTE_H_
#define REMOTE_H_
#include <histedit.h>

#define AST_CLI_COMPLETE_EOF	"_EOF_"

int
cli_tryconnect();
void
cli_remotecontrol(char *exec);
char *
prompt(EditLine *e);
char **
isaac_el_strtoarr(char *buf);
void
__remote_quit_handler(int num);
int
isaac_el_sort_compare(const void *i1, const void *i2);

#endif /* REMOTE_H_ */
