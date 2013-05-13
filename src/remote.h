/****************************************************************************
 **
 ** Copyright (C) 2011 Irontec SL. All rights reserved.
 **
 ** This file may be used under the terms of the GNU General Public
 ** License version 3.0 as published by the Free Software Foundation
 ** and appearing in the file LICENSE.GPL included in the packaging of
 ** this file.  Please review the following information to ensure GNU
 ** General Public Licensing requirements will be met:
 **
 ** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
 ** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 **
 ****************************************************************************/

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
