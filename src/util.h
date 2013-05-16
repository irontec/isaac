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
#ifndef UTIL_H_
#define UTIL_H_

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

/**
 * @brief Some macros for calculating the diffenrence between two timevals
 * @fixme someday
 */
#define SECOND (1)
#define MINUTE (SECOND*60)
#define HOUR (MINUTE*60)
#define DAY (HOUR*24)
#define WEEK (DAY*7)
#define YEAR (DAY*365)
//! define if we need a comma
#define NEEDCOMMA(x) ((x)? ",": "")
//! define if we need final s in descriptors
#define ESS(x) ((x>1)? "s": "")

/*! \brief Wrapper for string functions */
int
isaac_strcpy(char *dst, const char *src);
int
isaac_strncpy(char *dst, const char *src, int len);
int
isaac_strlen(const char *str);
int
isaac_strcmp(const char *s1, const char *s2);
int
isaac_strncmp(const char *s1, const char *s2, int len);
char *
isaac_strip(char *s);
char *
isaac_skip_blanks(const char *str);
char *
isaac_skip_nonblanks(const char *str);
int
isaac_strlen_zero(const char *s);
void
isaac_join(char *s, size_t len, const char * const w[]);

/*! \brief Wrapper for free */
void
isaac_free(void *mem);

/*! \brief Wrappers for time functions */
struct timeval
isaac_tvnow(void);
struct timeval
isaac_tvadd(struct timeval a, struct timeval b);
struct timeval
isaac_tvsub(struct timeval a, struct timeval b);
void
isaac_tvelap(struct timeval timeval, int printsec, char *out);


/// \endcond INCLUDE_UTILS

#endif /* UTIL_H_ */
