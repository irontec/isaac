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
 * @file util.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Wrappers for safety checks on common functions
 *
 * Handy functions for managing strings, dates and memory with some sanity
 * checks to avoid common segfaults.
 * Instead of segfaulting it will be nice to print some ERROR messages
 *
 */
#ifndef __ISAAC_UTIL_H_
#define __ISAAC_UTIL_H_

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>

/**
 * @brief Some macros for calculating the diffenrence between two timevals
 * @todo someday
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

/**
 * @brief String wrapper functions
 * Most of these functions are their original with some extra
 * sanity checks to avoid common segfaults.
 */

//! Wrapper for strcpy with sanity checks
int
isaac_strcpy(char *dst, const char *src);
//! Wrapper for strncpy with sanity checks
int
isaac_strncpy(char *dst, const char *src, int len);
//! Wrapper for strlen with sanity checks
int
isaac_strlen(const char *str);
//! Wrapper for strcmp with sanity checks
int
isaac_strcmp(const char *s1, const char *s2);
//! Wrapper for strcasecmp with sanity checks
int
isaac_strcasecmp(const char *s1, const char *s2);
//! Wrapper for strncmp with sanity checks
int
isaac_strncmp(const char *s1, const char *s2, int len);
//! Wrapper for strip with sanity checks
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
void
isaac_toupper(char *str);

#endif /* __ISAAC_UTIL_H_ */
