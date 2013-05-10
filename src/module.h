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
 * \file module.h
 * \author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 * \brief Manages loadable modules of Isaac
 * 
 * Actually loadable modules can only register applications. But hey, it's an
 * open door.
 *
 */
#ifndef __ISAAC_MODULE_H_
#define __ISAAC_MODULE_H_
#include <dirent.h>
#include <dlfcn.h>

//! Sorter declaration of struct isaac_module
typedef struct isaac_module isaac_module_t;

/**
 * \brief This structure contains of related information to one Isaac module
 * 
 * A modules is a loadable file that can contain resources and code that can
 * be used in the simplified protocol
 *
 */
struct isaac_module
{
    //! Filename of the module
    char *fname;
    //! Module load entry point
    int
    (*load)();
    //! Module unload entry point
    int
    (*unload)();
    //! Dynamic handler for this module file
    void *dlhandle;

    //! Next module in the list
    isaac_module_t *next;
};

/**
 * \brief Load all available modules found in MODDIR
 *
 * This function works in autoload mode, so don't use the directory for other dynamic linked
 * files.
 *
 * \retval 0 If any module has been loaded
 * \retval -1 If no module has been loaded
 */
extern int
load_modules();

/**
 * \brief Unload all previously loaded files
 *
 * Destroy all loaded modules (which in fact will invoke the unload function of each one)
 * using \ref module_destroy.
 * This is done on Isaac shutdown.
 *
 * \retval 0 In all cases
 */
extern int
unload_modules();

/**
 * \brief Create basic structure info of a module and add to modules lists.
 *
 * Allocates the necessary memory for the module and add it to the
 * modules list.
 *
 * \return A new allocated module structure
 */
extern isaac_module_t*
module_create(const char* file);

/**
 * \brief Requests module unload and free its memory
 *
 * - This function will request the module to unload itself (and free any
 * custom data it has used)
 * - Free the Dynamic function handler
 * - Free module memory
 *
 */
extern void
module_destroy(isaac_module_t* module);


#endif         /* __ISAAC_MODULE_H_ */
