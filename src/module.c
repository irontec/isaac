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
 * \file module.c
 * \author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 * \brief Source code for funtions defined in module.h
 *
 */

#include <dirent.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "log.h"
#include "module.h"

//! modules list
struct isaac_module *modules = NULL;

/*****************************************************************************/
int
load_modules()
{
    DIR *moddir;
    struct dirent *l;
    char *ext; /* File extension (incling dot) */
    char lfullfile[256];
    struct isaac_module *module;
	int modcnt = 0;

    isaac_log(LOG_VERBOSE, "Loading modules ...\n");

    /* Open modules directory */
    if (!(moddir = opendir(MODDIR))){
		isaac_log(LOG_ERROR, "Unable to open modules dir: %s\n", MODDIR);
        return 1;
	}

    while ((l = readdir(moddir))) {
        /* Ignore directories */
        if (l->d_type == DT_DIR)
            continue;

        /* Get file extension */
        if (!(ext = strchr(l->d_name, '.')))
            continue;

        /* Must end in .so to load it.  */
        if (strcasecmp(ext, ".so"))
            continue;

        /* Create full module file path */
        sprintf(lfullfile, "%s/%s", MODDIR, l->d_name);

        /* Create a new module */
        if (!(module = module_create(lfullfile))) {
            isaac_log(LOG_ERROR, "Failed to create module from %s\n", l->d_name);
            module_destroy(module);
            continue;
        }
        /* Open module module */
        if (!(module->dlhandle = dlopen(lfullfile,  RTLD_NOW | RTLD_LOCAL))) {
            isaac_log(LOG_ERROR, "Error opening %s\n", dlerror());
            module_destroy(module);
            continue;
        }

		/* Some logging */
		isaac_log(LOG_VERBOSE_2, "Loading module %s\n", l->d_name);

        /* Load basic module functions */
        module->load = dlsym(module->dlhandle, "load_module");
        module->unload = dlsym(module->dlhandle, "unload_module");

        /* Check module has basic capabilitys */
        if (module->load && module->unload) {
            /* Load the module! */
            if (module->load() == 0 ){
				// Increase module loaded count
				modcnt++;
			} else {
				// Wah! Failed to load :S
				isaac_log(LOG_WARNING, "Failed to fully load %s\n", l->d_name);
 			}
        } else {
            /* Give some bad output */
        	isaac_log(LOG_ERROR, "Module %s has no moding capabilities!\n", l->d_name);
            /* And remove this module */
            module_destroy(module);
        }
    }

    /* Close module directory */
    closedir(moddir);

    if (!modules) {
        isaac_log(LOG_ERROR, "Unable to load *ANY* module from %s!\n", MODDIR);
        return 1;
    }
    isaac_log(LOG_VERBOSE, "%d modules loaded.\n", modcnt);
    return 0;
}

/*****************************************************************************/
struct isaac_module*
module_create(const char* file)
{
    struct isaac_module *module;

    /* Allocate memory for this module */
    module = malloc(sizeof(struct isaac_module));
    memset(module, 0, sizeof(struct isaac_module));
    strcpy(module->file, file);

    /* Add to the modules list */
    module->next = modules;
    modules = module;

    return module;
}

/*****************************************************************************/
void
module_destroy(struct isaac_module *module)
{
    /* At least we have a module */
    if (!module)
        return;

    /* TODO Remove from the module list */

    /* Unload the module if it's able  */
    if (module->unload)
        module->unload();

    /* If we have an open handler, close it */
    if (module->dlhandle) {
        dlclose(module->dlhandle);
    }

    /* Finaly free module structure */
    free(module);

}

/*****************************************************************************/
struct isaac_module*
module_by_name(const char* name)
{
    struct isaac_module *module = modules;

    while (module) {
        if (!strcasecmp(module->name, name))
            return module;
        module = module->next;
    }
    return NULL;

}

