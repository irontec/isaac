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
 * @file res_lua.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Resource module that allow Lua modules to be loaded
 *
 * This module has all required logic to make possible to load LUA modules
 * into Isaac. Maybe someday this logic will be included in the core module
 * load logic.
 *
 */
#include "config.h"
#include <lua.h>
#include <lualib.h>
#include <dirent.h>
#include <lauxlib.h>
#include "log.h"
#include "app.h"
#include "util.h"
#include "session.h"
#include "filter.h"

typedef struct lua_module lua_module_t;
typedef struct lua_application lua_app_t;
typedef struct lua_filter lua_filter_t;

struct lua_module
{
    //! Filename of the module
    char *fname;
    //! Lua state for this module
    lua_State *lua;
    //! Next module in the list
    lua_module_t *next;
};

struct lua_application
{
    //! Lua Application name
    char name[20];
    //! Lua Application callback
    char callback[30];
    //! Lua module that contains this app
    lua_module_t *module;
    //! Nex application in the list
    lua_app_t *next;
};

struct lua_filter
{
    //! Session pointer who requested this filter
    session_t *sess;
    //! Lua Application callback
    char callback[30];
    //! Lua userpointer data
    void *lua_userpointer;
    //! Lua module that contains this app
    lua_module_t *module;
    //! Nex application in the list
    lua_app_t *next;
};

lua_module_t *lua_modules;
lua_app_t *lua_apps;
lua_filter_t *lua_filters;

int
lua_application_callback(session_t *sess, app_t *app, const char *args)
{
    lua_app_t *lua_app = lua_apps;
    // Find the lua application
    while (lua_app) {
        if (!(strcasecmp(lua_app->name, app->name))) break;
        lua_app = lua_app->next;
    }

    // If no application found, exit with error
    if (!lua_app) {
        return 1;
    }

    // Get the load_module function inside the script
    lua_getglobal(lua_app->module->lua, lua_app->callback);

    // Push callback values
    lua_pushstring(lua_app->module->lua, sess->id);
    lua_pushstring(lua_app->module->lua, app->name);
    lua_pushstring(lua_app->module->lua, args);

    // And run it
    if (lua_pcall(lua_app->module->lua, 3, 1, 0)) {
        isaac_log(LOG_ERROR, "lua_callback: %s() failed: %s\n", lua_app->callback, lua_tostring(
                lua_app->module->lua, -1));
    }

    // Get the return value
    return lua_tonumber(lua_app->module->lua, 1);
}

int
lua_filter_callback(filter_t *filter, ami_message_t *msg)
{
    char fullheader[MAX_LEN], header[MAX_LEN], value[MAX_LEN];
    int i;

    lua_filter_t *lua_filter = (lua_filter_t *) filter_get_userdata(filter);
    isaac_log(LOG_DEBUG, "Executing LUA callback [%s]\n", lua_filter->callback);

    // Get the load_module function inside the script
    lua_getglobal(lua_filter->module->lua, lua_filter->callback);

    // Push callback values
    lua_pushlightuserdata(lua_filter->module->lua, filter);

    // Push the message like a LUA table
    lua_newtable(lua_filter->module->lua);
    for (i = 0; i < msg->hdrcount; i++) {
        // Copy the header to a temp var
        isaac_strcpy(fullheader, msg->headers[i]);
        sscanf(fullheader, "%[^:]: %[^\r\n]", header, value);
        // Push this as key and value of msg table
        lua_pushstring(lua_filter->module->lua, header);
        lua_pushstring(lua_filter->module->lua, value);
        lua_settable(lua_filter->module->lua, -3);
    }

    // And run it
    if (lua_pcall(lua_filter->module->lua, 2, 0, 0)) {
        isaac_log(LOG_ERROR, "lua_callback: %s() failed: %s\n", lua_filter->callback, lua_tostring(
                lua_filter->module->lua, -1));
    }

    // Get the return value
    //return lua_tonumber(lua_app->module->lua, 1);

    return 0;
}

/* Declaration of exposed functions */
int
lua_application_register(lua_State *L)
{
    const char* appname = lua_tostring(L, 1);
    const char* appcallback = lua_tostring(L, 2);

    // Create a LUA application strctucture
    lua_app_t *app = malloc(sizeof(lua_app_t));
    // Copy basic application values
    isaac_strcpy(app->name, appname);
    isaac_strcpy(app->callback, appcallback);

    // Get the application module
    lua_getglobal(L, "__MODULE");
    app->module = (lua_module_t*) lua_touserdata(L, -1);

    // Add to the application list
    app->next = lua_apps;
    lua_apps = app;

    application_register(app->name, lua_application_callback);

    return 0;
}
int
lua_application_unregister(lua_State *L)
{
    return 0;
}

int
lua_session_write(lua_State *L)
{
    const char *sessid = lua_tostring(L, 1);
    const char *msg = lua_tostring(L, 2);

    session_t *sess = session_by_id(sessid);
    if (sess) {
        return session_write(sess, msg);
    } else {
        isaac_log(LOG_WARNING, "[Session %s] Write request on not found session.\n", sessid);
        return 1;
    }
}

int
lua_filter_create(lua_State *L)
{
    const char *sessid = lua_tostring(L, 1);
    int filter_type = lua_tonumber(L, 2);
    const char *callback = lua_tostring(L, 3);

    session_t *sess = session_by_id(sessid);
    if (sess) {
        // Create a LUA filter strctucture
        lua_filter_t *info = malloc(sizeof(lua_filter_t));

        // Copy basic application values
        isaac_strcpy(info->callback, callback);
        info->sess = sess;
        lua_getglobal(L, "__MODULE");
        info->module = (lua_module_t*) lua_touserdata(L, -1);

        isaac_log(LOG_DEBUG, "Creating new filter for LUA module [%s]\n", callback);

        filter_t *filter = filter_create(sess, filter_type, lua_filter_callback);
        filter_set_userdata(filter, info);

        lua_pushlightuserdata(L, filter);
        return 1;
    }
    return 0;
}

int
lua_filter_register(lua_State *L)
{
    filter_t *filter = lua_touserdata(L, 1);
    if (filter) {
        filter_register(filter);
    }
    return 0;
}

int
lua_filter_register_oneshot(lua_State *L)
{
    filter_t *filter = lua_touserdata(L, 1);
    if (filter) {
        filter_register_oneshot(filter);
    }
    return 0;
}

int
lua_filter_unregister(lua_State *L)
{
    filter_t *filter = lua_touserdata(L, 1);
    if (filter) {
        filter_unregister(filter);
    }
    return 0;
}

int
lua_filter_new_condition(lua_State *L)
{
    filter_t *filter = lua_touserdata(L, 1);
    int cond_type = lua_tonumber(L, 2);
    const char *header = lua_tostring(L, 3);
    const char *value = lua_tostring(L, 4);

    filter_new_condition(filter, cond_type, header, value);
    return 0;

}

int
lua_filter_set_userdata(lua_State *L)
{
    return 0;
}

int
lua_filter_get_userdata(lua_State *L)
{
    return 0;
}

int
lua_isaac_log(lua_State *L)
{
    int loglevel = lua_tonumber(L, 1);
    const char* msg = lua_tostring(L, 2);

    // Get backtrace information
    lua_Debug ar;
    lua_getstack(L, 1, &ar);
    lua_getinfo(L, "nSl", &ar);
    const char* file = basename(ar.short_src);
    int line = ar.currentline;
    const char* func = "receive";
    if (ar.name) func = ar.name;

    // Log with the lua code position
    isaac_log_location(loglevel, file, line, func, "%s", msg);

    return 0;
}

lua_module_t *
lua_module_create(const char *file)
{

    lua_module_t *module;

    if (!(module = malloc(sizeof(lua_module_t)))) {
        isaac_log(LOG_ERROR, "Unable to allocate memory for LUA module %s\n", file);
        return NULL;
    }

    // Initialize its memory
    memset(module, 0, sizeof(lua_module_t));
    // Create Lua interpreter
    module->lua = lua_open();
    // load Lua base libraries
    luaL_openlibs(module->lua);

    // Register satelite functions
    lua_register(module->lua, "application_register", lua_application_register);
    lua_register(module->lua, "application_unregister", lua_application_unregister);
    lua_register(module->lua, "session_write", lua_session_write);
    lua_register(module->lua, "filter_create", lua_filter_create);
    lua_register(module->lua, "filter_register", lua_filter_register);
    lua_register(module->lua, "filter_register_oneshot", lua_filter_register_oneshot);
    lua_register(module->lua, "filter_unregister", lua_filter_unregister);
    lua_register(module->lua, "filter_new_condition", lua_filter_new_condition);
    lua_register(module->lua, "filter_set_userdata", lua_filter_set_userdata);
    lua_register(module->lua, "filter_get_userdata", lua_filter_get_userdata);
    lua_register(module->lua, "isaac_log", lua_isaac_log);

    // Load LOG Levels
    lua_pushnumber(module->lua, LOG_DEBUG);
    lua_setglobal(module->lua, "LOG_DEBUG");
    lua_pushnumber(module->lua, LOG_NOTICE);
    lua_setglobal(module->lua, "LOG_NOTICE");
    lua_pushnumber(module->lua, LOG_WARNING);
    lua_setglobal(module->lua, "LOG_WARNING");
    lua_pushnumber(module->lua, LOG_ERROR);
    lua_setglobal(module->lua, "LOG_ERROR");
    lua_pushnumber(module->lua, LOG_CRITICAL);
    lua_setglobal(module->lua, "LOG_CRITICAL");

    // Load Filter Callback Types
    lua_pushnumber(module->lua, FILTER_ASYNC_CALLBACK);
    lua_setglobal(module->lua, "FILTER_ASYNC_CALLBACK");
    lua_pushnumber(module->lua, FILTER_SYNC_CALLBACK);
    lua_setglobal(module->lua, "FILTER_SYNC_CALLBACK");

    // Load Condition types
    lua_pushnumber(module->lua, MATCH_EXACT);
    lua_setglobal(module->lua, "MATCH_EXACT");
    lua_pushnumber(module->lua, MATCH_EXACT_CASE);
    lua_setglobal(module->lua, "MATCH_EXACT_CASE");
    lua_pushnumber(module->lua, MATCH_START_WITH);
    lua_setglobal(module->lua, "MATCH_START_WITH");
    lua_pushnumber(module->lua, MATCH_REGEX);
    lua_setglobal(module->lua, "MATCH_REGEX");
    lua_pushnumber(module->lua, MATCH_REGEX_NOT);
    lua_setglobal(module->lua, "MATCH_REGEX_NOT");

    // Load but don't run the Lua script
    if (luaL_loadfile(module->lua, file)) {
        isaac_log(LOG_ERROR, "luaL_loadfile() failed: %s\n", lua_tostring(module->lua, -1));
        return NULL;
    }

    // Priming run. Syntax checking for the script
    if (lua_pcall(module->lua, 0, 0, 0)) {
        isaac_log(LOG_ERROR, "lua_pcall() failed: %s\n", lua_tostring(module->lua, -1));
        return NULL;
    }

    // Add the new module to modules list
    module->next = lua_modules;
    lua_modules = module;

    // Return the allocated module
    return module;
}

int
lua_module_destroy(lua_module_t *module)
{
    return 0;
}

int
load_lua_modules()
{
    DIR *luadir;
    struct dirent *l;
    char *ext; // File extension (incling dot)
    char lfullfile[256];
    lua_module_t *module;
    int modulecnt = 0;

    isaac_log(LOG_VERBOSE_3, "Loading LUA modules ...\n");

    // Open launchers directory
    if (!(luadir = opendir(MODDIR))) return 1;

    while ((l = readdir(luadir))) {
        // Ignore directories
        if (l->d_type == DT_DIR) continue;
        // Get file extension
        if (!(ext = strchr(l->d_name, '.'))) continue;
        // Must end in .lua to load it.
        if (strcasecmp(ext, ".lua")) continue;

        // Create full launcher file path
        sprintf(lfullfile, "%s/%s", MODDIR, l->d_name);

        // Create a new launcher
        if (!(module = lua_module_create(lfullfile))) {
            isaac_log(LOG_ERROR, "Failed to create LUA module from %s\n", l->d_name);
            lua_module_destroy(module);
            continue;
        }

        // Store in LUA the module pointer of this file
        lua_pushlightuserdata(module->lua, (void*) module);
        lua_setglobal(module->lua, "__MODULE");

        // Get the load_module function inside the script
        lua_getglobal(module->lua, "load_module");
        // And run it
        if (lua_pcall(module->lua, 0, 0, 0)) {
            isaac_log(LOG_ERROR, "load_module() failed\n"); /* Error out if Lua file has an error */
        }

        modulecnt++;
    }

    // Close modules dir
    closedir(luadir);

    if (!lua_modules) {
        isaac_log(LOG_ERROR, "Unable to load *ANY* LUA modules from %s!\n", MODDIR);
        return 1;
    }
    isaac_log(LOG_VERBOSE_3, "%d LUA module(s) loaded.\n", modulecnt);
    return 0;
}

/**
 * @brief Module load entry point
 *
 * Load module applications
 *
 * @retval 0 if all applications been loaded, -1 otherwise
 */
int
load_module()
{
    // Search the modules dir for lua modules :D
    return load_lua_modules();

}

/**
 * @brief Module unload entry point
 *
 * Unload module applications
 *
 * @return 0 if all applications are unloaded, -1 otherwise
 */
int
unload_module()
{
    //nyi
    return 0;
}
