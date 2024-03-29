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
 * @file filter.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions for creating and managin AMI message filters
 *
 * A filter acts as hooks for applications. When a message from manager
 * is received, it will check against all registered filters. If a filter
 * match its conditions with the message format, it will trigger the
 * filter callback.
 *
 * There are two ways of trigger a callback: Sync and Async.
 * In Sync mode, the manager thread will block until the callback has
 * finished. That way, the callback can register new filters that will match
 * following events.
 * Async mode is more designed for events that wont depend on other events.
 * That callbacks are executed by a scheduler thread.
 *
 * Filters condition are used to determine witch manager messages will trigger
 * the filter callback, comparing each header and value with the defined in the
 * condition.
 *
 * @todo Implement Async scheduler thread. This will require to add locks to the
 *       filter structure, to allow accesing filter data from manager and scheduler
 *       thread.
 */

#ifndef __ISAAC_FILTER_H_
#define __ISAAC_FILTER_H_

#include "manager.h"
#include "app.h"

#define DEBUG_MESSAGE session_write(filter->sess, "%s\n", message_to_text(msg));
#define DUMP_MESSAGES filter_register(filter_create(filter->sess, FILTER_SYNC_CALLBACK, filter_print_message));

//! Maximum number of conditions a filter can contain
#define MAX_CONDS       10
//! Max length of header and value of conditions
#define MAX_CONDLEN     512

//! Sorter declaration of isaac_filter struct
typedef struct _Filter Filter;
//! Sorter declaration of isaac_condition struct
typedef struct _Condition Condition;
//! Filter callback function typedef
typedef gint (*FilterFunc)(Filter *filter, AmiMessage *msg);

#include <regex.h>
#include "manager.h"
#include "session.h"

/**
 * @brief Determine how to match the filter condition
 *
 * Determine how to check if a filter's condition matchs the message.
 * Mostly used in check_message.
 *
 * Technically, all of this types can be implemented by regex type conditions
 * but are kept to make conditions easier to understand.
 *
 */
enum ConditionType {
    //! Message must contain the condition header and value
    MATCH_EXACT = 0,
    //! Message must contain the condition header and value (Case Insensitive)
    MATCH_EXACT_CASE,
    //! Message must contain the condition header and value starting with conds value
    MATCH_START_WITH,
    //! Message must contain the condition header and value that match cond regexp
    MATCH_REGEX,
    //! Message must not contain the condition header and value that match cond regexp
    MATCH_REGEX_NOT,
};

/**
 * @brief Filter's Condition structure
 *
 * A filter can contain 0-n conditions, that will make restrictions about which
 * messages match the filter and which not.
 * All conditions are implemented with 'AND' logic, which means that ALLS filters
 * condition must match in order to trigger filter's callback.
 */

struct _Condition {
    //! Condition check type, one of @ref ConditionType values
    enum ConditionType type;
    //! Header to find while checking the condition
    gchar *header;
    //! Desired value or expression that header should match
    gchar *value;
    //! For condition types MATCH_REGEX, this is the compiled expresion
    regex_t regex;
};

/**
 * @brief Filter Structure. Core and Heart of Isaac functionality
 *
 * A filter acts as a callback for Isaac applications. It can contain 0-n conditions
 * that will determine which messages are sent back to the applications.
 */
struct _Filter {
    //! Determine if this filter is active. Inactive filters are destroyed
    gboolean active;
    //! Session that requested the application that registered this filter
    Session *sess;
    //! Useful for debugging purposes
    const gchar *name;
    //! Application that registered this filter
    Application *app;
    //! Filter's Condition List
    GPtrArray *conditions;
    //! Pointer to the callback function
    FilterFunc callback;
    //! If this flag is on, the filter will be unregister after triggering once
    gboolean oneshot;
    //! User pointer for storing application information if required
    gpointer app_info;
    //! User pointer destroy notify
    GDestroyNotify destroy_func;
};

/**
 * @brief Create a new filter structure (This won't add it to the Filter's list)
 *
 * This will create a new filter's structure with the minimum required information
 * This function only allocates memory and set some values, but won't add it to the
 * Filters list (so it still won't trigger) so a filter_register should be called
 * when the filter structure is ready to rock.
 *
 * @return The new allocated filter structure or NULL in case of failure
 */
Filter *
filter_create_async(Session *sess, Application *app, const gchar *name, FilterFunc callback);

/**
 * @brief Create a new condition structure and add if to the given filter
 *
 * This is the basic function to add conditions to filters from applications.
 *
 * @param filter Filter to which add the condition
 * @param type Condition check type, one of @ref ConditionType values
 * @param hdr Header to find while checking the condition
 * @param fmt Format for the condition value
 * @param ... Variables to fill the condition format
 */
void
filter_new_condition(Filter *filter, enum ConditionType type, const char *hdr, const char *fmt, ...);

/**
 * @brief Add filter to the filters list. This will allow the filter to trigger
 *
 * Main function to make the filter active, allowing it to trigger.
 * This function is moslty used for permanent application filters or filters that
 * match more than one AMI messages.
 *
 * @param filter Filter to be registered
 */
extern int
filter_register(Filter *filter);

/**
 * @brief Add filter to the filters list. This will allow the filter to trigger once
 *
 * Main function to make the filter active, allowing it to trigger. After one trigger
 * the filter will be auto-unregistered. This can be useful to capture one single AMI
 * message without the need of unregistering the filter manually.
 *
 * @param filter Filter to be registered
 */
extern int
filter_register_oneshot(Filter *filter);

/**
 * @brief Mark a filter as inactive
 * @param filter
 */
void
filter_inactivate(Filter *filter);

/**
 * @brief Remove a filter from the filters list.
 *
 * Main function for destroying a filter and remove it from the filter list.
 *
 * @param filter Filter to be removed
 */
void
filter_destroy(Filter *filter);

/**
 * @brief Excute the filters callback when a AMI message match its conditions
 *
 * When an AMI Message match all conditions from a filter, this function will
 * call its callback.
 * If the filteres is registered as oneshot, filter will be unregistered
 * after the callback has finished
 *
 * @param filter Filter that has matched
 * @param msg Message that matched filter conditions
 * @return The filter callback return
 */
int
filter_exec_async(Filter *filter, AmiMessage *msg);

/**
 * @brief Set userdata pointer to the filter
 *
 * In some cases, applications need to store some information, which is divided
 * in diferent AMI messages. Or maybe action arguments. Or maybe retrieved info.
 * This is the general pointer to store custom information :)
 *
 * @param filter The filter that will contain the custom information
 * @param userdata Pointer to the custom information
 */
void
filter_set_userdata(Filter *filter, gpointer user_data);

void
filter_set_userdata_full(Filter *filter, gpointer user_data, GDestroyNotify destroy_func);

/**
 * @brief Get the userdata pointer of the filter
 *
 * Getter for the information set by filter_set_userdata.
 *
 * @param filter Filter that contains the custom information
 */
gpointer
filter_get_userdata(Filter *filter);

/**
 * @brief Get next filter in session using <userdata>
 *
 * @param sess Session owning the filters
 * @param userdata Pointer to the custom information
 */
gpointer
filter_from_userdata(Session *sess, gpointer userdata);

/**
 * @brief Inject a fake message as being received by manager
 *
 * This can generate fake messages in order to trigger filters in other
 * sessions.
 * The fake message passed to this function will be checked before any other
 * manager message.
 *
 * Be aware: If the function emitting the message is also triggered by the
 *           injected message, this can cause an infinite loop!
 */
void
filter_inject_message(Filter *filter, AmiMessage *msg);


/**
 * @brief Check which of the registered filters match the given message
 *        and execs its callback function
 *
 * This function is invoked for each received message to check if
 * message match any of the registered filters, invoking its callback
 * if required.
 *
 * @param filter Filter to check conditions against
 * @param msg AMI message to be checked
 * @return 0 in all cases
 */
gboolean
filter_check_and_exec(Filter *filter, AmiMessage *msg);

#endif /* __ISAAC_FILTER_H_ */
