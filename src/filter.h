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

#define DEBUG_MESSAGE session_write(filter->sess, "%s\n", message_to_text(msg));
#define DUMP_MESSAGES filter_register(filter_create(filter->sess, FILTER_SYNC_CALLBACK, filter_print_message));

//! Maximum number of conditions a filter can contain
#define MAX_CONDS       10
//! Max length of header and value of conditions
#define MAX_CONDLEN     512

//! Sorter declaration of isaac_filter struct
typedef struct isaac_filter filter_t;
//! Sorter declaration of isaac_condition struct
typedef struct isaac_condition cond_t;

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
enum condtype
{
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

struct isaac_condition
{
    //! Condition check type, one of @ref condtype values
    enum condtype type;
    //! Header to find while checking the condition
    char hdr[MAX_CONDLEN];
    //! Desired value or expresion that header should match
    char val[MAX_CONDLEN];
    //! For condition types MATCH_REGEX, this is the compiled expresion
    regex_t regex;
};

/**
 * @brief Filter's Callback type
 *
 * This value determine if the received message from AMI is passed to the filter
 * async or sync. In Sync mode, the manager thread will stop passing the control to
 * the callback, allowing the aplication to register new filters for the following events.
 * In Async mode, the message is passed to the application from a scheduler thread,
 * which won't block manager thread, but only should be used for filters that don't
 * have to make further filters.
 */
enum filtertype
{
    //! Invoke filters callback from the scheduler thread
        FILTER_ASYNC = 0,
    //! Invoke filters callback from the manager thread (will block manager reads from AMI)
        FILTER_SYNC,
};

struct isaac_filter_async
{
    //! Pointer to the callback function
    int (*callback)(filter_t *filter, AmiMessage *msg);
    //! If this flag is on, the filter will be unregisted after triggering once
    int oneshot;
    //! User pointer for storing application information if required
    void *app_info;
};

struct isaac_filter_sync
{
    //! Stored ami message triggering the filter
    AmiMessage msg;
    //! This filter has triggered and has a valid message
    int triggered;
    //! Filter sync lock (avoid timeout while setting filter sync data)
    pthread_mutex_t lock;
};

/**
 * @brief Filter Strucure. Core and Heart of Isaac funcionality
 *
 * A filter acts as a callback for Isaac aplications. It can contain 0-n conditions
 * that will determine which messages are sent back to the applications.
 */
struct isaac_filter
{
    //! Session that requested the application that registered this filter
    Session *sess;

    //! Filter's conditions that will determine which messages are sent back to the app
    cond_t conds[MAX_CONDS];
    //! How many conditions must match
    unsigned int condcount;

    //! How the callback function is invoked
    enum filtertype type;

    //! Depending on the filter type
    union
    {
        struct isaac_filter_async async;
        struct isaac_filter_sync sync;
    } data;

    //! Pointer for Filters Linked list
    filter_t *next;
};

/**
 * @brief Create a new filter structure (This won't add it to the Filter's list)
 *
 * This will create a new filter's structure with the minimum required information
 * This function only allocates memory and set some values, but won't add it to the
 * Filters list (so it still won't trigger) so a filter_register should be called
 * when the filter structure is ready to rock.
 *
 * @param sess Session that requested the application that registered the filter
 * @param cbtype How the callback function is invoked
 * @param callback  Pointer to the callback function
 * @return The new allocated filter structure or NULL in case of failure
 */
extern filter_t *
filter_create_async(Session *sess, int (*callback)(filter_t *filter, AmiMessage *msg));

/**
 * @brief Create a new filter structure (This won't add it to the Filter's list)
 *
 * This will create a new filter's structure with the minimum required information
 * This function only allocates memory and set some values, but won't add it to the
 * Filters list (so it still won't trigger) so a filter_register should be called
 * when the filter structure is ready to rock.
 *
 * @param sess Session that requested the application that registered the filter
 * @param cbtype How the callback function is invoked
 * @param callback  Pointer to the callback function
 * @return The new allocated filter structure or NULL in case of failure
 */
extern filter_t *
filter_create_sync(Session *sess);

/**
 * @brief Add a cooked condition to the given filter
 *
 * Add a new condition to the filters condition list.
 * This function will not cook the condition for you, what means that
 * won't compile expresions in regex conditions, nor reserve any kind of
 * memory. It will only add it to the filters list (if not full)
 *
 * @param filter Filter to which add the condition
 * @param cond Condition to be added to filters condition list
 * @return 0 in case of success, 1 if the filter does not allow more filters
 */
extern int
filter_new_cooked_condition(filter_t *filter, cond_t cond);

/**
 * @brief Create a new condition structure and add if to the given filter
 *
 * This is the basic function to add conditions to filters from applications.
 *
 * @param filter Filter to which add the condition
 * @param type Condition check type, one of @ref condtype values
 * @param hdr Header to find while checking the condition
 * @param fmt Format for the condition value
 * @param ... Variables to fill the condition format
 * @return 0 in case of success, 1 if the filter does not allow more filters
 */
extern int
filter_new_condition(filter_t *filter, enum condtype type, const char *hdr, const char *fmt, ...);

/**
 * @brief Remove all conditions from the given filter
 *
 * This can be handy if we want to reuse a filter with different conditions.
 * @warning Do not use this in FILTER_ASYNC_CALLBACK Filters
 *
 * @param filter Filter to remove all conditions
 */
extern void
filter_remove_conditions(filter_t *filter);

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
filter_register(filter_t *filter);

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
filter_register_oneshot(filter_t *filter);

/**
 * @brief Mark a filter as no longer valid
 *
 * @param filter Filter to be removed
 */
extern int
filter_unregister(filter_t *filter);

/**
 * @brief Unregister all fiters from a session
 *
 * @param sess Session owning the filters
 */
extern int
filter_unregister_session(Session *sess);

/**
 * @brief Remove a filter from the filters list.
 *
 * Main function for destroying a filter and remove it from the filter list.
 *
 * @param filter Filter to be removed
 */
extern int
filter_destroy(filter_t *filter);

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
extern int
filter_exec_async(filter_t *filter, AmiMessage *msg);

/**
 * @brief Store the triggering message in the filter and mark it as triggered
 *
 * When an AMI Message match all conditions from a filter, this function will
 * strore the message in the filter and mark it as filtered
 *
 * @param filter Filter that has matched
 * @param msg Message that matched filter conditions
 * @return The filter callback return
 */
extern int
filter_exec_sync(filter_t *filter, AmiMessage *msg);

/**
 * @brief Wait for an ami event to trigger the filter
 *
 * This fuction will lock until timeout has elapsed or an ami event is filled
 * and the filter data.
 *
 * @param filter Filter thas has matched
 * @param timeout Block timeout in milliseconds
 * @param The matching ami message or NULL
 * @return 0 in case of triggered, 1 otherwise
 */
extern int
filter_run(filter_t *filter, int timeout, AmiMessage *msg);

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
extern void
filter_set_userdata(filter_t *filter, void *userdata);

/**
 * @brief Get the userdata pointer of the filter
 *
 * Getter for the information set by filter_set_userdata.
 *
 * @param filter Filter that contains the custom information
 */
extern void *
filter_get_userdata(filter_t *filter);

/**
 * @brief Get next filter in session using <userdata>
 *
 * @param sess Session owning the filters
 * @param userdata Pointer to the custom information
 */
extern void *
filter_from_userdata(Session *sess, void *userdata);

/**
 * @brief Get the next filter for the given session
 *
 * This is a simple iterator for session filters. It can be used
 * to start iterating (passing from parameter as NULL) or continue
 * from a given filter onwards.
 *
 * @param sess Session to find filters from
 * @param from NULL to start searching from the beginning of the filters list
 *             or a filter to start searching from that filter onwards.
 * @return The next filter of the session, or NULL if there are no more filters
 */
extern filter_t *
filter_from_session(Session *sess, filter_t *from);

/**
 * @brief Dummy callback for debugging purposes
 *
 * This can be handy as a general callback that prints the matching messages
 * of the filter back to the session socket. Mostly used for debugging with
 * AMI Messages match the filters conditions.
 *
 * @note Only for condition debugging purposes
 *
 * @param filter Triggered filter
 * @param msg Triggering AMI message
 * @return 0 if the message was successfully written to the session, -1 otherwise
 */
extern int
filter_print_message(filter_t *filter, AmiMessage *msg);

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
extern void
filter_inject_message(filter_t *filter, AmiMessage *msg);


/**
 * @brief Check which of the registered filters match the given message
 *
 * This function is invoked from manager thread for each received message to
 * check if the message match any of the registered filters, invoking its
 * callback if required.
 *
 * @param filter Filter to check conditions against
 * @param msg AMI message to be checked
 * @return 0 in all cases
 */
gboolean
filter_check_message(filter_t *filter, AmiMessage *msg);

#endif /* __ISAAC_FILTER_H_ */
