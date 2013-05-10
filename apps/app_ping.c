#include <stdio.h>
#include "app.h"
#include "session.h"

int ping_exec(session_t *sess, const char *args) {
	if (!session_test_flag(sess, SESS_FLAG_AUTHENTICATED)) 
		return NOT_AUTHENTICATED;
	session_write(sess, "PONG\n");
	return 0;
}

int load_module(){
	return application_register("Ping", ping_exec);
}

int unload_module(){
	return application_unregister("PING");
}
