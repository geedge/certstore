/*************************************************************************
	> File Name: cert_session.h
	> Author:
	> Mail:
	> Created Time: Fri 01 Jun 2018 02:01:08 AM PDT
 ************************************************************************/

#ifndef _CERT_SESSION_H
#define _CERT_SESSION_H

#include "event_struct.h"
#include "MESA_list_queue.h"
#include "rt_sync.h"

enum conn_states {
    conn_listening,  /**< the socket which listens for connections */
    conn_new_cmd,    /**< Prepare connection for next command */
    conn_waiting,    /**< waiting for a readable socket */
    conn_read,       /**< reading in a command line */
    conn_parse_cmd,  /**< try to parse a command from the input buffer */
    conn_write,      /**< writing out a simple response */
    conn_nread,      /**< reading in a fixed number of bytes */
    conn_swallow,    /**< swallowing unnecessary bytes w/o storing */
    conn_closing,    /**< closing this connection */
    conn_mwrite,     /**< writing out many items sequentially */
    conn_closed,     /**< connection is closed */
    conn_watch,      /**< held by the logger thread as a watcher */
    conn_max_state   /**< Max state value (used for assertion) */
};

typedef struct {
    int  id;

    rt_pthread pid;        /* unique ID of this thread */

    evutil_socket_t accept_fd;

    rt_pthread_attr *attr;

    void * (*routine)(void *);  /** Executive entry */
} libevent_thread;

struct rt_ca_statis{
    atomic64_t req_url;
    atomic64_t ca_store, ca_sign;
};

struct rt_ca_statis ca_writer;

#define WEB_REQUEST_ADD(n)  atomic64_add(&ca_writer.req_url, n);
#define CA_STORE_ADD(n)  atomic64_add(&ca_writer.ca_store, n);
#define CA_SIGN_ADD(n)  atomic64_add(&ca_writer.ca_sign, n);

extern int cert_session_init();

extern int cert_session_finish();

#endif

