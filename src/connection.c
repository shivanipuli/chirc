/* See connection.h for details about the functions in this module */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include "ctx.h"
#include "connection.h"
#include "utils.h"
#include "message.h"
#include "handlers.h"
#include "chirc.h"
#include "user.h"
#include "log.h"


/* Creating a new struct to pass in for the thread */
struct single_thread_args {
    int socket;
    chirc_ctx_t *ctx;
    chirc_connection_t *conn;
};

/* See connection.h */
void chirc_connection_init(chirc_connection_t *conn)
{
    conn->type = CONN_TYPE_UNKNOWN;

    conn->hostname = NULL;
    conn->port = 0;

}


/* See connection.h */
void chirc_connection_free(chirc_connection_t *conn)
{
    sdsfree(conn->hostname);

}

/* Provided in Project 1 Hints: https://beej.us/guide/bgnet/html/#sendall */
int sendall(int s, char *buf, int *len)
{
    int total = 0;        /* How many bytes we've sent */
    int bytesleft = *len; /* How many we have left to send */
    int n;

    while(total < *len) {
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) {
            break;
        }
        total += n;
        bytesleft -= n;
    }

    *len = total; /* Return number actually sent here */

    return n==-1?-1:0; /* Return -1 on failure, 0 on success */
}


/* See connection.h */
int chirc_connection_send_message(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* Serialize the message to a string */
    char *msg_str = NULL;
    if (chirc_message_to_string(msg, &msg_str) != 0) {
        chilog(CRITICAL, "Error serializing message");
        exit(-1);
    }

    pthread_mutex_lock(&ctx->socket_lock);

    /* Sending Message */
    if(msg_str != NULL) {
        int len = strlen(msg_str);
        if(sendall(conn->socket, msg_str, &len) < 0) {
            chilog(CRITICAL, "Socket send() failed");
            close(conn->socket);
            exit(-1);
        }
    }
    pthread_mutex_unlock(&ctx->socket_lock);
    return CHIRC_OK;
}

/* See connection.h */
void *service_client(void *args)
{
    /* Initializing */
    struct single_thread_args *sta;
    chirc_ctx_t *ctx;
    chirc_connection_t *conn;
    int active_socket;

    sta = (struct single_thread_args*) args;
    ctx = sta->ctx;
    conn = sta->conn;
    active_socket = sta->socket;

    pthread_detach(pthread_self());

    if(conn->type!=CONN_TYPE_SERVER) {
        /* Create the user */
        chirc_user_t *user = malloc(sizeof(chirc_user_t));
        if(!user) {
            chilog(CRITICAL, "Allocation for user failed");
            chirc_ctx_remove_connection(ctx, conn);
            chirc_connection_free(conn);
            close(conn->socket);
        }

        /* Initializing and connecting the user to the connection */
        chirc_user_init(user);
        conn->peer.user = user;
    }
    /* Locking the socket lock, adding connection, then unlocking */
    pthread_mutex_lock(&ctx->socket_lock);
    chirc_ctx_add_connection(ctx, conn);
    pthread_mutex_unlock(&ctx->socket_lock);

    /* Reading from the socket into a single buffer */

    /* Buffer to receive bytes from the socket */
    char recv_buffer[1024];

    /* Buffer for the actual message */
    char msg_buffer[514]; /* Max size of msg in IRC + '\0' */
    int msg_buffer_idx = 0;

    /* Number of bytes received */
    int nbytes;


    while((nbytes = recv(active_socket,
                         recv_buffer,
                         sizeof(recv_buffer) - 1, 0)) > 0) {

        recv_buffer[nbytes] = '\0';

        for(int i = 0; i < nbytes; i++) {
            /* Copy each character over into the recv buffer */
            msg_buffer[msg_buffer_idx++] = recv_buffer[i];

            /* Checking for the "\r\n" message end */
            if(msg_buffer_idx > 1 && msg_buffer[msg_buffer_idx - 1] == '\n'
                    && msg_buffer[msg_buffer_idx - 2] == '\r') {
                msg_buffer[msg_buffer_idx] = '\0';

                chirc_message_t *msg = malloc(sizeof(chirc_message_t));
                chirc_message_from_string(msg, msg_buffer);

                /* HANDLER */
                if(chirc_handle(ctx, conn, msg) < 0) {
                    chirc_connection_free(conn);
                    free(conn);
                    close(active_socket);
                    pthread_exit(NULL);
                }
                /* Close the socket, frree the connection, exit the thread */

                /* Reset the index for the next message */
                msg_buffer_idx = 0;
                msg_buffer[0] = '\0';
            }

            /* Checking for buffer overflow */
            if(msg_buffer_idx >= 514) {
                chilog(ERROR, "Message buffer overflow");
                msg_buffer_idx = 0;
            }
        }
    }
    if(conn->type==CONN_TYPE_USER)
        chirc_ctx_remove_user(ctx, conn->peer.user);
    chirc_ctx_remove_connection(ctx, conn);
    pthread_exit(NULL);
}

/* See connection.h */
int chirc_connection_create_thread(chirc_ctx_t *ctx, chirc_connection_t *connection)
{
    /* Initializing */
    struct single_thread_args *sta;
    pthread_t worker_thread;

    sta = calloc(1, sizeof(struct single_thread_args));
    sta->socket = connection->socket;
    sta->ctx = ctx;
    sta->conn = connection;

    if (pthread_create(&worker_thread, NULL, service_client, sta) != 0) {
        chilog(ERROR, "Could not create a worker thread");
        return CHIRC_FAIL;
    }

    return CHIRC_OK;
}

