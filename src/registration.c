/* See registration.h for details about the functions in this module */

#include <stdio.h>
#include <stdlib.h>
#include "handlers.h"
#include "reply.h"
#include "log.h"
#include "send.h"

/* See register.h */
int chirc_begin_registration(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Locking mutex */
    pthread_mutex_lock(&ctx->user_lock);

    chirc_connection_t *saved_conn = conn;


    /* Creating new user and adding to user hash table, error if exists */
    if(chirc_ctx_get_or_create_user(ctx, conn->peer.user->nick, &conn->peer.user) == 0) {
        send_ERR_NICKNAMEINUSE(ctx, conn, conn->peer.user->nick);
        return CHIRC_HANDLER_DISCONNECT;
    }
    chirc_user_t *user = chirc_ctx_get_user(ctx, conn->peer.user->nick);
    if(user == NULL) {
        chilog(ERROR, "Error getting the correct user");
        return CHIRC_HANDLER_DISCONNECT;
    }

    /* Assigning the connection and type to the user */
    user->conn = conn;
    if(conn->type == CONN_TYPE_SERVER) {
        user->server = conn->peer.server;
        user->server->servername = sdsnew(conn->peer.server->servername);
    } else {
        conn->type = CONN_TYPE_USER;
        user->server = ctx->network.this_server;
        user->server->servername = sdsnew(ctx->network.this_server->servername);
    }
    conn->peer.user->hostname = ctx->network.this_server->hostname;

    /* Unlocking mutex */
    pthread_mutex_unlock(&ctx->user_lock);

    return CHIRC_OK;
}


/* See register.h */
int chirc_finish_registration(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* Getting the user since this condition will always be false */
    chirc_ctx_get_or_create_user(ctx, conn->peer.user->nick, &conn->peer.user);
    /* Locking mutex */
    pthread_mutex_lock(&ctx->user_lock);

    if(conn->peer.user->username != NULL) {
        free(conn->peer.user->username);
    }
    /* Assigning the username to the user */
    conn->peer.user->username = sdsnew(msg->params[0]);
    chilog(INFO, "Assigned USER: %s", conn->peer.user->username);

    /* Checking for other parameters */
    conn->peer.user->fullname = sdsnew(msg->params[3]);
    chilog(INFO, "Assigned Full Name: %s", msg->params[3]);

    /* Setting registered var to true */
    conn->peer.user->registered = true;

    /* Unlocking mutex */
    pthread_mutex_unlock(&ctx->user_lock);

    /* Sending the welcome messages */
    chirc_welcome_messages(ctx, conn);
    for(chirc_server_t *s = ctx->network.servers; s != NULL; s = s->hh.next) {
        if(strcmp(s->servername, ctx->network.this_server->servername) != 0 && s->registered) {
            chilog(CRITICAL,"SENDING SERVER NICK");
            send_SERVER_NICK(ctx, s->conn, conn->peer.user);
        }
    }

    return CHIRC_OK;
}


/* See register.h */
int chirc_full_registration(chirc_ctx_t *ctx, chirc_connection_t *conn, char *username)
{
    /* Locking mutex */
    pthread_mutex_lock(&ctx->user_lock);

    /* Creating new user and adding to user hash table, error if exists */
    if(chirc_ctx_get_or_create_user(ctx, conn->peer.user->nick, &conn->peer.user) == 0) {
        send_ERR_NICKNAMEINUSE(ctx, conn, conn->peer.user->nick);
        return CHIRC_HANDLER_DISCONNECT;
    }
    chirc_user_t *user = chirc_ctx_get_user(ctx, conn->peer.user->nick);
    if(user == NULL) {
        chilog(ERROR, "Error getting the correct user");
        return CHIRC_HANDLER_DISCONNECT;
    }

    /* Assigning the connection and type to the user */
    if(conn->type == CONN_TYPE_SERVER) {
        user->server = conn->peer.server;
        user->server->servername = sdsnew(conn->peer.server->servername);
    } else {
        conn->type = CONN_TYPE_USER;
        user->server = ctx->network.this_server;
        user->server->servername = sdsnew(ctx->network.this_server->servername);
    }

    /* Assigning the connection and type to the user */
    user->conn = conn;

    /* Assigning the username and making registered true */
    conn->peer.user->username = username;
    conn->peer.user->registered = true;
    conn->peer.user->hostname = ctx->network.this_server->hostname;

    /* Unlocking mutex */
    pthread_mutex_unlock(&ctx->user_lock);

    /* Sending the welcome messages */
    chirc_welcome_messages(ctx, conn);

    for(chirc_server_t *s = ctx->network.servers; s != NULL; s = s->hh.next) {
        if(strcmp(s->servername, ctx->network.this_server->servername) != 0 && s->registered) {
            send_SERVER_NICK(ctx, s->conn, conn->peer.user);
        }
    }

    return CHIRC_OK;
}


/* See register.h */
int chirc_register_server(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    bool correct_server = false;
    for (chirc_server_t *s = ctx->network.servers; s != NULL; s = s->hh.next) {
        if(strncmp(s->servername,conn->peer.server->servername,strlen(s->servername))==0) {
            correct_server = true;
        }
    }
    if(!correct_server) {
        /* Sending ERROR :Server not configured here Message */
        chirc_message_t *error_msg = malloc(sizeof(chirc_message_t));
        if(chirc_message_construct(error_msg, NULL, "ERROR") != 0) {
            chilog(CRITICAL, "Error creating yourhost message");
            exit(-1);
        }
        chirc_message_add_parameter(error_msg,"Server not configured here",1);
        if(chirc_connection_send_message(ctx, conn, error_msg)!=0) {
            chilog(CRITICAL, "ERROR: unable to send quit message");
            chirc_message_free(error_msg);
            exit(-1);
        }
        return CHIRC_HANDLER_DISCONNECT;
    }
    /* Send ERROR: Bad Password */
    if(strncmp(ctx->network.this_server->passwd,conn->peer.server->passwd,strlen(ctx->network.this_server->passwd))!=0) {
        chirc_message_t *error_msg = malloc(sizeof(chirc_message_t));
        if(chirc_message_construct(error_msg, NULL, "ERROR") != 0) {
            chilog(CRITICAL, "Error creating yourhost message");
            exit(-1);
        }
        chirc_message_add_parameter(error_msg,"Bad password",1);
        if(chirc_connection_send_message(ctx, conn, error_msg)!=0) {
            chilog(CRITICAL, "ERROR: unable to send quit message");
            chirc_message_free(error_msg);
            exit(-1);
        }
        return CHIRC_HANDLER_DISCONNECT;
    }


    bool name_already_registered = false;
    bool send_other_one = false;
    char *servername;
    for (chirc_server_t *s = ctx->network.servers; s != NULL; s = s->hh.next) {
        if (strcmp(s->servername, conn->peer.server->servername) == 0 && s->conn == conn) {
            name_already_registered = true;
            break;
        } else if (strcmp(s->servername, conn->peer.server->servername) == 0 && s->conn != conn && s->registered) {
            servername = sdsdup(s->servername);
            send_other_one = true;
            break;
        }
    }

    if (name_already_registered) {
        chirc_message_t *error_msg = malloc(sizeof(chirc_message_t));
        if(chirc_message_construct_reply(error_msg,ctx,conn, ERR_ALREADYREGISTRED) != 0) {
            chilog(CRITICAL, "Error creating yourhost message");
            exit(-1);
        }
        char quit_str[512];
        sprintf(quit_str, "Unauthorized command (already registered)");

        chirc_message_add_parameter(error_msg,quit_str,1);
        if(chirc_connection_send_message(ctx, conn, error_msg)!=0) {
            chilog(CRITICAL, "ERROR: unable to send quit message");
            chirc_message_free(error_msg);
            exit(-1);
        }
        return CHIRC_HANDLER_DISCONNECT;
    } else if (send_other_one) {
        chilog(ERROR, "coming into here pls pls pls");
        chirc_message_t *error_msg = malloc(sizeof(chirc_message_t));
        if(chirc_message_construct(error_msg, NULL, "ERROR") != 0) {
            chilog(CRITICAL, "Error creating yourhost message");
            exit(-1);
        }
        char quit_str[512];
        sprintf(quit_str, "ID \"%s\" already registered", servername);

        chirc_message_add_parameter(error_msg,quit_str,true);
        if(chirc_connection_send_message(ctx, conn, error_msg)!=0) {
            chilog(CRITICAL, "ERROR: unable to send quit message");
            chirc_message_free(error_msg);
            exit(-1);
        }
        return CHIRC_HANDLER_DISCONNECT;
    }

    for(chirc_connection_t *c = ctx->connections; c != NULL; c = c->hh.next) {
        if(c->type == CONN_TYPE_SERVER && strcmp(c->peer.server->servername, conn->peer.server->servername) == 0) {
            chirc_server_t *server = chirc_ctx_get_server(ctx, c->peer.server->servername);
            conn->peer.server->registered = true;
            server->registered = true;
            server->conn = conn;


            chirc_message_t *pass_msg = malloc(sizeof(chirc_message_t));
            if(chirc_message_construct(pass_msg, ctx->network.this_server->servername, "PASS") != 0) {
                chilog(CRITICAL, "Error creating yourhost message");
                exit(-1);
            }
            chirc_message_add_parameter(pass_msg,server->passwd,false);
            chirc_message_add_parameter(pass_msg,"0210",false);
            chirc_message_add_parameter(pass_msg,"chirc|0.6",false);  /* Hardcoded based on ED suggestion */
            chirc_connection_send_message(ctx,conn,pass_msg);
            chirc_message_free(pass_msg);

            chirc_message_t *server_msg = malloc(sizeof(chirc_message_t));
            if(chirc_message_construct(server_msg, ctx->network.this_server->servername, "SERVER") != 0) {
                chilog(CRITICAL, "Error creating yourhost message");
                exit(-1);
            }
            chirc_message_add_parameter(server_msg,ctx->network.this_server->servername,0);
            chirc_message_add_parameter(server_msg,"1",0);

            chirc_message_add_parameter(server_msg,"1",0);
            chirc_message_add_parameter(server_msg,"chirc_server",1);
            if(chirc_connection_send_message(ctx,conn,server_msg)!=0) {
                chilog(ERROR, "Message send failure");
                exit(-1);
            }
            chirc_message_free(server_msg);
            return CHIRC_OK;
        }
    }
    return CHIRC_OK;
}