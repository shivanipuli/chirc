/*
 * Message handlers
 *
 * In chirc, the code to process each IRC command is contained in
 * a function that looks like this:
 *
 * int chirc_handle_COMMAND(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
 *
 * e.g., the handler function for PRIVMSG would be chirc_handle_PRIVMSG
 * (with the same parameters shown above)
 *
 * These functions are added to a dispatch table that allows us
 * to easily dispatch messages to the correct function based
 * on their command.
 *
 * A dispatch table is basically a table that maps a key (in this
 * case, an IRC command) to a function pointer. So, given
 * a command name, we can find the function that will handle
 * that command. In our code, this table is implemented
 * via the "handlers" array contained in this module.
 *
 * To implement a new command, you will need to implement a
 * handler function for that command, and update the "handlers"
 * array to add an entry for the new command. See the code
 * below for more details.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <sys/socket.h>
#include <netdb.h>
#include "ctx.h"
#include "channel.h"
#include "channeluser.h"
#include "handlers.h"
#include "reply.h"
#include "log.h"
#include "connection.h"
#include "chirc.h"
#include "message.h"
#include "user.h"
#include "server.h"
#include "send.h"
#include "registration.h"


/* The following typedef defines a type called "handler_function"
 * for the function pointers in the handlers array. */
typedef int (*handler_function_t)(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);


/* Forward declaration of handler functions */
int chirc_handle_PING(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_PONG(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_NICK(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_USER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_QUIT(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_PRIVMSG(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_NOTICE(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_MOTD(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_LUSERS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_WHOIS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_JOIN(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_PART(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_MODE(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_OPER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_AWAY(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_LIST(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_PASS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_SERVER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);
int chirc_handle_CONNECT(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);


/*! \struct handler_entry
 * \brief Entry in the handler dispatch table
 *
 * This struct represents one entry in the dispatch table:
 * a command name and a function pointer to a handler function
 * (using the handler_function_t type we defined earlier) */
struct handler_entry {
    char *name;
    handler_function_t func;
};

/* Convenience macro for specifying entries in the dispatch table */
#define HANDLER_ENTRY(NAME) { #NAME, chirc_handle_ ## NAME}

/* Null entry in the dispatch table. This must always be the last
 * entry in the dispatch table */
#define NULL_ENTRY			{ NULL, NULL }


/* The dispatch table (an array of handler_entry structs).
 * To add a new entry (e.g., for command FOOBAR) add a new
 * line that looks like this:
 *
 *     HANDLER_ENTRY (FOOBAR)
 *
 * Make sure to add it *before* the NULL_ENTRY entry, which
 * must always come last.
 */
struct handler_entry handlers[] = {
    HANDLER_ENTRY (PING),
    HANDLER_ENTRY (PONG),
    HANDLER_ENTRY (NICK),
    HANDLER_ENTRY (USER),
    HANDLER_ENTRY (QUIT),
    HANDLER_ENTRY (PRIVMSG),
    HANDLER_ENTRY (NOTICE),
    HANDLER_ENTRY (MOTD),
    HANDLER_ENTRY (LUSERS),
    HANDLER_ENTRY (WHOIS),
    HANDLER_ENTRY (JOIN),
    HANDLER_ENTRY (PART),
    HANDLER_ENTRY (MODE),
    HANDLER_ENTRY (OPER),
    HANDLER_ENTRY (AWAY),
    HANDLER_ENTRY (LIST),
    HANDLER_ENTRY (PASS),
    HANDLER_ENTRY (SERVER),
    HANDLER_ENTRY (CONNECT),
    NULL_ENTRY
};


/* See handlers.h */
int chirc_handle(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    chirc_message_t reply;
    int rc=0, h;
    int found = 0;

    /* Print message to the server log */
    serverlog(DEBUG, conn, "Handling command %s", msg->cmd);
    for(int i=0; i<msg->nparams; i++)
        serverlog(DEBUG, conn, "%s[%i] = %s", msg->cmd, i + 1, msg->params[i]);

    /* Search the dispatch table for an entry corresponding to the
     * message we are processing */
    for(h=0; handlers[h].name != NULL; h++)
        if (!strcmp(msg->cmd, handlers[h].name)) {

            rc = handlers[h].func(ctx, conn, msg);
            found = 1;
            break;
        }

    /* The command that was sent is unknown */
    if(!found && conn->peer.user->registered) {
        send_ERR_UNKNOWNCOMMAND(ctx, conn, msg->cmd);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return rc;
}


int chirc_handle_PING(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* Construct a reply to the PING */
    chirc_message_t reply;
    chirc_message_construct(&reply, NULL, "PONG");
    chirc_message_add_parameter(&reply, ctx->network.this_server->servername, 0);

    /* Send the message */
    if(chirc_connection_send_message(ctx, conn, &reply)) {
        chirc_message_free(&reply);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}


int chirc_handle_PONG(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* PONG messages are ignored, so we don't do anything */

    return CHIRC_OK;
}


int chirc_handle_NICK(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* Making sure there is a nickname passed in */
    if(msg->params[0] == NULL) {
        send_ERR_NONICKNAMEGIVEN(ctx, conn);
        return CHIRC_HANDLER_DISCONNECT;
    }

    if(conn->type==CONN_TYPE_SERVER) {
        /* Locking the mutex */
        pthread_mutex_lock(&ctx->server_lock);

        /* Creating the user to add to the table from the server connection */
        chirc_user_t *new_user = malloc(sizeof(chirc_user_t));
        chirc_user_init(new_user);
        chirc_ctx_get_or_create_user(ctx, msg->params[0], &new_user);
        new_user->nick = msg->params[0];
        new_user->username = msg->params[2];
        new_user->hostname = msg->params[3];
        new_user->fullname = msg->params[6];
        new_user->registered = true;
        new_user->conn=conn;
        chirc_server_t *server = chirc_ctx_get_server(ctx, msg->prefix);
        if(server == NULL) {
            chilog(ERROR, "Getting server failed");
        }
        new_user->server = server;
        new_user->server->servername = sdsnew(server->servername);

        /* Unlocking the mutex */
        pthread_mutex_unlock(&ctx->server_lock);

        return CHIRC_OK;
    } else {
        /* Checking to see if another user exists with the given nick */
        if(chirc_ctx_get_user(ctx, msg->params[0]) != NULL) {
            send_ERR_NICKNAMEINUSE(ctx, conn, msg->params[0]);
            return CHIRC_HANDLER_DISCONNECT;
        }

        /* No nickname was provided */
        if(strncmp(msg->params[0],"",2)==0) {
            send_ERR_NONICKNAMEGIVEN(ctx, conn);
            return CHIRC_HANDLER_DISCONNECT;
        }

        /* If user is registered already: trigger change in nick */
        if(conn->peer.user->registered) {
            /* Check if new nick is in use */
            chirc_user_t* u = chirc_ctx_get_user(ctx, msg->params[0]);

            /* If different user has same nick */
            if(u != NULL && strncmp(u->nick,msg->params[0],strlen(u->nick))!=0) {
                send_ERR_NICKNAMEINUSE(ctx, conn, msg->params[0]);
                return CHIRC_HANDLER_DISCONNECT;
            }
            /* Send message to notify other users */
            for(chirc_channeluser_t* channel_user = conn->peer.user->channels; channel_user!=NULL; channel_user = channel_user->hh_from_user.next) {
                chirc_channel_t* channel = channel_user->channel;

                /* For every user in channel */
                for (chirc_channeluser_t *u = channel->users; u != NULL; u = u->hh_from_channel.next)
                    /* sending quit message */
                    send_NICKCHANGED(ctx, conn, u->user->conn, msg->params[0]);
            }

            chirc_user_t *myuser = chirc_ctx_get_user(ctx,conn->peer.user->nick);
            myuser->nick = strndup(msg->params[0], strlen(msg->params[0]));

            return CHIRC_OK;
        }

        /* Assigning the nickname to the user */
        conn->peer.user->nick = strndup(msg->params[0], strlen(msg->params[0]));
        conn->type=CONN_TYPE_USER;

        /* Case 1 when the user command has already been sent */
        if(conn->peer.user->username != NULL) {
            char *username = strndup(conn->peer.user->username, strlen(conn->peer.user->username));
            chirc_full_registration(ctx, conn, username);
        } else {
            /* Case 2 when the nick command was sent first */
            chirc_begin_registration(ctx, conn);
        }
    }

    return CHIRC_OK;
}


int chirc_handle_USER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* Not enough parameters provided */
    if(msg->nparams < 4) {
        send_ERR_NEEDMOREPARAMS(ctx, conn, "USER");
        return CHIRC_HANDLER_DISCONNECT;
    }

    /* Going through the users hash table and checking if already registered */
    for (chirc_user_t *u = ctx->users; u != NULL; u = u->hh.next) {
        if(u->registered && strcmp(u->username,msg->params[0])==0) {
            send_ERR_ALREADYREGISTRED(ctx, conn);
            return CHIRC_HANDLER_DISCONNECT;
        }
    }

    /* Assigning the username to the user */
    conn->peer.user->username = strndup(msg->params[0], strlen(msg->params[0]));
    conn->type=CONN_TYPE_USER;

    /* Checking for other parameters */
    conn->peer.user->fullname = strndup(msg->params[3], strlen(msg->params[3]));

    /* Only going to finish registration if the nick command has been sent */
    if(conn->peer.user->nick != NULL) {
        chirc_finish_registration(ctx, conn, msg);
    }

    return CHIRC_OK;
}


int chirc_handle_QUIT(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    send_quit_messages(ctx, conn, msg);

    /* 1: Send error message to client */
    chirc_message_t *error_msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct(error_msg, NULL, "ERROR") != 0) {
        chilog(CRITICAL, "Error creating yourhost message");
        exit(-1);
    }
    char hostname[100];
    gethostname(hostname, sizeof(hostname));
    char quit_str[512];
    if(msg->nparams < 1) {
        sprintf(quit_str, "Closing Link: %s (Client Quit)", hostname);
    } else {
        sprintf(quit_str, "Closing Link: %s (%s)", hostname, msg->params[0]);
    }
    chirc_message_add_parameter(error_msg, quit_str, true);
    if(chirc_connection_send_message(ctx, conn, error_msg)!=0) {
        chilog(CRITICAL, "ERROR: unable to send quit message");
        chirc_message_free(error_msg);
        exit(-1);
    }

    for(chirc_channeluser_t* channel_user = conn->peer.user->channels; channel_user!=NULL; channel_user = channel_user->hh_from_user.next) {
        chirc_channel_t* channel = channel_user->channel;

        /* Removes user from each channel it's connected to */
        pthread_mutex_lock(&channel->lock);
        chirc_channeluser_remove(channel_user);
        chirc_channeluser_free(conn->peer.user->channels);
        if(chirc_ctx_numchannelusers(channel) == 0) {
            chirc_ctx_remove_channel(ctx, channel);
            chirc_channel_free(channel);
        }
        pthread_mutex_unlock(&channel->lock);
    }
    close(conn->socket);
    return CHIRC_OK;
}


int chirc_handle_PRIVMSG(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* Checking the recipient */
    if(msg->nparams < 1) {
        send_ERR_NORECIPIENT(ctx,conn,msg->cmd);
        return CHIRC_HANDLER_DISCONNECT;
    }

    /* Checking that there is something to actually send */
    if(msg->nparams < 2 || strlen(msg->params[1]) == 0) {
        send_ERR_NOTEXTTOSEND(ctx,conn,msg->cmd);
        return CHIRC_HANDLER_DISCONNECT;
    }
    /* Sending to channel */
    if(msg->params[0][0]=='#') {
        /* Checking and trying to create/retrieve channel */
        char *channel_name = msg->params[0];
        chirc_channel_t *channel = NULL;
        channel = chirc_ctx_get_channel(ctx, channel_name);
        if(channel == NULL) {
            send_ERR_NOSUCHNICK(ctx, conn, msg->params[0]);
            return CHIRC_HANDLER_DISCONNECT;
        }


        if(conn->type==CONN_TYPE_USER) {
            /* Getting the channeluser */
            chirc_channeluser_t *channeluser = chirc_channeluser_get(channel, conn->peer.user);
            if(channeluser == NULL) {
                send_ERR_CANNOTSENDTOCHAN(ctx, conn, channel->name);
                return CHIRC_HANDLER_DISCONNECT;
            }

            /* First checking whether the user has IRCop status */
            if (!chirc_user_has_mode(conn->peer.user, 'o') && !chirc_channeluser_has_mode(channeluser, 'o')) {
                /* Then checking if the channel mode is moderator only */
                if(chirc_channel_has_mode(channel, 'm') && !(chirc_channeluser_has_mode(channeluser, 'v'))) {
                    send_ERR_CANNOTSENDTOCHAN(ctx, conn, channel->name);
                    return CHIRC_HANDLER_DISCONNECT;
                }
            }
        }
        /* Send to all users in this channel */
        if(conn->type==CONN_TYPE_USER) {
            send_privmsg_messages(ctx, channel, conn->peer.user->nick, msg);
            /* 1st relay message */
            chirc_message_t relay_msg;
            chirc_message_construct(&relay_msg, conn->peer.user->nick, "PRIVMSG");
            chirc_message_add_parameter(&relay_msg, msg->params[0], false);
            chirc_message_add_parameter(&relay_msg, msg->params[1], true);
            for(chirc_server_t *s = ctx->network.servers; s != NULL; s = s->hh.next) {
                if(strcmp(s->servername, ctx->network.this_server->servername) != 0 && s->registered) {
                    if(chirc_connection_send_message(ctx, s->conn, &relay_msg)) {
                        chirc_message_free(&relay_msg);
                        return CHIRC_HANDLER_DISCONNECT;
                    }
                }
            }
            chirc_message_free(&relay_msg);
        } else if(conn->type==CONN_TYPE_SERVER) {
            send_privmsg_messages(ctx, channel, msg->prefix, msg);
        }
    } else { /* Sending to user(not channel) */
        chirc_user_t *recipient = chirc_ctx_get_user(ctx, msg->params[0]);
        if(recipient == NULL) {
            chilog(ERROR, "Could not get user");
            send_ERR_NOTREGISTERED(ctx, conn);
            return CHIRC_HANDLER_DISCONNECT;
        }
        /* Recipient is in this server */
        if(strncmp(recipient->server->servername,ctx->network.this_server->servername,sdslen(recipient->server->servername))==0) {
            chirc_message_t new_msg;
            if(chirc_user_has_mode(recipient,'a')) {
                chirc_message_construct_reply(&new_msg,ctx,conn,RPL_AWAY);
                chirc_message_add_parameter(&new_msg,recipient->nick,0);
                chirc_message_add_parameter(&new_msg,recipient->awaymsg,1);
                if(chirc_connection_send_message(ctx, conn, &new_msg)) {
                    chirc_message_free(&new_msg);
                    return CHIRC_HANDLER_DISCONNECT;
                }
            }
            if(conn->type==CONN_TYPE_SERVER)
                chirc_message_construct(&new_msg, msg->prefix, "PRIVMSG");
            else
                chirc_message_construct(&new_msg, conn->peer.user->nick, "PRIVMSG");
            chirc_message_add_parameter(&new_msg, msg->params[0], false);
            chirc_message_add_parameter(&new_msg, msg->params[1], true);
            if(chirc_connection_send_message(ctx, recipient->conn, &new_msg)) {
                chirc_message_free(&new_msg);
                return CHIRC_HANDLER_DISCONNECT;
            }
            return CHIRC_OK;
        } else {
            if(conn->type==CONN_TYPE_USER) {
                chirc_message_t relay_msg;
                chirc_message_construct(&relay_msg, conn->peer.user->nick, "PRIVMSG");
                chirc_message_add_parameter(&relay_msg, msg->params[0], false);
                chirc_message_add_parameter(&relay_msg, msg->params[1], true);
                for(chirc_server_t *s = ctx->network.servers; s != NULL; s = s->hh.next) {
                    if(strcmp(s->servername, ctx->network.this_server->servername) != 0 && s->registered) {
                        if(chirc_connection_send_message(ctx, s->conn, &relay_msg)) {
                            chirc_message_free(&relay_msg);
                            return CHIRC_HANDLER_DISCONNECT;
                        }
                    }
                }
                chirc_message_free(&relay_msg);
            } else /* If conn->type==CONN_TYPE_SERVER and user not in this server -> ignore */
                return CHIRC_HANDLER_DISCONNECT;
            return CHIRC_OK;
        }
    }
    return CHIRC_OK;
}


int chirc_handle_NOTICE(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    if(!conn->peer.user->registered) {
        return CHIRC_OK;
    }
    if(msg->nparams < 1) {
        return CHIRC_OK;
    }
    if(msg->nparams < 2 || strlen(msg->params[1]) == 0) {
        return CHIRC_OK;
    }
    chirc_user_t *recipient = chirc_ctx_get_user(ctx,msg->params[0]);
    if(recipient == NULL) {
        return CHIRC_OK;
    }

    chirc_message_t new_msg;
    chirc_message_construct(&new_msg, conn->peer.user->nick, "NOTICE");
    chirc_message_add_parameter(&new_msg, msg->params[0], false);
    chirc_message_add_parameter(&new_msg, msg->params[1], true);


    if(chirc_connection_send_message(ctx, recipient->conn, &new_msg)) {
        chirc_message_free(&new_msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}


int chirc_handle_MOTD(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    if(!conn->peer.user->registered) {
        send_ERR_NOTREGISTERED(ctx, conn);
        return CHIRC_HANDLER_DISCONNECT;
    }

    /* Buffer with default size of 514 for current working directory */
    char cwd[514];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        chilog(ERROR, "getcwd() error");
    }

    /* Appending the motd.txt to the path */
    strcat(cwd, "/motd.txt");

    /* Open the MOTD file */
    FILE *file = fopen(cwd, "r");
    if (file == NULL) {
        send_ERR_NOMOTD(ctx, conn);
        return CHIRC_HANDLER_DISCONNECT;
    }

    /* MOTD start message */
    chirc_message_t start_msg;
    if(chirc_message_construct_reply(&start_msg, ctx, conn, RPL_MOTDSTART) != 0) {
        chilog(CRITICAL, "Error creating yourhost message");
        exit(-1);
    }
    char long_str[514];
    sprintf(long_str, "- %s Message of the day - ", ctx->network.this_server->servername);
    chirc_message_add_parameter(&start_msg, long_str, true);
    chirc_connection_send_message(ctx, conn, &start_msg);

    /* Max size of a message is 514 characters */
    char buffer[514];

    /* Reading each line of the MOTD file */
    int counter = 1;
    while (fgets(buffer, 514, file) != NULL) {
        /* Splitting on each newline for correct message handling */
        buffer[strcspn(buffer, "\n")] = 0;
        /* Creating each RPL_MOTD message */
        chirc_message_t motd_msg;
        if(chirc_message_construct_reply(&motd_msg, ctx, conn, RPL_MOTD) != 0) {
            chilog(CRITICAL, "Error creating yourhost message");
            exit(-1);
        }

        char motd_msg_str[1024];
        sprintf(motd_msg_str, "- %s", buffer);
        chirc_message_add_parameter(&motd_msg, motd_msg_str, true);
        chirc_connection_send_message(ctx, conn, &motd_msg);
    }

    /* MOTD end message */
    chirc_message_t end_msg;
    if(chirc_message_construct_reply(&end_msg, ctx, conn, RPL_ENDOFMOTD) != 0) {
        chilog(CRITICAL, "Error creating yourhost message");
        exit(-1);
    }
    chirc_message_add_parameter(&end_msg, "End of MOTD command", true);
    chirc_connection_send_message(ctx, conn, &end_msg);

    /* Close the opened file */
    fclose(file);

    return CHIRC_OK;
}


int chirc_handle_LUSERS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* Checking for valid user registration */
    if(!conn->peer.user->registered) {
        send_ERR_NOTREGISTERED(ctx, conn);
        return CHIRC_HANDLER_DISCONNECT;
    }

    send_RPL_LUSERCLIENT(ctx, conn);
    send_RPL_LUSEROP(ctx, conn);
    send_RPL_LUSERUNKNOWN(ctx, conn);
    send_RPL_LUSERCHANNELS(ctx, conn);
    send_RPL_LUSERME(ctx, conn);
    return CHIRC_OK;
}


int chirc_handle_WHOIS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* Checking for valid user registration */
    if(!conn->peer.user->registered) {
        send_ERR_NOTREGISTERED(ctx, conn);
        return CHIRC_HANDLER_DISCONNECT;
    }

    /* Returning immediately if the number of params is not correct */
    if(msg->nparams == 0) {
        return CHIRC_OK;
    }

    /* Getting the recipient and handling case with no nickname */
    chirc_user_t *recipient = chirc_ctx_get_user(ctx,msg->params[0]);
    if(recipient == NULL) {
        send_ERR_NOSUCHNICK(ctx,conn, msg->params[0]);
        return CHIRC_HANDLER_DISCONNECT;
    }

    send_RPL_WHOISUSER(ctx, conn, recipient);

    sds channel_str = sdsempty();
    /* Get channeluser for recipient */
    for(chirc_channeluser_t* channel = recipient->channels; channel!= NULL; channel = channel->hh_from_user.next) {

        char *channel_name = strndup(channel->channel->name, strlen(channel->channel->name));
        /* Getting the channeluser if possible */
        chirc_channeluser_t *channeluser = chirc_channeluser_get(channel->channel, recipient);
        if(channeluser == NULL) {
            continue;
        }

        /* Getting the prefix */
        char prefix = '\0';
        if(chirc_channeluser_has_mode(channel, 'v')) {
            prefix = '+';
        } else if (chirc_channeluser_has_mode(channel, 'o')) {
            prefix = '@';
        }

        /* Creating the channel string */
        if (sdslen(channel_str) == 0) {
            if (prefix != '\0') {
                channel_str = sdscatprintf(channel_str, "%c%s ", prefix, channel_name);
            } else {
                channel_str = sdscatprintf(channel_str, "%s ", channel_name);
            }
        } else {
            if (prefix != '\0') {
                channel_str = sdscatprintf(channel_str, "%s %c%s ", channel_str, prefix, channel_name);
            } else {
                channel_str = sdscatprintf(channel_str, "%s %s ",  channel_str, channel_name);
            }
        }
    }

    /* Checking whether or not to actually send the string */
    if(strlen(channel_str) > 1) {
        /* Creating the message */
        chirc_message_t *cmsg = malloc(sizeof(chirc_message_t));
        chirc_message_construct_reply(cmsg, ctx, conn, RPL_WHOISCHANNELS);
        chirc_message_add_parameter(cmsg, recipient->nick, false);
        chirc_message_add_parameter(cmsg, channel_str, true);

        if(chirc_connection_send_message(ctx, conn, cmsg)) {
            chirc_message_free(cmsg);
            return CHIRC_HANDLER_DISCONNECT;
        }
    }

    send_RPL_WHOISSERVER(ctx, conn, recipient);

    /* send_RPL_AWAY */
    if(chirc_user_has_mode(recipient,'a')) {
        chirc_message_t new_msg;
        chirc_message_construct_reply(&new_msg,ctx,conn,RPL_AWAY);
        chirc_message_add_parameter(&new_msg,recipient->nick,0);
        chirc_message_add_parameter(&new_msg,recipient->awaymsg,1);
        if(chirc_connection_send_message(ctx, conn, &new_msg)) {
            chirc_message_free(&new_msg);
            return CHIRC_HANDLER_DISCONNECT;
        }
    }

    /* RPL_WHOISOPERATOR */
    if(chirc_user_has_mode(recipient, 'o')) {
        chirc_message_t new_msg;
        chirc_message_construct_reply(&new_msg,ctx,conn,RPL_WHOISOPERATOR);
        chirc_message_add_parameter(&new_msg,recipient->nick,0);
        chirc_message_add_parameter(&new_msg,"is an IRC operator",1);
        if(chirc_connection_send_message(ctx, conn, &new_msg)) {
            chirc_message_free(&new_msg);
            return CHIRC_HANDLER_DISCONNECT;
        }
    }

    send_RPL_ENDOFWHOIS(ctx, conn, recipient);

    return CHIRC_OK;
}


int chirc_handle_JOIN(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* Checking if there are not enough parameters */
    if(msg->nparams < 1) {
        send_ERR_NEEDMOREPARAMS(ctx, conn, "JOIN");
        return CHIRC_HANDLER_DISCONNECT;
    }

    if(conn->type == CONN_TYPE_SERVER) {

        /* Checking and trying to create/retrieve channel */
        char *channel_name = msg->params[0];
        chirc_channel_t *channel;
        if(chirc_ctx_get_or_create_channel(ctx, channel_name, &channel) == 1) {
            chilog(INFO, "NEW CHANNEL CREATED");
        }

        /* Locking mutex */
        pthread_mutex_lock(&channel->lock);

        /* Checking and trying to create/retrieve channeluser */
        chirc_channeluser_t *channeluser;
        chirc_user_t *user = chirc_ctx_get_user(ctx, msg->prefix);
        if(user == NULL) {
            chilog(ERROR, "The user is null");
        }

        if(chirc_channeluser_get_or_create(channel, user, &channeluser) == 1) {
            if(chirc_ctx_numchannelusers(channel) == 1) {
                chirc_channeluser_set_mode(channeluser, 'o');
            }
            /* Unlocking mutex */
            pthread_mutex_unlock(&channel->lock);

            /* Sending all of the other join messages */
            send_join_messages(ctx, conn, channel, user->nick);
        }

        /* Unlocking mutex if not already unlocked */
        pthread_mutex_unlock(&channel->lock);
    } else {
        /* Checking and trying to create/retrieve channel */
        char *channel_name = msg->params[0];
        chirc_channel_t *channel = NULL;
        if(chirc_ctx_get_or_create_channel(ctx, channel_name, &channel) == 1) {
            chilog(INFO, "NEW CHANNEL CREATED");
        }

        /* Locking mutex */
        pthread_mutex_lock(&channel->lock);

        /* Checking and trying to create/retrieve channeluser */
        chirc_channeluser_t *channeluser;
        if(chirc_channeluser_get_or_create(channel, conn->peer.user, &channeluser) == 1) {
            chilog(INFO, "%s JOINED", conn->peer.user->nick);
            if(chirc_ctx_numchannelusers(channel) == 1) {
                chirc_channeluser_set_mode(channeluser, 'o');
            }
            /* Unlocking mutex */
            pthread_mutex_unlock(&channel->lock);

            send_JOIN(ctx, conn, channel, conn->peer.user->nick);

            /* Sending the other two required messages */
            send_RPL_NAMREPLY(ctx, conn);
            send_RPL_ENDOFNAMES(ctx, conn);

            /* Sending all of the other join messages */
            send_join_messages(ctx, conn, channel, conn->peer.user->nick);
        }

        /* Unlocking mutex if not already unlocked */
        pthread_mutex_unlock(&channel->lock);
    }

    return CHIRC_OK;
}


int chirc_handle_PART(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    if(msg->nparams < 1) {
        send_ERR_NEEDMOREPARAMS(ctx, conn, "PART");
        return CHIRC_HANDLER_DISCONNECT;
    }

    char *part_message = NULL;
    if(msg->nparams == 2) {
        part_message = strndup(msg->params[1], strlen(msg->params[1]));
    }

    /* Retrieiving channel and checking that it exists */
    chirc_channel_t *channel;
    channel = chirc_ctx_get_channel(ctx, msg->params[0]);
    if(channel == NULL) {
        send_ERR_NOSUCHCHANNEL(ctx, conn, msg->params[0]);
        return CHIRC_HANDLER_DISCONNECT;
    }

    /* Retrieving channeluser and checking that it exists */
    chirc_channeluser_t *channeluser;
    channeluser = chirc_channeluser_get(channel, conn->peer.user);

    if(channeluser == NULL) {
        send_ERR_NOTONCHANNEL(ctx, conn, channel);
        return CHIRC_HANDLER_DISCONNECT;
    }

    char *nick = strndup(conn->peer.user->nick, strlen(conn->peer.user->nick));
    send_part_messages(ctx, conn, channel, nick, part_message);

    /* Locking mutex */
    pthread_mutex_lock(&ctx->user_lock);

    /* Removing the channeluser and freeing it */
    chirc_channeluser_remove(channeluser);
    chirc_channeluser_free(channeluser);

    /* Getting the number of channelusers */
    if(chirc_ctx_numchannelusers(channel) == 0) {
        pthread_mutex_lock(&ctx->server_lock);
        chirc_ctx_remove_channel(ctx, channel);
        pthread_mutex_unlock(&ctx->server_lock);
        chirc_channel_free(channel);
    }

    /* Unlocking mutex */
    pthread_mutex_unlock(&ctx->user_lock);

    return CHIRC_OK;
}


/*! \brief Specifically handles modes for channel structs
 *
 * This is a helper function that is called in the main MODE handler
 * to specifically handle the scenarios necessary for channels.
 *
 * \param ctx The server context
 * \param conn The connection
 * \param msg The MODE message
 */
int chirc_handle_channel_MODE(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    char* modes = "amt";
    char mode = msg->params[1][1];
    /* Retrieiving channel and checking that it exists */
    chirc_channel_t *channel;
    channel = chirc_ctx_get_channel(ctx, msg->params[0]);
    if(channel == NULL) {
        send_ERR_NOSUCHCHANNEL(ctx, conn, msg->params[0]);
        return CHIRC_HANDLER_DISCONNECT;
    }

    if(msg->params[2] != NULL) {
        /* Finding the user based on the nick provided in the mode command */
        char *advanced_modes = "aovmt";
        char *nick;
        nick = sdsnew(msg->params[2]);
        chirc_user_t *mode_user;
        mode_user = chirc_ctx_get_user(ctx, nick);
        if(mode_user == NULL) {
            send_ERR_USERNOTINCHANNEL(ctx, conn, channel, nick);
            return CHIRC_HANDLER_DISCONNECT;
        }

        if (strchr(advanced_modes, mode) == NULL) {
            char m[2];
            m[0] = mode;
            m[1] = '\0';
            send_ERR_UNKNOWNMODE(ctx, conn, channel, m);
            return CHIRC_HANDLER_DISCONNECT;
        }

        /* Retrieving channeluser and checking that it exists */
        pthread_mutex_lock(&ctx->user_lock);
        chirc_channeluser_t *channeluser;
        channeluser = chirc_channeluser_get(channel, conn->peer.user);
        pthread_mutex_unlock(&ctx->user_lock);

        if(chirc_user_has_mode(conn->peer.user, 'o') && channeluser == NULL)  {
            send_ERR_USERNOTINCHANNEL(ctx, conn, channel, nick);
            return CHIRC_HANDLER_DISCONNECT;
        } else if (channeluser == NULL && !chirc_user_has_mode(conn->peer.user, 'o')) {
            send_ERR_CHANOPRIVSNEEDED(ctx, conn, channel);
            return CHIRC_HANDLER_DISCONNECT;
        } else if(!chirc_channeluser_has_mode(channeluser, 'o') && !chirc_user_has_mode(conn->peer.user, 'o')) {
            send_ERR_CHANOPRIVSNEEDED(ctx, conn, channel);
            return CHIRC_HANDLER_DISCONNECT;
        } else if (mode == 'v' || mode == 'o') {
            pthread_mutex_lock(&ctx->user_lock);
            chirc_user_t *fetched_user = chirc_ctx_get_user(ctx, msg->params[2]);
            if(fetched_user == NULL) {
                send_ERR_USERNOTINCHANNEL(ctx, conn, channel, msg->params[2]);
                return CHIRC_HANDLER_DISCONNECT;
            }

            chirc_channeluser_t *fetched_channeluser = chirc_channeluser_get(channel, mode_user);
            if(fetched_channeluser == NULL) {
                send_ERR_USERNOTINCHANNEL(ctx, conn, channel, nick);
                return CHIRC_HANDLER_DISCONNECT;
            }

            if (msg->params[1][0] == '+') {
                chirc_channeluser_set_mode(fetched_channeluser, mode);
            } else if (msg->params[1][0] == '-') {
                chirc_channeluser_remove_mode(fetched_channeluser, mode);
            }

            pthread_mutex_unlock(&ctx->user_lock);

            char *param_1 = msg->params[1];
            char *nick = fetched_user->nick;
            for (chirc_channeluser_t *u = channel->users; u != NULL; u = u->hh_from_channel.next) {
                /* Sending user MODE Message */
                chirc_message_t *msg = malloc(sizeof(chirc_message_t));
                if(chirc_message_construct(msg, conn->peer.user->nick, "MODE") != 0) {
                    chilog(CRITICAL, "Error creating message");
                    exit(-1);
                }
                chirc_message_add_parameter(msg, channel->name, false);
                chirc_message_add_parameter(msg, param_1, false);
                chirc_message_add_parameter(msg, nick, false);
                if(chirc_connection_send_message(ctx, u->user->conn, msg)) {
                    chirc_message_free(msg);
                    return CHIRC_HANDLER_DISCONNECT;
                }
            }
            return CHIRC_HANDLER_DISCONNECT;
        }
    } else {
        if (strchr(modes, mode) == NULL) {
            char m[2];
            m[0] = mode;
            m[1] = '\0';
            send_ERR_UNKNOWNMODE(ctx, conn, channel, m);
            return CHIRC_HANDLER_DISCONNECT;
        }
    }

    /* Locking mutex */
    pthread_mutex_lock(&channel->lock);

    bool send = false;

    /* Retrieving channeluser and checking that it exists */
    chirc_channeluser_t *channeluser;
    channeluser = chirc_channeluser_get(channel, conn->peer.user);

    if((msg->params[1][0] == '+' || msg->params[1][0] == '-') &&
            !chirc_channeluser_has_mode(channeluser, 'o') &&
            !chirc_user_has_mode(conn->peer.user, 'o')) {
        pthread_mutex_unlock(&channel->lock);
        send_ERR_CHANOPRIVSNEEDED(ctx, conn, channel);
        return CHIRC_HANDLER_DISCONNECT;
    }

    if(msg->params[1][0] == '+' && !chirc_channel_has_mode(channel, mode)) {
        chirc_channel_set_mode(channel, mode);
    } else if (msg->params[1][0] == '-') {
        chirc_channel_remove_mode(channel, mode);
    }

    if (!chirc_channel_has_mode(channel, mode) && msg->params[1][0] == '+') {
        chirc_channel_set_mode(channel, mode);
    }
    /* Unlocking mutex */
    pthread_mutex_unlock(&channel->lock);

    send_mode_messages(ctx, conn, channel, msg);

    return CHIRC_OK;
}


/*! \brief Specifically handles modes for user structs
 *
 * This is a helper function that is called in the main MODE handler
 * to specifically handle the scenarios necessary for users.
 *
 * \param ctx The server context
 * \param conn The connection
 * \param msg The MODE message
 */
int chirc_handle_user_MODE(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    char* modes = "aom";
    char mode = msg->params[1][1];

    if(strcmp(conn->peer.user->nick, msg->params[0]) != 0) {
        send_ERR_USERSDONTMATCH(ctx, conn, msg->params[0]);
        return CHIRC_HANDLER_DISCONNECT;
    }

    if (strchr(modes, mode) == NULL) {
        char m[2];
        m[0] = mode;
        m[1] = '\0';
        send_ERR_UMODEUNKNOWNFLAG(ctx, conn, m);
        return CHIRC_HANDLER_DISCONNECT;
    }

    /* Locking mutex */
    pthread_mutex_lock(&ctx->user_lock);

    if(msg->params[1][0] == '+' && !chirc_user_has_mode(conn->peer.user, mode)) {
        chirc_user_set_mode(conn->peer.user, mode);
    } else if (msg->params[1][0] == '-') {
        chirc_user_remove_mode(conn->peer.user, mode);
    }

    /* Unlocking mutex */
    pthread_mutex_unlock(&ctx->user_lock);

    send_user_MODE(ctx, conn, msg->params[1]);

    return CHIRC_OK;
}


int chirc_handle_MODE(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* Checking to see if the number of parameters is correct */
    if(msg->nparams < 1) {
        send_ERR_NEEDMOREPARAMS(ctx, conn, "MODE");
        return CHIRC_HANDLER_DISCONNECT;
    }

    char* modes = "aovmt";

    if(msg->nparams == 1 && msg->params[0][0] == '#') {
        chirc_channel_t *channel;
        channel = chirc_ctx_get_channel(ctx, msg->params[0]);
        if(channel == NULL) {
            send_ERR_NOSUCHCHANNEL(ctx, conn, msg->params[0]);
            return CHIRC_HANDLER_DISCONNECT;
        }
        send_RPL_CHANNELMODEIS(ctx, conn, channel->modes, channel);

    } else if (msg->params[0][0] == '#' || msg->params[1][0] == '#') {
        /* For channel modes specifically */
        chirc_handle_channel_MODE(ctx, conn, msg);
    } else if (strncmp(msg->params[1], "+o",2) != 0 &&
               strncmp(msg->params[1], "+a",2) != 0 &&
               strncmp(msg->params[1], "-a",2) != 0 ) {
        /* For user modes specifically */
        chirc_handle_user_MODE(ctx, conn, msg);
    }

    return CHIRC_OK;
}


int chirc_handle_OPER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* Checking to see if the number of parameters is correct */
    if(msg->nparams < 2) {
        send_ERR_NEEDMOREPARAMS(ctx, conn, "OPER");
        return CHIRC_HANDLER_DISCONNECT;
    }

    if(strncmp(ctx->oper_passwd, msg->params[1], strlen(ctx->oper_passwd)) != 0) {
        send_ERR_PASSWDMISMATCH(ctx, conn);
        return CHIRC_HANDLER_DISCONNECT;
    } else {
        /* Locking the mutex */
        pthread_mutex_lock(&ctx->user_lock);

        if(chirc_user_set_mode(conn->peer.user, 'o') != 0) {
            chilog(ERROR, "Error setting the mode");
            return CHIRC_HANDLER_DISCONNECT;
        }

        /* Unlocking the mutex */
        pthread_mutex_unlock(&ctx->user_lock);

        send_RPL_YOUREOPER(ctx, conn);
    }

    return CHIRC_OK;
}


int chirc_handle_AWAY(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* Remove 'a' mode */
    if(msg->nparams==0) {
        chirc_user_remove_mode(conn->peer.user, 'a');
        free(conn->peer.user->awaymsg);
        conn->peer.user->awaymsg = NULL;
        chirc_message_t reply;
        if(chirc_message_construct_reply(&reply, ctx, conn,RPL_UNAWAY)) {
            chilog(CRITICAL, "Error creating reply message");
            exit(-1);
        }
        chirc_message_add_parameter(&reply, "You are no longer marked as being away", 1);

        /* Send the message */
        if(chirc_connection_send_message(ctx, conn, &reply)!=0) {
            chirc_message_free(&reply);
            return CHIRC_HANDLER_DISCONNECT;
        }
        return CHIRC_OK;
    }

    /* Set a mode and message */
    chirc_user_set_mode(conn->peer.user, 'a');
    conn->peer.user->awaymsg = strndup(msg->params[0], strlen(msg->params[0]));

    /* Send reply message */
    chirc_message_t reply;
    if(chirc_message_construct_reply(&reply, ctx, conn,RPL_NOWAWAY)) {
        chilog(CRITICAL, "Error creating reply message");
        exit(-1);
    }
    chirc_message_add_parameter(&reply, "You have been marked as being away", 1);

    /* Send the message */
    if(chirc_connection_send_message(ctx, conn, &reply)) {
        chirc_message_free(&reply);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}


int chirc_handle_LIST(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* Handling for just listing all of the channels */
    if(msg->nparams == 0) {

        /* Iterating through all of the channels */
        for (chirc_channel_t *u = ctx->channels; u != NULL; u = u->hh.next) {
            send_RPL_LIST(ctx, conn, u);
        }
        send_RPL_LISTEND(ctx, conn);

    } else if (msg->nparams == 1) {
        /* Handle for just listing for a specific channel */
        chirc_channel_t *channel;
        channel = chirc_ctx_get_channel(ctx, msg->params[0]);
        if(channel == NULL) {
            send_ERR_NOSUCHCHANNEL(ctx, conn, msg->params[0]);
            return CHIRC_HANDLER_DISCONNECT;
        }
        send_RPL_LIST(ctx, conn, channel);
        send_RPL_LISTEND(ctx, conn);
    }

    return CHIRC_OK;
}


int chirc_handle_PASS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* Relay message back */
    if(msg->prefix!=NULL) {
        chirc_server_t *active_server = chirc_ctx_get_server(ctx,msg->prefix);
        if(active_server->conn != NULL) {
            chilog(CRITICAL, "server already registered");
            return CHIRC_OK;
        }
        chirc_server_t *server = malloc(sizeof(chirc_server_t));
        chirc_server_init(server);
        conn->peer.server= server;
        conn->type=CONN_TYPE_SERVER;
        server->conn = conn;
        conn->peer.server->passwd = sdsnew(msg->params[0]);
        return CHIRC_OK;
    }
    if(conn->type==CONN_TYPE_UNKNOWN) {
        chirc_server_t *server = malloc(sizeof(chirc_server_t));
        chirc_server_init(server);
        conn->peer.server= server;
        conn->type=CONN_TYPE_SERVER;
        server->conn = conn;
    }
    if(msg->nparams < 1) {
        send_ERR_NEEDMOREPARAMS(ctx,conn,"PASS");
    }
    conn->peer.server->passwd = sdsnew(msg->params[0]);

    /* Check if server was called */
    if(conn->peer.server->servername != NULL) {
        /* Attempting to register the ACTIVE SERVER */
        return chirc_register_server(ctx,conn);
    }
    return CHIRC_OK;
}


int chirc_handle_SERVER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    if(msg->prefix!=NULL) {
        chirc_server_t* active_server = chirc_ctx_get_server(ctx,msg->prefix);
        if(active_server->conn!=NULL) {
            chilog(CRITICAL, "server already registered");
            return CHIRC_OK;
        }
        /* Relay message sent back */
        conn->peer.server->servername=sdsnew(msg->params[0]);
        chirc_register_server(ctx,conn);
        return CHIRC_OK;
    }
    if(conn->type == CONN_TYPE_UNKNOWN) {
        chirc_server_t *server = malloc(sizeof(chirc_server_t));
        chirc_server_init(server);
        conn->peer.server=server;
        conn->type = CONN_TYPE_SERVER;
        server->conn = conn;
    }
    if(msg->nparams<1) {
        send_ERR_NEEDMOREPARAMS(ctx,conn,"SERVER");
    }
    conn->peer.server->servername=sdsnew(msg->params[0]);
    if(conn->peer.server->passwd != NULL) {
        /* Attempting to register the ACTIVE SERVER */
        return chirc_register_server(ctx,conn);
    }
    return CHIRC_OK;
}


int chirc_handle_CONNECT(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    /* Making sure the number of parameters is satisfied */
    if (msg->nparams < 2) {
        send_ERR_NEEDMOREPARAMS(ctx, conn, msg->cmd);
        return CHIRC_HANDLER_DISCONNECT;
    }

    /* Setting up socket + other vars */
    struct addrinfo hints, *res, *p;
    int status;
    int server_socket;

    /* Getting the server */
    chirc_server_t *ctx_server = chirc_ctx_get_server(ctx, msg->params[0]);
    /* Getting the server */
    if(ctx_server == NULL) {
        chilog(ERROR, "Could not find server");
        return send_ERR_NOSUCHSERVER(ctx, conn, msg->params[0]);
    }

    chirc_server_t *server = malloc(sizeof(chirc_server_t));
    chirc_server_init(server);
    server->hostname=sdsdup(ctx_server->hostname);
    server->passwd=sdsdup(ctx_server->passwd);
    server->port=sdsdup(ctx_server->port);
    server->servername=sdsdup(ctx_server->servername);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    /* Get the address information given the server host and port */
    if ((status = getaddrinfo(server->hostname, server->port, &hints, &res)) != 0) {
        chilog(CRITICAL, "getaddrinfo() failed: %s", gai_strerror(status));
        return CHIRC_HANDLER_DISCONNECT;
    }

    /* Looping through trying to connect */
    for (p = res; p != NULL; p = p->ai_next) {
        if ((server_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            chilog(ERROR, "Error assigning the socket");
            continue;
        }

        /* Trying to connect */
        if (connect(server_socket, p->ai_addr, p->ai_addrlen) == -1) {
            close(server_socket);
            chilog(ERROR, "Error with connect()");
            continue;
        }

        break;
    }

    if (p == NULL) {
        /* Connection failed */
        chilog(CRITICAL, "Failed to connect to any address");
        freeaddrinfo(res);
        return CHIRC_HANDLER_DISCONNECT;
    }

    freeaddrinfo(res);

    /* Creating the new connection */
    chirc_connection_t *new_conn = malloc(sizeof(chirc_connection_t));
    if (!new_conn) {
        chilog(ERROR, "Allocation for new connection failed");
        close(server_socket);
        return CHIRC_HANDLER_DISCONNECT;
    }

    /* Initializing the new connection */
    chirc_connection_init(new_conn);
    server->registered = true;
    server->conn = new_conn;
    new_conn->peer.server = server;
    new_conn->hostname = sdsdup(server->hostname);
    new_conn->port = sdsdup(server->port);
    new_conn->socket = server_socket;
    new_conn->type = CONN_TYPE_SERVER;

    ctx_server->conn = new_conn;
    ctx_server->registered=true;

    /* Sending Pass and Server Back */
    chirc_message_t *pass_msg = malloc(sizeof(chirc_message_t));
    chirc_message_construct(pass_msg,NULL,"PASS");
    chirc_message_add_parameter(pass_msg,ctx_server->passwd,false);
    chirc_message_add_parameter(pass_msg,"0210",false);
    chirc_message_add_parameter(pass_msg,"chirc|0.6",false);
    if(chirc_connection_send_message(ctx,new_conn,pass_msg) != 0)
        chilog(CRITICAL, "ERROR: unable to send pass message\n\n");
    chirc_message_free(pass_msg);

    chirc_message_t *server_msg = malloc(sizeof(chirc_message_t));
    chirc_message_construct(server_msg,NULL,"SERVER");
    chirc_message_add_parameter(server_msg,ctx->network.this_server->servername,false);
    chirc_message_add_parameter(server_msg,"1",0);
    chirc_message_add_parameter(server_msg,"1",0);
    chirc_message_add_parameter(server_msg,"chirc_server",1);
    if(chirc_connection_send_message(ctx,new_conn,server_msg) != 0)
        chilog(CRITICAL, "ERROR: unable to send server message\n\n");
    chirc_message_free(server_msg);


    chirc_connection_create_thread(ctx, new_conn);

    return CHIRC_OK;
}