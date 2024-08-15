/* See send.h for details about the functions in this module */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <netdb.h>
#include "chirc.h"
#include "ctx.h"
#include "log.h"
#include "connection.h"
#include "user.h"
#include "message.h"
#include "handlers.h"
#include "reply.h"

/* See send.h */
int send_RPL_WELCOME(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending RPL_WELCOME */
    chirc_message_t *new_msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(new_msg,
                                     ctx,
                                     conn,
                                     RPL_WELCOME) != 0) {
        chilog(CRITICAL, "Error creating reply message");
        exit(-1);
    }

    char long_str[100];
    sprintf(long_str,
            "Welcome to the Internet Relay Network %s!%s@%s",
            conn->peer.user->nick,
            conn->peer.user->username, conn->hostname);

    chirc_message_add_parameter(new_msg, long_str, true);
    if (chirc_connection_send_message(ctx, conn, new_msg) != 0) {
        chirc_message_free(new_msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}

/* See send.h */
int send_RPL_YOURHOST(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending RPL_YOURHOST */
    chirc_message_t *your_host_msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(your_host_msg, ctx, conn, RPL_YOURHOST) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }

    char message_str[100];
    sprintf(message_str, "Your host is %s, running version %s", ctx->network.this_server->servername, ctx->version);
    chirc_message_add_parameter(your_host_msg, message_str, true);
    if(chirc_connection_send_message(ctx, conn, your_host_msg) != 0) {
        chirc_message_free(your_host_msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}

/* See send.h */
int send_RPL_CREATED(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending RPL_CREATED */
    chirc_message_t *created_msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(created_msg, ctx, conn, RPL_CREATED) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }

    char create_str[100];
    sprintf(create_str, "This server was created %s", asctime(&ctx->created));

    chirc_message_add_parameter(created_msg, create_str, true);
    if(chirc_connection_send_message(ctx, conn, created_msg) != 0) {
        chirc_message_free(created_msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}

/* See send.h */
int send_RPL_MYINFO(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending RPL_MYINFO */
    chirc_message_t *my_info_msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(my_info_msg, ctx, conn, RPL_MYINFO) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }

    chirc_message_add_parameter(my_info_msg, ctx->network.this_server->servername, false);
    chirc_message_add_parameter(my_info_msg, ctx->version, false);
    chirc_message_add_parameter(my_info_msg, "ao", false);
    chirc_message_add_parameter(my_info_msg, "mtov", false);
    if(chirc_connection_send_message(ctx, conn, my_info_msg ) != 0) {
        chirc_message_free(my_info_msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}

/* See send.h */
int send_RPL_LUSERCLIENT(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending the RPL_LUSERCLIENT reply */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, RPL_LUSERCLIENT) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }

    char str[50];
    sprintf(str, "There are %d users and 0 services on %d servers", chirc_ctx_numusers(ctx), chirc_ctx_numservers(ctx));
    chirc_message_add_parameter(msg, str, true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}

/* See send.h */
int send_RPL_LUSEROP(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending the RPL_LUSEROP reply */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, RPL_LUSEROP) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    char str[10];
    sprintf(str, "%d", chirc_ctx_numops(ctx));
    chirc_message_add_parameter(msg, str, false);
    chirc_message_add_parameter(msg, "operator(s) online", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int send_RPL_LUSERUNKNOWN(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending the RPL_LUSERUNKNOWN reply */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, RPL_LUSERUNKNOWN) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    char str[10];
    sprintf(str, "%d", chirc_ctx_unknown_connections(ctx));
    chirc_message_add_parameter(msg, str, false);
    chirc_message_add_parameter(msg, "unknown connection(s)", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int send_RPL_LUSERCHANNELS(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending the RPL_LUSERCHANNELS reply */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, RPL_LUSERCHANNELS) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    char str[10];
    sprintf(str, "%d", chirc_ctx_numchannels(ctx));
    chirc_message_add_parameter(msg, str, false);
    chirc_message_add_parameter(msg, "channels formed", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int send_RPL_LUSERME(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending the RPL_LUSERME reply */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, RPL_LUSERME) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    char str[50];

    int count = 0;
    for(chirc_user_t *u = ctx->users; u != NULL; u = u->hh.next) {
        if(strncmp(u->server->servername, ctx->network.this_server->servername, strlen(u->server->servername)) == 0) {
            count++;
        }
    }

    sprintf(str, "I have %d clients and 1 servers", count);
    chirc_message_add_parameter(msg, str, true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int send_RPL_WHOISUSER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_user_t *user)
{
    /* Sending the RPL_WHOISUSER reply */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, RPL_WHOISUSER) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, user->nick, false);
    chirc_message_add_parameter(msg, user->username, false);

    char *hostname = user->hostname;
    chirc_message_add_parameter(msg, hostname, false);
    chirc_message_add_parameter(msg, "*", false);
    char str[50];
    sprintf(str, "%s", user->fullname);
    chirc_message_add_parameter(msg, str, true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}

/* See send.h */
int send_RPL_WHOISSERVER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_user_t *user)
{
    /* Sending the RPL_WHOISSERVER reply */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, RPL_WHOISSERVER) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }

    chirc_message_add_parameter(msg, user->nick, false);
    chirc_message_add_parameter(msg, user->server->servername, false);
    /* Hard coding this because I am not sure what to add here */
    chirc_message_add_parameter(msg, "SERVER INFO", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}


/* See send.h */
int send_RPL_ENDOFWHOIS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_user_t *user)
{
    /* Sending the RPL_ENDOFWHOIS reply */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, RPL_ENDOFWHOIS) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, user->nick, false);
    chirc_message_add_parameter(msg, "End of WHOIS list", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}

/* See send.h */
int send_RPL_NAMREPLY(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending the RPL_NAMREPLY reply */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, RPL_NAMREPLY) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, conn->peer.user->nick, false);
    chirc_message_add_parameter(msg, "foobar", false);

    /* Hard coding */
    chirc_message_add_parameter(msg, "NAMES NOT IMPLEMENTED", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}

/* See send.h */
int send_RPL_ENDOFNAMES(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending the RPL_ENDOFNAMES reply */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, RPL_ENDOFNAMES) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, conn->peer.user->nick, false);

    /* Hard coding */
    chirc_message_add_parameter(msg, "NAMES NOT IMPLEMENTED", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}

/* See send.h */
int send_RPL_YOUREOPER(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending RPL_YOUREOPER Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, RPL_YOUREOPER) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, "You are now an IRC operator", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}

/* See send.h */
int send_RPL_CHANNELMODEIS(chirc_ctx_t *ctx, chirc_connection_t *conn, char *modes, chirc_channel_t *channel)
{
    /* Sending RPL_CHANNELMODEIS Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, RPL_CHANNELMODEIS) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, channel->name, false);
    char s[20];
    sprintf(s, "+%s", modes);
    chirc_message_add_parameter(msg, s, false);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}

/* See send.h */
int send_RPL_LIST(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel)
{
    /* Sending RPL_LIST Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, RPL_LIST) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, channel->name, false);

    /* Dealing with getting number of users */
    int users = chirc_ctx_numchannelusers(channel);
    char users_str[12];
    sprintf(users_str, "%d", users);
    chirc_message_add_parameter(msg, users_str, false);

    /* Adding a placeholder since we aren't actually implementing topic */
    chirc_message_add_parameter(msg, "TOPIC", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}

/* See send.h */
int send_RPL_LISTEND(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending RPL_LIST_END Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, RPL_LISTEND) != 0) {
        chilog(CRITICAL, "Error creating message");
        return CHIRC_HANDLER_DISCONNECT;
    }
    chirc_message_add_parameter(msg, "End of LIST", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}


/* See send.h */
int send_ERR_NONICKNAMEGIVEN(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending ERR_NONICKNAMEGIVEN Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_NONICKNAMEGIVEN) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, "No nickname given", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int send_ERR_NICKNAMEINUSE(chirc_ctx_t *ctx, chirc_connection_t *conn, char *nick)
{
    /* Sending ERR_NICKNAMEINUSE Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_NICKNAMEINUSE) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, nick, false);
    chirc_message_add_parameter(msg, "Nickname is already in use", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}

/* See send.h */
int send_ERR_ALREADYREGISTRED(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending ERR_ALREADYREGISTRED Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_ALREADYREGISTRED) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, "You may not reregister", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}

/* See send.h */
int send_ERR_NEEDMOREPARAMS(chirc_ctx_t *ctx, chirc_connection_t *conn, char *param)
{
    /* Sending ERR_NEEDMOREPARAMS Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_NEEDMOREPARAMS) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, param, false);
    chirc_message_add_parameter(msg, "Not enough parameters", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}

/* See send.h */
int send_ERR_NOTREGISTERED(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending ERR_NOTREGISTERED Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_NOTREGISTERED) != 0) {
        chilog(CRITICAL, "Error creating message");
        return CHIRC_HANDLER_DISCONNECT;
    }
    chirc_message_add_parameter(msg, "You have not registered", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }

    return CHIRC_OK;
}

/* See send.h */
int send_ERR_NORECIPIENT(chirc_ctx_t *ctx, chirc_connection_t *conn, char *cmd)
{
    /* Sending ERR_NORECIPIENT Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_NORECIPIENT) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    char msg_str[514];
    sprintf(msg_str, "No recipient given (%s)", cmd);
    chirc_message_add_parameter(msg, msg_str, true);
    chirc_connection_send_message(ctx, conn, msg);
    return CHIRC_OK;
}

/* See send.h */
int send_ERR_NOTEXTTOSEND(chirc_ctx_t *ctx, chirc_connection_t *conn, char *cmd)
{
    /* Sending ERR_NOTEXTTOSEND Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_NOTEXTTOSEND) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, "No text to send", true);
    chirc_connection_send_message(ctx, conn, msg);
    return CHIRC_OK;
}

/* See send.h */
int send_ERR_NOSUCHNICK(chirc_ctx_t *ctx, chirc_connection_t *conn, char *nick)
{
    /* Sending ERR_NOSUCHNICK Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_NOSUCHNICK) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, nick, false);
    chirc_message_add_parameter(msg, "No such nick/channel", true);
    chirc_connection_send_message(ctx, conn, msg);
    return CHIRC_OK;
}

/* See send.h */
int send_ERR_UNKNOWNCOMMAND(chirc_ctx_t *ctx, chirc_connection_t *conn, char *cmd)
{
    /* Sending UNKNOWNCOMMAND Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_UNKNOWNCOMMAND) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, cmd, false);
    chirc_message_add_parameter(msg, "Unknown command", true);
    chirc_connection_send_message(ctx, conn, msg);
    return CHIRC_OK;
}

/* See send.h */
int send_ERR_NOSUCHSERVER(chirc_ctx_t *ctx, chirc_connection_t *conn, char *servername)
{
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_NOSUCHSERVER) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, servername, false);
    chirc_message_add_parameter(msg, "No such server", true);
    chirc_connection_send_message(ctx, conn, msg);
    return CHIRC_OK;
}

/* See send.h */
int send_ERR_NOMOTD(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending ERR_NOMOTD Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_NOMOTD) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, "MOTD File is missing", true);
    chirc_connection_send_message(ctx, conn, msg);
    return CHIRC_OK;
}

/* See send.h */
int send_ERR_NOTONCHANNEL(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel)
{
    /* Sending ERR_NOTONCHANNEL Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_NOTONCHANNEL) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, channel->name, false);
    chirc_message_add_parameter(msg, "You're not on that channel", true);
    chirc_connection_send_message(ctx, conn, msg);
    return CHIRC_OK;
}

/* See send.h */
int send_ERR_NOSUCHCHANNEL(chirc_ctx_t *ctx, chirc_connection_t *conn, char *channel_name)
{
    /* Sending ERR_NOSUCHCHANNEL Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_NOSUCHCHANNEL) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, channel_name, false);
    chirc_message_add_parameter(msg, "No such channel", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int send_ERR_CANNOTSENDTOCHAN(chirc_ctx_t *ctx, chirc_connection_t *conn, char *channel_name)
{
    /* Sending ERR_CANNOTSENDTOCHAN Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_CANNOTSENDTOCHAN) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, channel_name, false);
    chirc_message_add_parameter(msg, "Cannot send to channel", true);
    if(chirc_connection_send_message(ctx, conn, msg) != 0) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int send_ERR_PASSWDMISMATCH(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending ERR_PASSWDMISMATCH Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_PASSWDMISMATCH) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, "Password incorrect", true);
    if(chirc_connection_send_message(ctx, conn, msg)) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int send_ERR_USERNOTINCHANNEL(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel, char *nick)
{
    /* Sending ERR_USERNOTINCHANNEL Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_USERNOTINCHANNEL) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, nick, false);
    chirc_message_add_parameter(msg, channel->name, false);
    chirc_message_add_parameter(msg, "They aren't on that channel", true);
    if(chirc_connection_send_message(ctx, conn, msg)) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int send_ERR_UNKNOWNMODE(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel, char *mode)
{
    /* Sending ERR_UNKNOWNMODE Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_UNKNOWNMODE) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, mode, false);
    char msg_str[512];
    sprintf(msg_str, "is unknown mode char to me for %s", channel->name);
    chirc_message_add_parameter(msg, msg_str, true);

    if(chirc_connection_send_message(ctx, conn, msg)) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int send_ERR_UMODEUNKNOWNFLAG(chirc_ctx_t *ctx, chirc_connection_t *conn, char *mode)
{
    /* Sending ERR_UMODEUNKNOWNFLAG Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_UMODEUNKNOWNFLAG) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }

    chirc_message_add_parameter(msg, "Unknown MODE flag", true);
    if(chirc_connection_send_message(ctx, conn, msg)) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int send_ERR_USERSDONTMATCH(chirc_ctx_t *ctx, chirc_connection_t *conn, char *nick)
{
    /* Sending ERR_USERSDONTMATCH Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_USERSDONTMATCH) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }

    chirc_message_add_parameter(msg, "Cannot change mode for other users", true);
    if(chirc_connection_send_message(ctx, conn, msg)) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

int send_ERR_CHANOPRIVSNEEDED(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel)
{
    /* Sending ERR_CHANOPRIVSNEEDED Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct_reply(msg, ctx, conn, ERR_CHANOPRIVSNEEDED) != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, channel->name, false);
    chirc_message_add_parameter(msg, "You're not channel operator", true);
    if(chirc_connection_send_message(ctx, conn, msg)) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int send_JOIN(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel, char *nick)
{
    /* Sending JOIN Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct(msg, nick, "JOIN") != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, channel->name, false);
    if(chirc_connection_send_message(ctx, conn, msg)) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

int send_NICKCHANGED(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_connection_t *rec, char *nick)
{
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct(msg, conn->peer.user->nick, "NICK")!=0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, nick, true);
    if(!chirc_connection_send_message(ctx, rec, msg)) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int send_PART(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel, char *nick, char *part_msg)
{
    /* Sending PART Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct(msg, nick, "PART") != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }

    chirc_message_add_parameter(msg, channel->name, false);

    /* Addding the parting message to the message if it exists */
    if(part_msg != NULL) {
        chirc_message_add_parameter(msg, part_msg, true);
    }
    if(chirc_connection_send_message(ctx, conn, msg)) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int send_user_MODE(chirc_ctx_t *ctx, chirc_connection_t *conn, char *mode)
{
    /* Sending user MODE Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct(msg, conn->peer.user->nick, "MODE") != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, conn->peer.user->nick, false);
    chirc_message_add_parameter(msg, mode, true);
    if(chirc_connection_send_message(ctx, conn, msg)) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int send_channel_MODE(chirc_ctx_t *ctx, chirc_connection_t *conn, char *nick, char *param_1, char *mode)
{
    /* Sending user MODE Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct(msg, nick, "MODE") != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, param_1, false);
    chirc_message_add_parameter(msg, mode, false);
    if(chirc_connection_send_message(ctx, conn, msg)) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int send_SERVER_NICK(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_user_t *user)
{
    /* Sending server NICK Message */
    chirc_message_t *msg = malloc(sizeof(chirc_message_t));
    if(chirc_message_construct(msg, ctx->network.this_server->servername, "NICK") != 0) {
        chilog(CRITICAL, "Error creating message");
        exit(-1);
    }
    chirc_message_add_parameter(msg, user->nick, false);
    chirc_message_add_parameter(msg, "1", false);
    chirc_message_add_parameter(msg, user->username, false);
    chirc_message_add_parameter(msg, user->hostname, false);
    chirc_message_add_parameter(msg, "1", false);
    chirc_message_add_parameter(msg, "+", false);
    chirc_message_add_parameter(msg, user->fullname, true);
    if(chirc_connection_send_message(ctx, conn, msg)) {
        chirc_message_free(msg);
        return CHIRC_HANDLER_DISCONNECT;
    }
    return CHIRC_OK;
}

/* See send.h */
int chirc_welcome_messages(chirc_ctx_t *ctx, chirc_connection_t *conn)
{
    /* Sending all of the required welcome messages in order */
    send_RPL_WELCOME(ctx, conn);
    send_RPL_YOURHOST(ctx, conn);
    send_RPL_CREATED(ctx, conn);
    send_RPL_MYINFO(ctx, conn);
    send_RPL_LUSERCLIENT(ctx, conn);
    send_RPL_LUSEROP(ctx, conn);
    send_RPL_LUSERUNKNOWN(ctx, conn);
    send_RPL_LUSERCHANNELS(ctx, conn);
    send_RPL_LUSERME(ctx, conn);
    send_ERR_NOMOTD(ctx, conn);

    return CHIRC_OK;
}

/* See send.h */
int send_join_messages(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel, char *nick)
{
    for (chirc_channeluser_t *u = channel->users; u != NULL; u = u->hh_from_channel.next) {
        if (strcmp(u->user->nick, nick) != 0 && strcmp(u->user->server->servername, ctx->network.this_server->servername) == 0) {
            send_JOIN(ctx, u->user->conn, channel, nick);
        }
    }

    /* Sending JOIN to other servers */
    for(chirc_connection_t *c = ctx->connections; c != NULL; c=c->hh.next) {
        if(c->type == CONN_TYPE_SERVER && strcmp(c->peer.server->servername, conn->peer.server->servername) != 0) {
            send_JOIN(ctx, c, channel, nick);
        }
    }

    return CHIRC_OK;
}

/* See send.h */
int send_quit_messages(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg)
{
    char hostname[100];
    gethostname(hostname, sizeof(hostname));
    chirc_message_t quit_msg;
    if(chirc_message_construct(&quit_msg, conn->peer.user->nick, "QUIT") != 0) {
        chilog(CRITICAL, "Error creating yourhost message");
        exit(-1);
    }
    if(msg->nparams == 1)
        chirc_message_add_parameter(&quit_msg, msg->params[0], true);
    else
        chirc_message_add_parameter(&quit_msg, "Client Quit", true);

    /* For every channel user is connected to */
    for(chirc_channeluser_t* channel_user = conn->peer.user->channels; channel_user!=NULL; channel_user = channel_user->hh_from_user.next) {
        chirc_channel_t* channel = channel_user->channel;

        /* For every user in the channel */
        for (chirc_channeluser_t *u = channel->users; u != NULL; u = u->hh_from_channel.next) {

            /* Sending quit message */
            if(strncmp(u->user->nick, conn->peer.user->nick, strlen(u->user->nick))!=0)
                if(chirc_connection_send_message(ctx, u->user->conn, &quit_msg) != 0) {
                    chilog(CRITICAL, "\n\n ERROR: unable to send quit message\n\n");
                }
        }
    }
    return CHIRC_OK;
}

/* See send.h */
int send_privmsg_messages(chirc_ctx_t *ctx, chirc_channel_t *channel, char *sender_nick, chirc_message_t *msg)
{
    for (chirc_channeluser_t *u = channel->users; u != NULL; u = u->hh_from_channel.next) {
        if(strcmp(u->user->nick, sender_nick) != 0 && strcmp(u->user->server->servername, ctx->network.this_server->servername) == 0) {
            chirc_message_t new_msg;
            chirc_message_construct(&new_msg, sender_nick, "PRIVMSG");
            chirc_message_add_parameter(&new_msg, msg->params[0], false);
            chirc_message_add_parameter(&new_msg, msg->params[1], true);
            if(chirc_connection_send_message(ctx, u->user->conn, &new_msg)) {
                chirc_message_free(&new_msg);
                return CHIRC_HANDLER_DISCONNECT;
            }
        }
    }
    return CHIRC_OK;
}

/* See send.h */
int send_part_messages(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel, char *nick, char *part_msg)
{
    /* Going through the users hash table and checking if already registered */
    for (chirc_channeluser_t *u = channel->users; u != NULL; u = u->hh_from_channel.next) {
        send_PART(ctx, u->user->conn, channel, nick, part_msg);
    }
    return CHIRC_OK;
}

/* See send.h */
int send_mode_messages(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel, chirc_message_t *msg)
{
    char *nick = conn->peer.user->nick;
    for (chirc_channeluser_t *u = channel->users; u != NULL; u = u->hh_from_channel.next) {
        send_channel_MODE(ctx, u->user->conn, nick, msg->params[0], msg->params[1]);
    }
    return CHIRC_OK;
}