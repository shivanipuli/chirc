/*! \file handlers.h
 *  \brief Message handlers
 *
 *  This module implements a dispatch table that provides a uniform
 *  interface for implementing the handling of each IRC command.
 *
 *  The only function that should be called from the rest of the call
 *  is chirc_handle which, based on the message to process, will dispatch
 *  it to the appropriate handler function.
 *
 *  See handler.c for details on how the dispatch table is implemented
 *  (and how to implement new commands)
 */

#ifndef HANDLERS_H_
#define HANDLERS_H_

#include "ctx.h"
#include "connection.h"
#include "message.h"

/*! Return code that indicates that the outcome of processing
 *  the message is that the server must close the connection
 *  (e.g., when receiving a QUIT message) */
#define CHIRC_HANDLER_DISCONNECT	(-42)

/*! \brief Process (handle) a message received by the server
 *
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return If the message was handled correctly, returns 0 (CHIRC_OK).
 *         In some commands, the expected outcome of the command is
 *         for the connection to be closed (e.g., the QUIT command)
 *         In those cases, chirc_handle will return -42 (CHIRC_HANDLER_DISCONNECT).
 *         If the handling of the message fails,  a non-zero value
 *         (other than -42) will be returned.
 */
int chirc_handle(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief command used to test active status of other connection. Returns 402(ERR_NOSUCHSERVER)
 * if no server matching target parameter was found. 
 *
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK) if handled correctly, otherwise -42 (CHIRC_HANDLER_DISCONNECT)
 */
int chirc_handle_PING(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief message reply to PING command. Responds with its own user/server identifier. Returns 
 * 402(ERR_NOSUCHSERVER) if no server matching target parameter was found. 
 *
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK) if handled correctly, otherwise -42 (CHIRC_HANDLER_DISCONNECT)
 */
int chirc_handle_PONG(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);


/*! \brief One of the commands needed for connection registration of a user. NICK command used to create
 * new nickname or change existing one. If an error occurs, sends back the following numeric replies 
 * to the user: ERR_NONICKNAMEGIVEN, ERR_ERRONEUSNICKNAME, ERR_NICKNAMEINUSE
 *
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return If successful, 0 (CHIRC_OK), otherwise -42 (CHIRC_HANDLER_DISCONNECT)
 */
int chirc_handle_NICK(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief One of the commands needed for connection registration of a user. USER command used to create
 * new username or change existing one. 
 *
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK) if handled correctly, otherwise -42 (CHIRC_HANDLER_DISCONNECT)
 */
int chirc_handle_USER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief Command sent by client when they want to terminate their session. 
 * Closes socket connection and client receives an error message in response.
 * 
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK) if handled correctly, otherwise -42 (CHIRC_HANDLER_DISCONNECT)
 */
int chirc_handle_QUIT(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief Command used to send private messages between users or to channels depending 
 * message parameters. If user is away, sends automatic reply set by user.
 * Sends one of the following errors if message was unable to sent: 
 * ERR_NORECIPIENT, ERR_NOTEXTTOSEND, ERR_CANNOTSENDTOCHAN, ERR_NOTOPLEVEL, ERR_WILDTOPLEVEL,
 * ERR_TOOMANYTARGETS, ERR_NOSUCHNICK, RPL_AWAY
 * 
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK) if handled correctly, otherwise -42 (CHIRC_HANDLER_DISCONNECT)
 */
int chirc_handle_PRIVMSG(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief Command used to send messages between users and channels like PRIVMSG. 
 * However, no automatic replies are sent in response. Sends one of the following error
 * messages back to user if error occurs: ERR_NORECIPIENT, ERR_NOTEXTTOSEND, ERR_CANNOTSENDTOCHAN, 
 * ERR_NOTOPLEVEL, ERR_WILDTOPLEVEL, ERR_TOOMANYTARGETS, ERR_NOSUCHNICK, RPL_AWAY
 * 
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK) if handled correctly, otherwise -42 (CHIRC_HANDLER_DISCONNECT)
 */
int chirc_handle_NOTICE(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief Command to give "Message of the Day" of the target server or current server if
 * no server is given. Possible numeric replies given to the user are the following:
 * RPL_MOTDSTART, RPL_MOTD, RPL_ENDOFMOT, ERR_NOMOTD
 * 
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK) if handled correctly, otherwise -42 (CHIRC_HANDLER_DISCONNECT)
 */
int chirc_handle_MOTD(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);


/*! \brief Command to give the stats on the size of the network. If server is found, 
 * gives the following numeric replies: RPL_LUSERCLIENT, RPL_LUSEROP, RPL_LUSERUNKOWN,
 * RPL_LUSERCHANNELS, RPL_LUSERME. If server is not found, replies with 402(ERR_NOSUCHSERVER). 
 * 
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK) if handled correctly, otherwise -42 (CHIRC_HANDLER_DISCONNECT)
 */
int chirc_handle_LUSERS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief Command used to query information about the target. The server will respond with
 * different replies indicating different server statuses. Based on the target parameter, 
 * the server will send back one of the following: RPL_WHOISUSER, RPL_WHOISCHANNELS, 
 * RPL_WHOISCHANNEL, RPL_WHOISSERVER, RPL_AWAY, RPL_WHOISOPERATOR, RPL_WHOISIDLE, RPL_ENDOFWHOIS.
 * If an error occurs, server sends back 402(ERR_NOSUCHSERVER) if no server matching target found, 
 * or 431 (ERR_NONICKNAMEGIVEN) if no nickname given to the user.
 * 
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK) otherwise -42 (CHIRC_HANDLER_DISCONNECT).
 */
int chirc_handle_WHOIS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief Commmand used to join a channel. Will create a new channeluser if one does not
 * exist and will also create a new channel if one does not exist for the channeluser to join.
 * Will send ERR_NEEDMOREPARAMS if there are not enough parameters passed in.
 *
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK)
 */
int chirc_handle_JOIN(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief Command used to leave a channel. Will also delete the channel if there 
 * are no users left in the channel. Will send ERR_NEEDMOREPARAMS if there is not
 * at least 1 parameter, will send ERR_NOSUCHCHANNEL if the channel does not exist,
 * and will send ERR_NOTONCHANNEL if the channeluser is not in the specified channel.
 *
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK) if handled correctly, otherwise -42 (CHIRC_HANDLER_DISCONNECT)
 */
int chirc_handle_PART(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief Command used to handle the modes that are assigned for channels and for
 * users. This controls when to go into the two helper functions, one for channels
 * specifically and the other for users. If the channel is null, ERR_NOSUCHCHANNEL
 * will be sent.
 *
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK) if handled correctly, otherwise -42 (CHIRC_HANDLER_DISCONNECT)
 */
int chirc_handle_MODE(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief Command used to control the operator status for users within a channel. 
 * Calling this is the only way that a user can gain access to operator status. T
 * will send ERR_NEEDMOREPARAMS if there are not at least 2 parameters in the msg and
 * it will send ERR_PASSWDMISMATCh if the password given does not match the  operator 
 * password from the server context. 
 *
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK) if handled correctly, otherwise -42 (CHIRC_HANDLER_DISCONNECT)
 */
int chirc_handle_OPER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief Command used to control the status of when a user is away from the IRC 
 * server. Will attempt to set the mode to away for the user when called.
 *
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK) if handled correctly, otherwise -42 (CHIRC_HANDLER_DISCONNECT)
 */
int chirc_handle_AWAY(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief Command used to list all of the channels. It will send a reply with the
 * list of all of the channels. If there is only 1 parameter in the message, then
 * it will attempt to get the channel and if it does not exist then it will send
 * ERR_NOSUCHCHANNEL.
 *
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK) if handled correctly, otherwise -42 (CHIRC_HANDLER_DISCONNECT)
 */
int chirc_handle_LIST(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief Command used to in the initiation of a server connection. Will send an
 * ERR_NEEDMOREPARAMS if the message has less than 1 parameter, and it will also 
 * function in different ways depending on the connection type.
 *
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK) if handled correctly, otherwise -42 (CHIRC_HANDLER_DISCONNECT)
 */
int chirc_handle_PASS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief Command also used in the initiation of a server connection. It will check
 * the active server, then it will ensure that the conenction isn't NULL. If so, 
 * then it will register the server. If the message does not contain at least one 
 * parameter, then the function will return ERR_NEEDMOREPARAMS.
 *
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK)
 */
int chirc_handle_SERVER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief CONNECT will connect two servers together. This is done first by checking 
 * the number of parameters, and if there are less than 2 then it will return 
 * ERR_NEEDMOREPARAMS, then it will attempt to get the active server. If it fails
 * during this step, then it will send ERR_NOSUCHSERVER. Then it will do some 
 * intiialization, and if it fails to connect using the socket function connect()
 * then it will close the server socket. 
 *
 * \param ctx Server context
 * \param conn Connection the message arrived through
 * \param msg The message to process
 * \return 0 (CHIRC_OK) if handled correctly, otherwise -42 (CHIRC_HANDLER_DISCONNECT)
 */
int chirc_handle_CONNECT(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

#endif /* HANDLERS_H_ */
