/*! \file send.h
 *  \brief RPL and ERR sending functions */

#ifndef SEND_H_
#define SEND_H_

#include "chirc.h"

/* REPLY MESSAGES */

/*! \brief The RPL_WELCOME message sent back to a user when their nick/user
 * finishes registration to a server
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_RPL_WELCOME(chirc_ctx_t *ctx, chirc_connection_t *conn);


/*! \brief The RPL_YOURHOST message sent back to a user when their nick/user
 * finishes registration to a server. Gives information about host new connection
 * host
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_RPL_YOURHOST(chirc_ctx_t *ctx, chirc_connection_t *conn);


/*! \brief Sends RPL_CREATED message sent back when new connection is registered.
 * Gives information about server created
 * 
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_RPL_CREATED(chirc_ctx_t *ctx, chirc_connection_t *conn);


/*! \brief Sends RPL_MYINFO message back to user connection.
 * Gives information user and channel modes available to new client
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_RPL_MYINFO(chirc_ctx_t *ctx, chirc_connection_t *conn);


/*! \brief Sends RPL_LUSERCLIENT message
 * Tells the user how many other users, services, and servers are connected to the irc
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_RPL_LUSERCLIENT(chirc_ctx_t *ctx, chirc_connection_t *conn);


/*! \brief Sends RPL_LUSEROP message. Gives information on whether an ircop is registered and online
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_RPL_LUSEROP(chirc_ctx_t *ctx, chirc_connection_t *conn);


/*! \brief Sends RPL_LUSERUNKNOWN message. Sends to user connection information on number of unknown users.
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_RPL_LUSERUNKNOWN(chirc_ctx_t *ctx, chirc_connection_t *conn);


/*! \brief Sends RPL_LUSERCHANNELS message. Gives information on the number of channels in the irc.
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_RPL_LUSERCHANNELS(chirc_ctx_t *ctx, chirc_connection_t *conn);


/*! \brief Sends RPL_LUSERME message. 
 * Gives server information on the number of users the current server has
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_RPL_LUSERME(chirc_ctx_t *ctx, chirc_connection_t *conn);


/*! \brief Sends RPL_WHOISUSER message. Responds to sender with information on the targeted user.
 * Sends back nick, user, host, and server of the target user.
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param user The nick user
 */
int send_RPL_WHOISUSER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_user_t *user);


/*! \brief Sends RPL_WHOISSERVER message. Responds with information of the server the target user is on
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param user The nick user
 */
int send_RPL_WHOISSERVER(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_user_t *user);


/*! \brief Sends RPL_ENDOFWHOIS message. Last response at the end of a WHOIS command call.
 * Signals to the user that all information on from the call has been sent.
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param user The nick user
 */
int send_RPL_ENDOFWHOIS(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_user_t *user);

/*! \brief Sends RPL_TOPIC message
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_RPL_TOPIC(chirc_ctx_t *ctx, chirc_connection_t *conn);

/*! \brief Sends RPL_NAMREPLY message
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_RPL_NAMREPLY(chirc_ctx_t *ctx, chirc_connection_t *conn);

/*! \brief Sends RPL_ENDOFNAMES message
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_RPL_ENDOFNAMES(chirc_ctx_t *ctx, chirc_connection_t *conn);

/*! \brief Sends RPL_YOUREOPER message
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_RPL_YOUREOPER(chirc_ctx_t *ctx, chirc_connection_t *conn);

/*! \brief Sends RPL_CHANNELMODEIS message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param mode The actual mode being implemented
 * \param channel The channel for information
 */
int send_RPL_CHANNELMODEIS(chirc_ctx_t *ctx, chirc_connection_t *conn, char *modes, chirc_channel_t *channel);

/*! \brief Sends RPL_LIST message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param channel The channel for information
 */
int send_RPL_LIST(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel);

/*! \brief Sends RPL_LISTEND message
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_RPL_LISTEND(chirc_ctx_t *ctx, chirc_connection_t *conn);


/* ERROR MESSAGES */

/*! \brief Sends ERR_NONICKNAMEGIVEN message
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_ERR_NONICKNAMEGIVEN(chirc_ctx_t *ctx, chirc_connection_t *conn);

/*! \brief Sends ERR_NICKNAMEINUSE message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param nick The nickname
 */
int send_ERR_NICKNAMEINUSE(chirc_ctx_t *ctx, chirc_connection_t *conn, char *nick);

/*! \brief Sends ERR_ALREADYREGISTRED message
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_ERR_ALREADYREGISTRED(chirc_ctx_t *ctx, chirc_connection_t *conn);

/*! \brief Sends ERR_NEEDMOREPARAMS message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param param The parameter for space #2
 */
int send_ERR_NEEDMOREPARAMS(chirc_ctx_t *ctx, chirc_connection_t *conn, char *param);

/*! \brief Sends ERR_NOTREGISTERED message
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_ERR_NOTREGISTERED(chirc_ctx_t *ctx, chirc_connection_t *conn);

/*! \brief Sends ERR_NORECIPIENT message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param cmd The command
 */
int send_ERR_NORECIPIENT(chirc_ctx_t *ctx, chirc_connection_t *conn, char *cmd);

/*! \brief Sends ERR_NOTEXTTOSEND message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param cmd The command
 */
int send_ERR_NOTEXTTOSEND(chirc_ctx_t *ctx, chirc_connection_t *conn, char *cmd);

/*! \brief Sends ERR_NOSUCHNICK message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param nick The nickname
 */
int send_ERR_NOSUCHNICK(chirc_ctx_t *ctx, chirc_connection_t *conn, char *nick);

/*! \brief Sends ERR_UNKNOWNCOMMAND message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param cmd The command
 */
int send_ERR_UNKNOWNCOMMAND(chirc_ctx_t *ctx, chirc_connection_t *conn, char *cmd);

/*! \brief Sends ERR_NOMOTD message
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_ERR_NOMOTD(chirc_ctx_t *ctx, chirc_connection_t *conn);

/*! \brief Sends ERR_NOTONCHANNEL message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param channel The channel to check
 */
int send_ERR_NOTONCHANNEL(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel);

/*! \brief Sends ERR_NOSUCHCHANNEL message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param channel_name The channel name that doesn't exist
 */
int send_ERR_NOSUCHCHANNEL(chirc_ctx_t *ctx, chirc_connection_t *conn, char *channel_name);

/*! \brief Sends ERR_CANNOTSENDTOCHAN message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param channel_name The channel name that doesn't exist
 */
int send_ERR_CANNOTSENDTOCHAN(chirc_ctx_t *ctx, chirc_connection_t *conn, char *channel_name);

/*! \brief Sends ERR_PASSWDMISMATCH message
 *
 * \param ctx Server context
 * \param conn The connection to add
 */
int send_ERR_PASSWDMISMATCH(chirc_ctx_t *ctx, chirc_connection_t *conn);

/*! \brief Sends ERR_USERNOTINCHANNEL message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param channel The channel that is being checked
 * \param nick The nickname of the user being checked
 */
int send_ERR_USERNOTINCHANNEL(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel, char *nick);

/*! \brief Sends ERR_UNKNOWNMODE message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param channel The channel name
 * \param mode The unknown mode
 */
int send_ERR_UNKNOWNMODE(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel, char *mode);

/*! \brief Sends ERR_UMODEUNKNOWNFLAG message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param mode The unknown mode
 */
int send_ERR_UMODEUNKNOWNFLAG(chirc_ctx_t *ctx, chirc_connection_t *conn, char *mode);

/*! \brief Sends ERR_USERSDONTMATCH message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param nick The nickname to compare against
 */
int send_ERR_USERSDONTMATCH(chirc_ctx_t *ctx, chirc_connection_t *conn,  char *nick);

/*! \brief Sends ERR_USERSDONTMATCH message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param channel The relevant channel
 */
int send_ERR_CHANOPRIVSNEEDED(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel);

/*! \brief Sends ERR_USERSDONTMATCH message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param servername The servername
 */
int send_ERR_NOSUCHSERVER(chirc_ctx_t *ctx, chirc_connection_t *conn, char *servername);

/* Regular Messages */

/*! \brief Sends JOIN message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param channel The channel in which you are sending messages 
 * \param nick The nickname parameter
 */
int send_JOIN(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel, char *nick);

/*! \brief Sends PART message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param channel The channel in which you are sending messages 
 * \param nick The nickname parameter
 * \param part_msg The parting message
 */
int send_PART(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel, char *nick, char *part_msg);


/*! \brief Sends user MODE message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param mode The mode that was set
 */
int send_user_MODE(chirc_ctx_t *ctx, chirc_connection_t *conn, char *mode);

/*! \brief Sends channel MODE message
 *
 * \param ctx Server context
 * \param conn The connection to add
 * \param nick The nick for the prefix
 * \param param1 The first parameter
 * \param mode The mode that was set
 */
int send_channel_MODE(chirc_ctx_t *ctx, chirc_connection_t *conn, char *nick, char *param_1, char *mode);

/*! \brief Sends NICK changed message
 *
 * \param ctx Server context
 * \param conn The user connection
 * \param rec The recipient connection to send messgae to
 * \param nick The new nickaname 
 */
int send_NICKCHANGED(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_connection_t *rec, char *nick);


/*! \brief Sends NICK changed message
 *
 * \param ctx Server context
 * \param conn The user connection
 * \param user The user that is joining the server
 */
int send_SERVER_NICK(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_user_t *user);

/*! \brief Sends all of the welcome messages
 *
 * \param ctx Server context
 * \param conn The user connection
 */
int chirc_welcome_messages(chirc_ctx_t *ctx, chirc_connection_t *conn);

/*! \brief Sends all of the welcome messages
 *
 * \param ctx Server context
 * \param conn The user connection
 * \param channel The channel to send to
 * \param nick The source NICK
 */
int send_join_messages(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel, char *nick);


/*! \brief Sends all of the quit messages
 *
 * \param ctx Server context
 * \param conn The user connection
 * \param msg The message to be sent
 */
int send_quit_messages(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);

/*! \brief Sends all of the private messages
 *
 * \param ctx Server context
 * \param conn The user connection
 * \param sender_nick The NICK from the sender
 * \param msg The message to be sent
 */
int send_privmsg_messages(chirc_ctx_t *ctx, chirc_channel_t *channel, char *sender_nick, chirc_message_t *msg);

/*! \brief Sends all of the part messages
 *
 * \param ctx Server context
 * \param conn The user connection
 * \param channel The channel that the user is leaving
 * \param nick The nick of the person that is leaving
 * \param msg The parting message to be sent
 */
int send_part_messages(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel, char *nick, char *part_msg);

/*! \brief Sends all of the mode messages
 *
 * \param ctx Server context
 * \param conn The user connection
 * \param channel The designated channel
 * \param msg The message to be sent
 */
int send_mode_messages(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_channel_t *channel, chirc_message_t *msg);

#endif /* SEND_H_ */
