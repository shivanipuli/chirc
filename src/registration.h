/*! \file registration.h
 *  \brief Functions associated with registration */

#ifndef REGISTRATION_H_
#define REGISTRATION_H_

#include "chirc.h"

/* Registration Functions */

/*! \brief Begins the registration
 * 
 * Used when only the NICK message has been sent, and therefore it does the
 * initial user registration, but does not actually assign it as being fully
 * registered.
 *
 * \param ctx Server context
 * \param conn The user connection
 */
int chirc_begin_registration(chirc_ctx_t *ctx, chirc_connection_t *conn);


/*! \brief Finishes the initially started registration
 * 
 * Used when the USER command follows the NICK command. Since the user has
 * already been partially initialized from the begin registration function, 
 * this function finishes the registration for the user.
 *
 * \param ctx Server context
 * \param conn The user connection
 */
int chirc_finish_registration(chirc_ctx_t *ctx, chirc_connection_t *conn, chirc_message_t *msg);


/*! \brief Full user registration
 * 
 * Will happen if the USER command is sent before the NICK command, and will
 * allow all of the registration steps to happen in a single go.
 *
 * \param ctx Server context
 * \param conn The user connection
 */
int chirc_full_registration(chirc_ctx_t *ctx, chirc_connection_t *conn, char *username);


/*! \brief Full Server Registration
 * 
 * Will use the context and the connection in order to register a server.
 *
 * \param ctx Server context
 * \param conn The user connection
 */
int chirc_register_server(chirc_ctx_t *ctx, chirc_connection_t *conn);


#endif /* REGISTRATION_H_ */