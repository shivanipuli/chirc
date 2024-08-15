/*! \file main.c
 *  \brief main() function for chirc server
 *
 *  This module provides the main() function for the server,
 *  which parses the command-line arguments to the chirc executable.
 *
 *  Code related to running the server should go in the chirc_run function
 *  (found below the main() function)
 */

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

/* Forward declaration of chirc_run */
int chirc_run(chirc_ctx_t *ctx);

/* DO NOT modify the contents of the main() function.
 * Add your code in the chirc_run function found below
 * the main() function. */
int main(int argc, char *argv[])
{
    /* Parse command-line parameters */
    int opt;
    sds port = NULL, passwd = NULL, servername = NULL, network_file = NULL;
    int verbosity = 0;

    while ((opt = getopt(argc, argv, "p:o:s:n:vqh")) != -1)
        switch (opt) {
        case 'p':
            port = sdsnew(optarg);
            break;
        case 'o':
            passwd = sdsnew(optarg);
            break;
        case 's':
            servername = sdsnew(optarg);
            break;
        case 'n':
            if (access(optarg, R_OK) == -1) {
                printf("ERROR: No such file: %s\n", optarg);
                exit(-1);
            }
            network_file = sdsnew(optarg);
            break;
        case 'v':
            verbosity++;
            break;
        case 'q':
            verbosity = -1;
            break;
        case 'h':
            printf("Usage: chirc -o OPER_PASSWD [-p PORT] [-s SERVERNAME] [-n NETWORK_FILE] [(-q|-v|-vv)]\n");
            exit(0);
            break;
        default:
            fprintf(stderr, "ERROR: Unknown option -%c\n", opt);
            exit(-1);
        }

    if (!passwd) {
        fprintf(stderr, "ERROR: You must specify an operator password\n");
        exit(-1);
    }

    if (network_file && !servername) {
        fprintf(stderr, "ERROR: If specifying a network file, you must also specify a server name.\n");
        exit(-1);
    }

    /* Set logging level based on verbosity */
    switch (verbosity) {
    case -1:
        chirc_setloglevel(QUIET);
        break;
    case 0:
        chirc_setloglevel(INFO);
        break;
    case 1:
        chirc_setloglevel(DEBUG);
        break;
    case 2:
        chirc_setloglevel(TRACE);
        break;
    default:
        chirc_setloglevel(TRACE);
        break;
    }

    /* Create server context */
    chirc_ctx_t ctx;
    chirc_ctx_init(&ctx);
    ctx.oper_passwd = passwd;

    if (!network_file) {
        /* If running in standalone mode, we have an IRC Network with
         * just one server. We only initialize ctx.network.this_server */
        char hbuf[NI_MAXHOST];
        gethostname(hbuf, sizeof(hbuf));

        ctx.network.this_server = calloc(1, sizeof(chirc_server_t));

        ctx.network.this_server->servername = sdsnew(hbuf);
        ctx.network.this_server->hostname = sdsnew(hbuf);
        ctx.network.this_server->passwd = NULL;
        ctx.network.this_server->conn = NULL;

        if (port) {
            ctx.network.this_server->port = port;
        } else {
            ctx.network.this_server->port = sdsnew("6667");
        }

        serverlog(INFO, NULL, "%s: standalone mode (port %s)", ctx.version, ctx.network.this_server->port);
    } else {
        /* If running in network mode, we load the network specification from the network file
         * specified with the -n parameter */
        if (chirc_ctx_load_network(&ctx, network_file, servername) == CHIRC_FAIL) {
            serverlog(CRITICAL, NULL, "Could not load network file.");
            exit(-1);
        }

        serverlog(INFO, NULL, "%s: IRC network mode", ctx.version);

        for (chirc_server_t *s = ctx.network.servers; s != NULL; s = s->hh.next) {
            bool cur_server = (strncmp(s->servername, ctx.network.this_server->servername,strlen(s->servername)) == 0);
            serverlog(INFO, NULL, "  %s (%s:%s) %s", s->servername, s->hostname, s->port,
                      cur_server ? " <--" : "");
        }
    }

    /* Run the server */
    return chirc_run(&ctx);
}

/*!
 * \brief Runs the chirc server
 *
 * This function starts the chirc server and listens for new
 * connections. Each time a new connection is established,
 * a new thread is created to handle that connection
 * (by calling create_connection_thread)
 *
 * In this function, you can assume the ctx parameter is a fully
 * initialized chirc_ctx_t struct. Most notably, ctx->network.this_server->port
 * will contain the port the server must listen on.
 *
 * \param ctx Server context
 * \return 0 on success, non-zero on failure.
 */
int chirc_run(chirc_ctx_t *ctx)
{
    /* Creating passive and active sockets */
    int passive_socket; /* Listening for connections */
    int active_socket;  /* Used for communcation with a client */

    /* Socket address information */
    struct addrinfo hints, *res, *p;
    struct sockaddr_in *client_addr;

    int yes = 1;
    char *host = NULL;
    socklen_t sin_size = sizeof(struct sockaddr_in);


    /* Ensuring server_addr is all zeros */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;      /* Unpecified Family */
    hints.ai_socktype = SOCK_STREAM;  /* Duplex Socket */
    hints.ai_flags = AI_PASSIVE;      /* Mentioned on ED */

    /* Getting port from ctx */
    char *port = ctx->network.this_server->port;
    if(port == NULL) {
        chilog(CRITICAL, "Error getting port from ctx");
        exit(-1);
    }

    /* Call getaddrinfo with the host and port from ctx */
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        chilog(CRITICAL, "getaddrinfo() failed");
        exit(-1);
    }

    /* Iterate through the list */
    for(p = res; p != NULL; p = p->ai_next) {
        if ((passive_socket = socket(p->ai_family,
                                     p->ai_socktype,
                                     p->ai_protocol)) == -1) {
            chilog(ERROR, "Could not open socket");
            continue;
        }

        /* Try to connect */
        if (setsockopt(passive_socket, SOL_SOCKET, SO_REUSEADDR,
                       &yes, sizeof(int)) == -1) {
            chilog(ERROR, "Socket setsockopt() failed");
            close(passive_socket);
            continue;
        }

        /* Bind the passive socket to the address */
        if(bind(passive_socket, (struct sockaddr *)p->ai_addr, p->ai_addrlen) == -1) {
            chilog(ERROR, "Socket bind() failed");
            close(passive_socket);
            continue;
        }

        /* Start listening for the passive socket */
        if(listen(passive_socket, 5) == -1) {
            chilog(ERROR, "Socket listen() failed");
            close(passive_socket);
            continue;
        }

        /* Success */
        break;
    }

    freeaddrinfo(res);

    /* Making sure a socket was found */
    if (p == NULL) {
        chilog(CRITICAL, "Could not find a socket to bind with");
        exit(-1);
    }

    chilog(INFO, "Waiting for connection... ");

    /* Loop to accept multiple connections */
    while(1) {
        /* Accept incoming connection */
        if((active_socket = accept(passive_socket, (struct sockaddr *) &client_addr,
                                   &sin_size)) == -1) {
            chilog(ERROR, "Socket accept() failed");
            continue;
        }

        /* Creating a new socket and making allocation for it */
        chirc_connection_t *connection = malloc(sizeof(chirc_connection_t));
        if(!connection) {
            chilog(ERROR, "Allocation for connection failed");
            close(active_socket);
            continue;
        }

        /* Initializing a connection and assigning the socket */
        chirc_connection_init(connection);
        connection->hostname = host;
        connection->port = port;
        connection->socket = active_socket;
        connection->peer.server = ctx->network.this_server;
        ctx->network.this_server->registered = true;

        if(chirc_connection_create_thread(ctx,connection) != 0) {
            free(client_addr);
            close(passive_socket);
            close(active_socket);
        }
        chirc_connection_free(connection);
    }
    return 0;
}
