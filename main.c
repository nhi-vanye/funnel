/*
 * $Id: main.c,v 1.2 2003/06/06 00:11:04 offer Exp offer $
 *
 */

/* Funnel - a program to break network security policy.
 *
 * The intention of funnel is to listen on a port (at any label), then
 * to talk to another machine at a given label.
 *
 * This would allow a daemon to service clients at multiple labels without
 * using inetd. Or to proxy a remote server to local clients at multiple 
 * labels.
 *
 * As such it really really breaks network security policy, but hey some
 * people wanted it, and it provides a basic exmaple of T6 networking.
 *
 * Original Author: Richard Offer.
 * 
 *
 * Design Goal:
 *
 * 	 o	Keep it basic and simple. Its designed to break security policy
 * 		so keep it small enough to analyse
 * 	 o	no performace issues - keep the code simple that means
 * 	 	using slow algorhtims (fork rather than select)
 *
 * example usage:
 *
 * 		funnel -l tcp,bind=127.0.0.1,port=2101 -r host=remote.example.com,port=2101,label=dbadmin
 *
 * Listen only on the localhost (127.0.0.1) TCP port 2101 and funnel all
 * connections to remote.example.com port 2101 at dbadmin.
 *
 *
 * Note, funnel is simple, it will not work with protocols that embed
 * port numbers in the data stream, ie ftp
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <bstring.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mac.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>


/* options */

char *opts[] = {/* the return of getsubopt is the index into this array */
	"tcp",		/* so don't mess with it unless you fix the getsubopt */
	"udp",		/* code as well */
	"bind",
	"port",
	"host",
	"label",
	
	NULL
};

enum { LOCAL=0, REMOTE };

typedef struct _conn {

	int proxy; /* do it or not ? */
	char * protocol_name;
	int port[2];
	int socket[2];
	mac_t label[2];
	char * label_name[2];
	char * host[2];

	struct hostent *hostent[2];
	struct sockaddr_in net[2];
	char *net_name[2];
} Conn;

/* used by UDP to match requests/responses */
typedef struct _client {

	int socket;
	struct sockaddr_in net;
	time_t last;
	mac_t	label;

	struct _client *next;

} Client;

static void validate_inputs(int);
static void usage(void);
static int parse_args(int argc, char **argv);
static void init_connection(Conn *);

static void tcp_read_write(int local, int remote);


/* global variables */
int verbose=0;
int mac_enabled=0;

Conn tcpConn;
Conn udpConn;

Client *clientList=NULL;

struct sockaddr wildcardAddr = {AF_INET, INADDR_ANY};

#define BUF_SIZE (1<<16) /* read and write buffer size */
#define TIMEOUT 5 /* time for UDP to reply */

int
main(int argc, char **argv)
{
	int true = 1;
	int err=0;
	fd_set rfds;

	memset(&tcpConn, 0, sizeof(tcpConn));
	memset(&udpConn, 0, sizeof(udpConn));

	/* parse cmd-line options */
	err = parse_args(argc, argv);

	/* test inputs */
	validate_inputs(err);


	/* try to change our process label to that of the remote host*/
	if ( mac_enabled > 0 ) {
		if ( tcpConn.proxy && mac_set_proc(tcpConn.label[REMOTE]) == -1 ) {
			fprintf(stderr,"Cannot set process label to '%s'.\n",
					mac_to_text(tcpConn.label[REMOTE],NULL));
			exit(1);
		}
		if ( tcpConn.proxy == 0 && 
				udpConn.proxy && mac_set_proc(udpConn.label[REMOTE]) == -1 ) {
			fprintf(stderr,"Cannot set process label to '%s'.\n",
					mac_to_text(tcpConn.label[REMOTE],NULL));
			exit(1);
		}
	}
	


	/* start networking code */


	if ( tcpConn.proxy ) {
		tcpConn.socket[LOCAL] = socket(AF_INET, SOCK_STREAM, 0);
	
		init_connection(&tcpConn);
	
		/* allow multiple instances of funnel to be run for the same port, but
	 	 * different local IP addresses - potentionally this would allow
	 	 * different networks to use different labels...
	 	 */
		setsockopt(tcpConn.socket[LOCAL], SOL_SOCKET, SO_REUSEADDR, 
				&true, sizeof(true));

	}

	if ( udpConn.proxy ) {
		udpConn.socket[LOCAL] = socket(AF_INET, SOCK_DGRAM, 0);

		/* for some reason this is only a requirement for T6 networking, but
		 * without it, we only server one request
		 */
		ioctl(udpConn.socket[LOCAL], FIONBIO, &true);

		init_connection(&udpConn);
	}



	/* bind to local socket (server) */
	if ( tcpConn.proxy && bind(tcpConn.socket[LOCAL], 
				(struct sockaddr *) &tcpConn.net[LOCAL], 
				sizeof(tcpConn.net[LOCAL])) == -1 ) {
		fprintf(stderr,"Can't bind local TCP socket: %s\n",strerror(errno));
		exit(2);
	}	

	if ( udpConn.proxy && bind(udpConn.socket[LOCAL], 
				(struct sockaddr *) &udpConn.net[LOCAL], 
				sizeof(udpConn.net[LOCAL])) == -1 ) {
		fprintf(stderr,"Can't bind local UDP socket: %s\n",strerror(errno));
		exit(2);
	}	
	
	/* enable T6 */
	if ( mac_enabled && tcpConn.proxy && tsix_on(tcpConn.socket[LOCAL]) ==-1 ) {
		fprintf(stderr,"Can't enable T6: %s\n",strerror(errno));
		exit(3);
	}

	if ( mac_enabled && udpConn.proxy && tsix_on(udpConn.socket[LOCAL]) ==-1 ) {
		fprintf(stderr,"Can't enable T6: %s\n",strerror(errno));
		exit(4);
	}

	/* Start listening on the TCP connection */
	if ( tcpConn.proxy && listen(tcpConn.socket[LOCAL], 10) == -1 ) {
		fprintf(stderr,"Can't listen: %s\n",strerror(errno));
		exit(4);
	}

	if ( verbose ) {
		if ( tcpConn.proxy )
			fprintf(stderr,"listening on tcp/%s:%d for %s:%d%s%s\n",
				tcpConn.net_name[LOCAL], tcpConn.net[LOCAL].sin_port,
				tcpConn.net_name[REMOTE], tcpConn.net[REMOTE].sin_port,
				( mac_enabled ? "@" : "" ),
				( mac_enabled ? tcpConn.label_name[REMOTE] : "" ));

		if ( udpConn.proxy )
			fprintf(stderr,"listening on udp/%s:%d for %s:%d%s%s\n",
				udpConn.net_name[LOCAL], udpConn.net[LOCAL].sin_port,
				udpConn.net_name[REMOTE], udpConn.net[REMOTE].sin_port,
				( mac_enabled ? "@" : "" ),
				( mac_enabled ? udpConn.label_name[REMOTE] : "" ));

	}


	while ( 1 ) {
		int max_fd=0;
	   
		FD_ZERO(&rfds);

		if ( tcpConn.proxy ) {
			FD_SET(tcpConn.socket[LOCAL], &rfds);
			max_fd = tcpConn.socket[LOCAL];
		}

		if ( udpConn.proxy ) {
			FD_SET(udpConn.socket[LOCAL], &rfds);

			if ( max_fd < udpConn.socket[LOCAL] )
				max_fd = udpConn.socket[LOCAL];

			/* UDP is harder, we need to listen on the client connections, as
			 * well as listening for new clients
			 */
			if ( clientList != NULL ) {

				Client *c = clientList;

				while ( c != NULL ) {

					FD_SET(c->socket, &rfds);
			
					if ( max_fd < c->socket )
						max_fd = c->socket;

					c = c->next;
				}
			}
		}

		max_fd = max_fd + 1;
				
		if ( select(max_fd, &rfds, NULL, NULL, NULL) <= 0 ) {
			break;
		}
		
		if ( tcpConn.proxy && FD_ISSET(tcpConn.socket[LOCAL], &rfds) ) {
			Conn client;
			socklen_t l;
			int fd;
		
			memset(&client, 0, sizeof(client));

			l=sizeof(client.net[REMOTE]);

			if ( (fd=accept(tcpConn.socket[LOCAL], 
							(struct soackaddr *) &client.net[REMOTE], &l)) == -1 ) {
				fprintf(stderr,"accept failed: %s\n",strerror(errno));
				break;

			}
		
			if (mac_enabled ) {
				if ( tsix_get_mac(fd,&client.label[REMOTE]) == -1 ) {
					fprintf(stderr,"tsix_get_mac() failed: %s\n",
							strerror(errno));
				}

				client.label_name[REMOTE] = mac_to_text(client.label[REMOTE], NULL);
			}

			if ( verbose > 0 ) {
				fprintf(stderr,
						"Connection from tcp/%s:%d%s%s via %s:%d to %s:%d\n",
					inet_ntoa(client.net[REMOTE].sin_addr),
					client.net[REMOTE].sin_port,
					(client.label_name[REMOTE] ? "@" : "" ),
					(client.label_name[REMOTE] ? client.label_name[REMOTE] :""),
					tcpConn.net_name[LOCAL],tcpConn.net[LOCAL].sin_port,
					tcpConn.net_name[REMOTE],tcpConn.net[REMOTE].sin_port);
			}
			
			/* For TCP we fork a child to handle the ongoing communication */
			if ( fork() == 0 ) { 

				/* child process */

				close(tcpConn.socket[LOCAL]);

				tcpConn.socket[REMOTE] = socket(AF_INET, SOCK_STREAM, 0);

				if ( connect(tcpConn.socket[REMOTE], 
							(struct sockaddr *) &tcpConn.net[REMOTE],
							sizeof(tcpConn.net[REMOTE])) == -1 ) {

					fprintf(stderr,"Can't connect to remote host: %s\n",
							strerror(errno));
					exit(2);

				}

				if ( mac_enabled && tsix_set_mac(fd, client.label[REMOTE]) == -1 ) {
					fprintf(stderr,"Can't set T6 label on data: %s\n", 
							strerror(errno));
				}


				/* read from each end of the connection and write to the other
				 * - encapusalte it in a separate function to keep it tidier
				 */
				tcp_read_write(fd,tcpConn.socket[REMOTE]);
				
				if ( verbose > 2 )
					fprintf(stderr,"Closing connection.\n");

				exit(0);
			}

			close(fd);
		} /* tcpConn */				

		if ( udpConn.proxy ) {
	
			char buf[BUF_SIZE];
			int bytes;
	
			if ( FD_ISSET(udpConn.socket[LOCAL], &rfds) ) {

				struct sockaddr_in from;
				int flen = sizeof(from);
				mac_t flabel;
				char *label = NULL;

				if ( mac_enabled ) {
					bytes = tsix_recvfrom_mac(udpConn.socket[LOCAL], 
							buf, sizeof(buf), 
							0, (struct sockaddr *) &from, &flen,
							&flabel);
					label = mac_to_text(flabel, NULL);
				}
				else	
					bytes = recvfrom(udpConn.socket[LOCAL], buf, sizeof(buf), 
							0, (struct sockaddr *) &from, &flen);

				if ( bytes >= 0 ) {
			
					Client *c=clientList;

					while ( c ) {
				
						if ((c->net.sin_addr.s_addr != from.sin_addr.s_addr)
								|| (c->net.sin_port != from.sin_port))

							c = c->next;
						else  {
							break;
						}
			
					}
			
					if ( c == NULL ) {
					
						c = (Client *) calloc(1, sizeof(Client));
				
						c->next = clientList;
				
						clientList = c;
				
						memcpy(&(c->net), &from, sizeof(from));

						if ( mac_enabled )
							memcpy(&(c->label), &flabel, sizeof(flabel));
				
						c->socket = socket(AF_INET, SOCK_DGRAM, 0);
				
						/* for some reason this is only a requirement for 
						 * T6 networking, but without it, we only server one 
						 * request 
						 */
						ioctl(c->socket, FIONBIO, &true);
	
						if ( bind(c->socket, 
									(struct sockaddr *) &wildcardAddr, 
									sizeof(wildcardAddr)) == -1 ) {
		
							if ( mac_enabled && 
									tsix_on(c->socket) ==-1 ) {
		
								fprintf(stderr,
										"Can't enable T6: %s\n",
										strerror(errno));
								exit(4);
							}

							fprintf(stderr,
									"Can't bind wildcard UDP socket: %s\n",
									strerror(errno));
							exit(2);
	
						}	
					}

					errno=0;
					if ( mac_enabled ) {
						tsix_sendto_mac(c->socket, buf, bytes, 0, 
								(struct sockaddr *) &udpConn.net[REMOTE],
								sizeof(udpConn.net[REMOTE]), 
								udpConn.label[REMOTE]);

					}
					else {
						sendto(c->socket, buf, bytes, 0, 
								(struct sockaddr *) &udpConn.net[REMOTE],
								sizeof(udpConn.net[REMOTE]));

					}
			
					if ( verbose > 2 ) {
				
						fprintf(stderr,
								"Message from udp/%s:%d%s%s via %s:%d to %s:%d%s%s\n",
								inet_ntoa(from.sin_addr),from.sin_port,
								(label ? "@" : ""),
								(label ? label : ""),
								udpConn.net_name[LOCAL],udpConn.net[LOCAL].sin_port,
								udpConn.net_name[REMOTE],udpConn.net[REMOTE].sin_port,
								(udpConn.label_name[REMOTE] ? "@" : ""),
								(udpConn.label_name[REMOTE] ? udpConn.label_name[REMOTE] : "")
								);
					}
					c->last = time(NULL);
				}

				if ( label )
					free(label);
	
			} /* LOCAL */

			else {

				/* there's something to read from a previous client connection
				 */

				Client *c=clientList;
				struct sockaddr_in from;
				int flen = sizeof(from);
				mac_t	flabel;
				char *label = NULL;
				char *clabel = NULL;

				time_t now = time(NULL);

				while ( c != NULL ) {

					if ( mac_enabled ) {
						bytes=tsix_recvfrom_mac(c->socket, buf, 
									sizeof(buf), 0, 
									(struct sockaddr *) &from, &flen, &flabel);

						label = mac_to_text(flabel, NULL);
					}
					else
						bytes=recvfrom(c->socket, buf, 
									sizeof(buf), 0, 
									(struct sockaddr *) &from, &flen);

					if ( bytes >= 0) {
						
						if ( mac_enabled )  {
							tsix_sendto_mac(udpConn.socket[LOCAL], buf, bytes, 
									0, 
									(struct sockaddr *) &c->net,
									sizeof(c->net), c->label);

							clabel = mac_to_text(c->label,NULL);
						}
						else
							sendto(udpConn.socket[LOCAL], buf, bytes, 0, 
									(struct sockaddr *) &c->net,
									sizeof(c->net));
					
						if ( verbose > 2 ) {
							fprintf(stderr,
								"Message from udp/%s:%d%s%s via %s:%d to %s:%d%s%s\n",
								inet_ntoa(from.sin_addr),from.sin_port,
								(label ? "@" : ""),
								(label ? label : ""),
								udpConn.net_name[LOCAL],udpConn.net[LOCAL].sin_port,
								inet_ntoa(c->net.sin_addr),c->net.sin_port,
								(clabel ? "@" : ""),
								(clabel ? clabel : "")
								);
						}
					}
					if ( (now - c->last) > TIMEOUT ) {

							Client *client = clientList;

							close(c->socket);

							if ( c == clientList ) {

								clientList = c->next;

								if ( mac_enabled && c->label )
									mac_free(c->label);

								free(c);

								c = clientList;

								continue;

							}
							else {

								while ( client->next != c ) {
									client = client->next;

								}
								client->next = client->next->next;

								if ( mac_enabled && c->label )
									mac_free(c->label);

								free(c);

								c = client;
							}
					}

					c = c->next;

				}

			}

		} /* udpConn */


	} /* while forever */

	return 0;

}


/* read from the local socket and write to the remote socket, 
 * then read from the remote socket and write to the local one, 
 * rince, repeat.
 */ 
static void
tcp_read_write(int local, int remote)
{
	int max_fd;
	struct timeval timeout;

	fd_set cfds;


	max_fd = (local > remote ? local : remote ) + 1;

	timeout.tv_sec = 60;
	timeout.tv_usec = 0;

					
	while (1) {
		char buf[BUF_SIZE];
		int bytes, c;
					
		FD_ZERO(&cfds);
		FD_SET(local, &cfds);
		FD_SET(remote, &cfds);

		if ( select(max_fd, &cfds, NULL, NULL, &timeout) <= 0 ) {
			fprintf(stderr,"select() timeout.\n");
			break;
		}

		/* read from local socket, write to remote socket */
		if ( FD_ISSET(local,&cfds) ) {

			if ( (bytes=read(local, buf, sizeof(buf))) <= 0 ) {
				if ( verbose > 3 )
					fprintf(stderr, "read from local returned %d.\n", bytes);
				break;
			}
			
			if ( verbose > 2 )
				fprintf(stderr,"read %d bytes from local.\n", bytes);
			
			if ( (c=write(remote, buf, bytes)) != bytes ) {
				if ( verbose > 3 )
					fprintf(stderr, "write to remote returned %d.\n", c);
				break;
			}

			if ( verbose > 2 )
				fprintf(stderr,"wrote %d bytes to remote.\n", c);
		}
			
		/* read from remote socket, write to local socket */
		if ( FD_ISSET(remote,&cfds) ) {

			if ( (bytes=read(remote, buf, sizeof(buf))) <= 0) {

				if ( verbose > 3 )
					fprintf(stderr, "read from remote returned %d.\n", bytes);
				break;
			}
			
			if ( verbose > 2 )
				fprintf(stderr,"read %d bytes from remote.\n", bytes);
			
			if ( (c=write(local, buf, bytes)) != bytes ) {
				if ( verbose > 3 )
					fprintf(stderr, "write to remote returned %d.\n", c);
				break;
			}
			
			if ( verbose > 2 )
				fprintf(stderr,"wrote %d bytes to local.\n", c);
		}

	}
}

static void
init_connection(Conn *conn)
{

	extern int h_errno;
	
	/* local side of connection */
	memset(&conn->net[LOCAL], 0, sizeof(conn->net[LOCAL]));

	conn->net[LOCAL].sin_port = conn->port[LOCAL];
	conn->net[LOCAL].sin_family =  AF_INET;
	
	if ( conn->host[LOCAL] != NULL ) {
		conn->hostent[LOCAL] = gethostbyname(conn->host[LOCAL]);

		if ( conn->hostent[LOCAL] )
			memcpy(&conn->net[LOCAL].sin_addr,
					conn->hostent[LOCAL]->h_addr, 
					conn->hostent[LOCAL]->h_length);
		else
			conn->net[LOCAL].sin_addr.s_addr = htonl(inet_addr("0.0.0.0"));
	}
	else
		conn->net[LOCAL].sin_addr.s_addr = htonl(inet_addr("0.0.0.0"));

	conn->net_name[LOCAL] = strdup(inet_ntoa(conn->net[LOCAL].sin_addr));

	/* remote side */
	memset(&conn->net[REMOTE], 0, sizeof(conn->net[REMOTE]));

	conn->net[REMOTE].sin_port = conn->port[REMOTE];
	conn->net[REMOTE].sin_family =  AF_INET;

	conn->hostent[REMOTE] = gethostbyname(conn->host[REMOTE]);

	if ( conn->hostent[REMOTE] == NULL ) {
		fprintf(stderr,"looking for '%s': %s\n",
				conn->host[REMOTE], hstrerror(h_errno));
	}
	
	memcpy(&conn->net[REMOTE].sin_addr, conn->hostent[REMOTE]->h_addr, 
					conn->hostent[REMOTE]->h_length);

	conn->net_name[REMOTE] = strdup(inet_ntoa(conn->net[REMOTE].sin_addr));	

}


static int
parse_args(int argc, char **argv)
{

	extern char *optarg;
	extern int optind;
	int c;
	int err=0;

	while ( (c=getopt(argc, argv, "Mvhl:r:")) != -1 ) {

		switch (c) {

			case 'h':
			case '?':

				usage();
				exit(0);
				break;

			case 'v':
				verbose++;
				break;

			case 'M':
				/* is MAC enabled ? */
				mac_enabled = sysconf(_SC_MAC) > 0 ;
				break;

			case 'l':
			{
				char *options=optarg;

				while ( *options ) {
					char *val;
					char *ptr;
					switch ( getsubopt(&options, opts, &val) ) {

						case 0: /* tcp */
							tcpConn.proxy=1;
							break;

						case 1: /* udp */
							udpConn.proxy=1;
							break;

						case 2: /* bind */
							tcpConn.host[LOCAL]=strdup(val);
							udpConn.host[LOCAL]=strdup(val);
							break;

						case 3: /* port */
							tcpConn.port[LOCAL]=strtol(val, &ptr, 10);
							if ( ptr == val ) {
								struct servent *portname;
								if ( (portname=getservbyname(val, 
												NULL)) != NULL ) {
									tcpConn.port[LOCAL]=portname->s_port;
								}
								else {
									fprintf(stderr,
											"Can't find service '%s'\n",
											val);
									err++;
								}
							}
							udpConn.port[LOCAL]=tcpConn.port[LOCAL];
							break;
							
						case 4: /* host */
							fprintf(stderr,"'host' not supported in local address. Did you mean 'bind' ?\n");
							err++;
							break;
							
						case 5: /* label */
							fprintf(stderr,"'label' not supported in local address.\n");
							err++;
							break;

						default:
							fprintf(stderr,"unknown flag '%s'.\n", val);
							err++;
							break;
							

					}
				}
			}
			break;
				
			case 'r':
			{
				char *options=optarg;

				while ( *options ) {
					char *val;
					char *ptr;
					switch ( getsubopt(&options, opts, &val) ) {

						case 0: /* tcp */
						case 1: /* udp */
							fprintf(stderr,"specifying the protocol is only done on the local connection.\n");
							err++;
							break;

						case 2: /* bind */
							fprintf(stderr,"'bind' not supported in remote address. Did you mean 'host' ?\n");
							err++;
							break;

						case 3: /* port */
							tcpConn.port[REMOTE]=strtol(val, &ptr, 10);
							if ( ptr == val ) {
								struct servent *portname;
								if ( (portname=getservbyname(val, 
												NULL)) != NULL ) {
									tcpConn.port[REMOTE]=portname->s_port;
								}
								else {
									fprintf(stderr,
											"Can't find service '%s'\n",
											val);
									err++;
								}
							}
							udpConn.port[REMOTE]=tcpConn.port[REMOTE];
							break;
							
						case 4: /* host */
							tcpConn.host[REMOTE]=strdup(val);
							udpConn.host[REMOTE]=strdup(val);
							break;
							
						case 5: /* label */
	
							if ( mac_enabled ) {
								udpConn.label[REMOTE] = 
									tcpConn.label[REMOTE] = mac_from_text(val);
								
								if ( tcpConn.label[REMOTE] == NULL ) {
									fprintf(stderr,
											"Can't convert '%s' to MAC label.\n",val);
									err++;
								}
								else {
									tcpConn.label_name[REMOTE] = 
									mac_to_text(tcpConn.label[REMOTE],NULL);

									udpConn.label_name[REMOTE] = strdup(tcpConn.label_name[REMOTE]);  
								}
							}
							break;

						default:
							fprintf(stderr,"unknown flag '%s'.\n", val);
							err++;
							break;
							

					}
				}
			}
			break; /* 'r' */
		}
	}

	return err;

}

static void
validate_inputs(int err)
{

	if ( tcpConn.proxy == 0  && udpConn.proxy == 0 ) {
		fprintf(stderr,"protocol family (tcp,udp) not specified.\n");
		err++;
	}

	if ( ( tcpConn.proxy && tcpConn.port[LOCAL] == 0 ) ||  
			( udpConn.proxy && udpConn.port[LOCAL] == 0 ) ) {
		fprintf(stderr,"local 'port' not specified\n");
		err++;
	}

	if ( ( tcpConn.proxy && tcpConn.port[REMOTE] == 0 ) ||  
			( udpConn.proxy && udpConn.port[REMOTE] == 0 ) ) {
		fprintf(stderr,"remote 'port' not specified\n");
		err++;
	}

	if ( ( tcpConn.proxy && tcpConn.host[REMOTE] == NULL ) ||  
			( udpConn.proxy && udpConn.host[REMOTE] == NULL ) ) {
		fprintf(stderr,"Must specify a remote host.\n");
		err++;
	}

	if ( mac_enabled && 
			( ( tcpConn.proxy && tcpConn.label[REMOTE] == NULL) || 
			  ( udpConn.proxy && udpConn.label[REMOTE] == NULL) ) ) {
		fprintf(stderr,"Must specify the label to use to talk to the remote host.\n");
		err++;
	}

	if ( err )
		exit(err);

}

static void
usage()
{
	
	fprintf(stderr,
"\n\
funnel - funnel INET connections to a (remote) server. If MAC is enabled \n\
         local connections (at any label) will be written to the remote \n\
		 server at a single label.\n\
usage:\n\
	funnel [-v] [-M] <-l local-options> <-r remote-options>\n\
	-v	increase verbosity (can be used multiple times).\n\
	-M  enable MAC behavior (ignored on a single level host).\n\
\n\
local options:\n\
	tcp | udp\n\
	bind=<IP address> (default is all IP address on local machine)\n\
	port=<listen on port, maybe number or name from /etc/services>\n\
\n\
remote options\n\
	host=<address>\n\
	port=<port, maybe number or name from /etc/services>\n\
	label=<label> (label to use to talk to remote host)\n\
\n\
example:\n\
  funnel -l tcp,bind=127.0.0.1,port=80 -r host=example.com,port=80,label=dblow\n\
\n\
Privilege Requirements\n\
\n\
Funnel would normally require privielge to run (to use low port numbers,\n\
downgrade data, etc). Since funnel is a security breech, it does not grab \n\
capabilities, the user must have them in their environment in order to work.\n\
You will probably need :-\n\
	CAP_MAC_RELABEL_SUBJ\n\
	CAP_NETWORK_MGT\n\
And potentionaly:\n\
	CAP_MAC_DOWNGRADE\n\
	CAP_MAC_UPGRADE\n\
	CAP_MAC_WRITE\n\
	CAP_PRIV_PORT\n\
plus others....\n");

}
