/*
 * $Id: main.c,v 1.1 2003/05/21 17:00:30 offer Exp $
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
 * 	 o	Keep is basic and simple. Its designed to break security policy
 * 		so keep it small enough to analyse
 * 	 o	no performace issues - keep the code simple that means
 * 	 	using slow algorhtims (fork rather than select)
 *
 * example usage:
 *
 * 		funnel -l tcp,bind=127.0.0.1,port=2101 -r host=remote.example.com,port=2101,label=dbadmin
 *
 * Listen on the localhost (127.0.0.1) TCP port 2101 and funnel all
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


typedef struct _conn {

	int protocol;
	int port;
	int socket;
	mac_t label;
	char * label_text;
	union {
		char * bind;
		char * host;
	} addr;

	struct hostent *hostent;
	struct sockaddr_in net;
	char *net_name;
} Conn;


void validate_inputs(int);


/* global variables */
int verbose=0;
int mac_enabled=0;
Conn local;
Conn remote;

int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;
	extern int h_errno;
	int c;
	int err=0;
	int true=1;

	memset(&local, 0, sizeof(local));
	memset(&remote, 0, sizeof(remote));


	/* is MAC enabled ? */

	mac_enabled = sysconf(_SC_MAC);

	/* Initialize defaults for subsequent error checking */

	local.addr.bind = NULL;
	remote.addr.host = NULL;

	remote.protocol = local.protocol = SOCK_STREAM;
	remote.port = local.port = 0;


	/* parse cmd-line options */
	while ( (c=getopt(argc, argv, "vl:r:")) != -1 ) {

		switch (c) {

			case 'h':
			case '?':
				fprintf(stderr,
"\n\
funnel - funnel TCP INET connections at any MAC label to a (remote) server \n\
         at a single label\n\
usage:\n\
	funnel [-v] <-l local-options> <-r remote-options>\n\
	-v	increase verbosity (can be used multiple times).\n\
\n\
local options:\n\
	tcp | udp (UDP not supported in this version)\n\
	bind=<IP address> (default is all IP address on local machine)\n\
	port=<listen on port>\n\
\n\
remote options\n\
	host=<address>\n\
	port=<port>\n\
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
				exit(0);
				break;

			case 'v':
				verbose++;
				break;

			case 'l':
				{
					char *options=optarg;

					while ( *options ) {
						char *val;
						switch ( getsubopt(&options, opts, &val) ) {

							case 0: /* tcp */
								local.protocol=SOCK_STREAM;
								remote.protocol=SOCK_STREAM;
								break;

							case 1: /* udp */
								local.protocol=SOCK_DGRAM;
								remote.protocol=SOCK_DGRAM;
								break;

							case 2: /* bind */
								local.addr.bind=strdup(val);
								break;

							case 3: /* port */
								local.port=strtol(val, NULL, 10);
								if ( errno ) {
									fprintf(stderr,"%s\n",strerror(errno));
									err++;
								}
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
								remote.port=strtol(val, NULL, 10);
								if ( errno ) {
									fprintf(stderr,"%s: %s\n",val, strerror(errno));
									err++;
								}
								break;
								
							case 4: /* host */
								remote.addr.host=strdup(val);
								break;
								
							case 5: /* label */
		
								remote.label=mac_from_text(val);
								if ( mac_enabled && remote.label == NULL ) {
									fprintf(stderr,"Can't convert '%s' to MAC label.\n",val);
									err++;
								}
								remote.label_text = mac_to_text(remote.label,NULL);
								break;

							default:
								fprintf(stderr,"unknown flag '%s'.\n", val);
								err++;
								break;
								

						}
					}
				}
				break;

		}

	}

	/* test inputs */
	validate_inputs(err);


	/* try to change our process label to that of the remote host*/
	if ( mac_enabled > 0 && mac_set_proc(remote.label) == -1 ) {
		fprintf(stderr,"Cannot set process label to '%s'.\n",
				mac_to_text(remote.label,NULL));
		exit(1);
	}
	


	/* start networking code */

	local.socket = socket(AF_INET, local.protocol, 0);
	memset(&local.net, 0, sizeof(local.net));

	local.net.sin_family = AF_INET;
	local.net.sin_port = htons((u_short) local.port);
	if ( local.addr.bind != NULL ) {
		local.hostent = gethostbyname(local.addr.bind);

		if ( local.hostent )
			memcpy(&local.net.sin_addr,
					local.hostent->h_addr, local.hostent->h_length);
		else
			local.net.sin_addr.s_addr = htonl(inet_addr("0.0.0.0"));;
	}
	else
		local.net.sin_addr.s_addr = htonl(inet_addr("0.0.0.0"));;

	local.net_name = strdup(inet_ntoa(local.net.sin_addr));

	memset(&remote.net, 0, sizeof(remote.net));

	remote.net.sin_family = AF_INET;
	remote.net.sin_port = htons((u_short) remote.port);

	remote.hostent = gethostbyname(remote.addr.host);

	if ( remote.hostent == NULL ) {
		fprintf(stderr,"looking for '%s': %s\n",
				remote.addr.host, hstrerror(h_errno));
		exit(1);
	}
		
	memcpy(&remote.net.sin_addr, 
			remote.hostent->h_addr, remote.hostent->h_length);

	remote.net_name = strdup(inet_ntoa(remote.net.sin_addr));

	/* allow multiple instances of funnel to be run for the same port, but
	 * different local IP addresses - potentionally this would allow
	 * different networks to use different labels...
	 */
	setsockopt(local.socket, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(true));

	/* bind to local socket (server) */
	if ( bind(local.socket, (struct sockaddr *) &local.net, 
				sizeof(local.net)) == -1 ) {
		fprintf(stderr,"Can't bind local socket: %s\n",strerror(errno));
		exit(2);
	}	


	if ( mac_enabled && tsix_on(local.socket) == -1 ) {
		fprintf(stderr,"Can't enable T6: %s\n",strerror(errno));
		exit(4);

	}

	if ( listen(local.socket, 10) == -1 ) {
		fprintf(stderr,"Can't listen: %s\n",strerror(errno));
		exit(3);
	}

	if ( verbose )
		fprintf(stderr,"listening on %s:%d for %s:%d%s%s\n",
				local.net_name, local.net.sin_port,
				remote.net_name, remote.net.sin_port,
				( mac_enabled ? "@" : "" ),
				( mac_enabled ? remote.label_text : "" ));

	while ( 1 ) {
		Conn client;
		pid_t child;
		socklen_t l;
		int fd;
	   
	
		memset(&client, 0, sizeof(client));

		l=sizeof(client.net);

		if ( (fd=accept(local.socket, (struct soackaddr *) &client.net, 
						&l)) == -1 ) {
			fprintf(stderr,"accept failed: %s\n",strerror(errno));
			break;

		}

		if (mac_enabled ) {

			if ( tsix_get_mac(fd,&client.label) == -1 ) {

			}

			client.label_text = mac_to_text(client.label, NULL);
		}
		
		if ( verbose > 0 ) {
			fprintf(stderr,"Connection from %s:%d%s%s via %s:%d to %s:%d\n", 
					inet_ntoa(client.net.sin_addr),client.net.sin_port,
					( client.label_text ? "@" : "" ),
					( client.label_text ? client.label_text : "" ),
					local.net_name,local.net.sin_port,
					remote.net_name,remote.net.sin_port);
		}

		/* fork the child */
		if ( (child=fork()) == 0 ) { 
			fd_set rfds, wfds;
			struct timeval timeout;
			int max_fd;

			/* child process */

			close(local.socket);

			timeout.tv_sec = 60;
			timeout.tv_usec = 0;

			remote.socket = socket(AF_INET, remote.protocol, 0);

			if ( connect(remote.socket, (struct sockaddr *) &remote.net,
						sizeof(remote.net)) == -1 ) {

				fprintf(stderr,"Can't connect to remote host: %s\n",
						strerror(errno));
				exit(2);
			}

			if ( tsix_set_mac(fd, client.label) == -1 ) {
				fprintf(stderr,"Can't set T6 label on data: %s\n", 
						strerror(errno));
			}

			FD_ZERO(&rfds);
			FD_SET(fd, &rfds);
			FD_SET(remote.socket, &rfds);

			
			if ( fd > remote.socket )
				max_fd = fd;
			else
				max_fd = remote.socket;

			while ( 1 ) {
				char buf[4096];
				int bytes, c;

				memcpy(&wfds, &rfds, sizeof(rfds));
				
				if ( select(max_fd+1, &wfds, NULL, NULL, &timeout) <= 0 ) {
					break;
				}


				/* read from local socket, write to remote socket */
				if ( FD_ISSET(fd,&wfds) ) {

					if ( (bytes=read(fd, buf, sizeof(buf))) <= 0 ) 
						break;
					if ( verbose > 2 )
						fprintf(stderr,"read %d bytes from local\n", bytes);
					if ( (c=write(remote.socket, buf, bytes)) != bytes )
						break;
					if ( verbose > 2 )
						fprintf(stderr,"wrote %d bytes to remote \n", c);
				}
						
				/* read from remote socket, write to local socket */
				if ( FD_ISSET(remote.socket,&wfds) ) {
					if ( (bytes=read(remote.socket, buf, sizeof(buf))) <= 0 ) 
						break;
					if ( verbose > 2 )
						fprintf(stderr,"read %d bytes from remote\n", bytes);
					if ( (c=write(fd, buf, bytes)) != bytes )
						break;
					if ( verbose > 2 )
						fprintf(stderr,"wrote %d bytes to local \n", c);
				}

			}

			if ( verbose > 2 )
				fprintf(stderr,"Closing connection.");

			exit(0);
		}

		close(fd);
	}

	return 0;
}




void
validate_inputs(int err)
{

	if ( local.protocol != SOCK_STREAM ) {
		fprintf(stderr,"Only TCP is currently supported.\n");
		err++;
	}

	if ( local.port == 0 ) {
		fprintf(stderr,"local 'port' not specified\n");
		err++;
	}

	if ( remote.port == 0 ) {
		fprintf(stderr,"remote 'port' not specified\n");
		err++;
	}

	if ( remote.addr.host == NULL ) {
		fprintf(stderr,"Must specify a remote host.\n");
		err++;
	}

	if ( mac_enabled && remote.label == NULL ) {
		fprintf(stderr,"Must specify the label to use to talk to the remote host.\n");
		err++;
	}

	if ( err )
		exit(err);

}
