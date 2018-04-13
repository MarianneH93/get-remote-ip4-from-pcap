/* A much more complicated libtrace program designed to demonstrate combining
 * various elements of libtrace to create a useful tool.
 *
 * Specifically, this program calculates the amount of header overhead for
 * TCP and UDP traffic compared with the amount of application payload. It
 * writes the byte counts regularly to generate data suitable for a time series
 * graph.
 *
 */
#include "libtrace.h"
#include <stdio.h>
#include <inttypes.h>
#include <err.h>
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>

uint64_t udp_header = 0;
uint64_t udp_payload = 0;
uint64_t tcp_header = 0;
uint64_t tcp_payload = 0;
uint64_t not_ip = 0;

uint32_t next_report = 0;
uint32_t interval = 10;		/* Reporting interval defaults to 10 seconds. */

/* This enum defines values for all the possible protocol cases that this
 * program is interested in */
typedef enum {
	DEMO_PROTO_TCP,		/* The packet is a TCP packet */
	DEMO_PROTO_UDP,		/* The packet is a UDP packet */
	DEMO_PROTO_NOTIP,	/* The packet is NOT an IP packet */
	DEMO_PROTO_OTHER,	/* The packet is none of the above */
	DEMO_PROTO_UNKNOWN	/* Haven't yet determined anything about the
				   packet */
} demo_proto_t;

/**
 * Get the remote IPv4 address from a given packet. Returns the address as an
 * unsigned long. If the address is 0, it could not be retrieved from the
 * packet.
 * @param packet
 */
static unsigned long getRemoteIP4Address(libtrace_packet_t *packet) {
    void *layer3;
    uint16_t ethertype;
    uint32_t remaining;
    unsigned long remoteIP = 0;

    layer3 = trace_get_layer3(packet, &ethertype, &remaining);
    
    if (layer3 == NULL)
        return;
    
    // IPV4
    if (ethertype == 0x0800) {
        libtrace_ip_t *ip = (libtrace_ip_t *)layer3;
        
        libtrace_direction_t dir = trace_get_direction(packet);
        
        
        // Outbound
        if (dir == 0) {
            remoteIP = ntohl(ip->ip_dst.s_addr);
        // Inbound
        } else if (dir == 1) {
            remoteIP = ntohl(ip->ip_src.s_addr);
        }
    }
    
    return remoteIP;
    
}

static void per_packet(libtrace_packet_t *packet)
{
    unsigned long remoteIP = getRemoteIP4Address(packet);
    if (remoteIP != 0) {
        printf("%d.%d.%d.%d\n",
            (remoteIP >> 24)&0xFF,
            (remoteIP >> 16)&0xFF,
            (remoteIP >> 8)&0xFF,
            (remoteIP)&0xFF);
    }
}

/* Due to the amount of error checking required in our main function, it
 * is a lot simpler and tidier to place all the calls to various libtrace
 * destroy functions into a separate function.
 */
static void libtrace_cleanup(libtrace_t *trace, libtrace_packet_t *packet, 
		libtrace_filter_t *filter) {
	
	/* It's very important to ensure that we aren't trying to destroy
	 * a NULL structure, so each of the destroy calls will only occur
	 * if the structure exists */
	if (trace)
		trace_destroy(trace);
	
	if (packet)
		trace_destroy_packet(packet);

	if (filter)
		trace_destroy_filter(filter);
}

static void usage(char *prog) {
	fprintf(stderr, "Usage: %s [-i interval] [-f filter] inputURI\n",
		prog);
}


int main(int argc, char *argv[])
{
	libtrace_t *trace = NULL;
	libtrace_packet_t *packet = trace_create_packet();
	libtrace_filter_t *filter = NULL;

	int opt;
	char *filterstring = NULL;

	/* Ensure we have at least one argument after the program name */
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	/* Using getopt to handle any command line flags that would set the
	 * reporting interval and a filter */
	while ((opt = getopt(argc, argv, "i:f:")) != EOF) {
		switch (opt) {
			case 'i':
				interval = atoi(optarg);
				break;
			case 'f':
				filterstring = optarg;
				break;
			default:
				usage(argv[0]);
				return 1;
		}
	}

	trace = trace_create(argv[1]);

	if (trace_is_err(trace)) {
		trace_perror(trace,"Opening trace file");
		libtrace_cleanup(trace, packet, filter);
		return 1;
	}

	if (trace_start(trace) == -1) {
		//trace_perror(trace,"Starting trace");
		libtrace_cleanup(trace, packet, filter);
		return 1;
	}

	/* This loop will read packets from the trace until either EOF is
	 * reached or an error occurs (hopefully the former!)
	 *
	 * Remember, EOF will return 0 so we only want to continue looping
	 * as long as the return value is greater than zero
	 */
	while (trace_read_packet(trace,packet)>0) {
		/* Call our per_packet function for every packet */
		per_packet(packet);
	}

	/* If the trace is in an error state, then we know that we fell out of
	 * the above loop because an error occurred rather than EOF being
	 * reached. Therefore, we should probably tell the user that something
	 * went wrong
	 */
	if (trace_is_err(trace)) {
		trace_perror(trace,"Reading packets");
		libtrace_cleanup(trace, packet, filter);
		return 1;
	}

	libtrace_cleanup(trace, packet, filter);

	return 0;
}