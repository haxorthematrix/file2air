/*
* file2air - injects binary files as packets onto 802.11 networks
*
* $Id: file2air.c,v 1.9 2007/02/08 20:47:52 jwright Exp $
*
* Copyright (c) 2005, Joshua Wright <jwright@hasborg.com>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 as
* published by the Free Software Foundation. See COPYING for more
* details.
*
* file2air is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* Many thanks for the original file2wire source to:
* FX <fx@phenoelit.de>
* Phenoelit (http://www.phenoelit.de)
* (c) 2k1
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>

#include <tx80211.h>
#include <tx80211_packet.h>

#include <sys/socket.h>
#include <linux/wireless.h>

#include "common.h"
#include "utils.h"
#include "file2air.h"


void usage(char *message) {

	struct tx80211_cardlist *cardlist = NULL;
	int i;

	cardlist = tx80211_getcardlist();


	if (strlen(message) > 0) {
		printf("%s: %s\n", PROGNAME, message);
	}

	printf("Usage: %s [options]\n", PROGNAME);
	printf("\n"
	"  -i  --interface\tSpecify an interface name\n"
	"  -r  --driver   \tDriver type for injection\n"
	"  -f  --filename \tSpecify a binary file contents for injection\n"
	"\n"
	"  -c  --channel  \tChannel number\n"
	"  -n  --count	\tNumber of packets to send\n"
	"  -w  --delay	\tDelay between packets (uX for usec or X for seconds)\n"
	"  -t  --fast	 \tAlias for -w u100000 (10 packets per second)\n"
	"\n"
	"  -d  --dest	 \tOverride the destination address\n"
	"  -s  --source   \tOverride the source address\n"
	"  -b  --bssid	\tOverride the BSSID address\n"
	"  -a  --wds	  \tOverride the WDS address\n"
	"  -q  --seqnum   \tOverride the sequence number (leading 0x for hex value)\n"
	"  -Q  --seqnuminc\tOverride the sequence number and increment sequentially\n"
	"  -p  --pieces   \tFragment the payload into X pieces.\n"
	"\n"
	"  -h  --help	 \tOutput this help information and exit\n"
	"  -v  --verbose  \tPrint verbose info (more -v's for more verbosity)\n"
	"\n");
	
	if (cardlist == NULL) {
		fprintf(stderr, "Error accessing supported cardlist.\n");
	} else {
		printf("\nSupported drivers are: ");
		for (i = 1; i < cardlist->num_cards; i++) {
			printf("%s ", cardlist->cardnames[i]);
		}
		printf("\n");
	}

}


/* returns -1 on error, number of bytes read on success */
int readfile(unsigned char *buffer, struct optcfg *cfg) {

	int fd;
	struct stat sfilebuf;

	if (stat(cfg->filename, &sfilebuf) !=0) {
		perror("stat");
		return(1);
	} 

	if (cfg->verbose) {
		printf("%s - %ld bytes raw data\n", cfg->filename,
		sfilebuf.st_size);
	}

	if (sfilebuf.st_size > MAXPACKETSIZE) {
		fprintf(stderr, "Packet size too large (%d).  Must be %d or "
		"smaller.\n", (int)sfilebuf.st_size,
		MAXPACKETSIZE);
		return(-1);
	}

	if ((fd = open(cfg->filename, O_RDONLY)) < 0) {
		perror("open()");
		return (1);
	}

	read(fd, buffer, sfilebuf.st_size);
	close(fd);

	return(sfilebuf.st_size);
}

int sendpackets(struct tx80211 *in_tx, struct optcfg *cfg, 
		unsigned char *packet, int plen) {

	int ret, i, payloadlen, fragsize, lastfragsize, wholefrags, offset;
	unsigned char *fragpacket;
	struct tx80211_packet in_packet;
	struct ieee80211 *dot11ptr;

	tx80211_initpacket(&in_packet);

	if (cfg->fragpieces > 1) {
		/* fragment packet for transmission */
		payloadlen = plen - (sizeof(struct ieee80211));

		/* Ensure payload length is greater then the number of 
		fragments */
		if (!(payloadlen >= cfg->fragpieces)) 
		return -2;

		/* Calculate the size of fragments, and the last fragment 
		size */
		fragsize = payloadlen / cfg->fragpieces;
		if (payloadlen % cfg->fragpieces) {
			lastfragsize = (payloadlen - 
			(fragsize * (cfg->fragpieces - 1)));
		} else {
			lastfragsize = 0;
		}

		/* Offset of the packet to transmit as fragments, starting at
		payload */
		offset=sizeof(struct ieee80211);

		/* Number of fragments to send */
		if (lastfragsize > 0) {
			wholefrags = cfg->fragpieces-1;
		} else {
			wholefrags = cfg->fragpieces;
		}

		/* Specify the packet size to transmit */
		in_packet.plen = sizeof(struct ieee80211)+fragsize;

		/* Packet to transmit with specified header contents and 
		   fragmented payload contents. */
		fragpacket=malloc(sizeof(struct ieee80211)+fragsize);
		if (fragpacket == NULL) {
			return -3;
		}
		memcpy(fragpacket, packet, sizeof(struct ieee80211));
		dot11ptr = (struct ieee80211 *)fragpacket;

		/* Set the More Fragments flag in the Frame Control header */
		dot11ptr->more_frag=1;

		/* Send fragments */
		for (i=0; i < wholefrags; i++) {
			dot11ptr->fragment = i;
			memcpy(fragpacket+sizeof(struct ieee80211), 
					packet+offset, fragsize);
			in_packet.packet = fragpacket;

			/* Test for last fragment and no final partiaa
			   fragment */
			if(i == wholefrags-1 && lastfragsize == 0) {
				dot11ptr->more_frag=0;
			}

			ret = tx80211_txpacket(in_tx, &in_packet);
			if (ret < (sizeof (struct ieee80211)+fragsize)) {
				return -4;
			}
			offset+=fragsize;
		}
		free(fragpacket);

		/* Send last fragment */
		if (lastfragsize != 0) {

			/* Packet to transmit with specified header contents 
				and fragmented payload contents. */
			fragpacket=malloc(sizeof(struct ieee80211) +
			lastfragsize);
			if (fragpacket == NULL) {
				return -3;
			}
			memcpy(fragpacket, packet, sizeof(struct ieee80211));

			dot11ptr = (struct ieee80211 *)fragpacket;
			dot11ptr->fragment = i;
			dot11ptr->more_frag = 0;

			memcpy(fragpacket+sizeof(struct ieee80211), 
			packet + offset, lastfragsize);

			in_packet.packet = fragpacket;
			in_packet.plen = sizeof(struct ieee80211)+lastfragsize;

			ret = tx80211_txpacket(in_tx, &in_packet);
			if (ret < (sizeof (struct ieee80211)+lastfragsize)) {
				return -6;
			}

			free(fragpacket);
		}

		ret = plen;

	} else {

		/* Setup the tx80211_packet struct to transmit */
		in_packet.plen = plen;
		in_packet.packet = packet;
		ret = tx80211_txpacket(in_tx, &in_packet);

	}

	return ret;
}

int getseqnum(char *seqnum) {
	int ret=0;
	if (strncmp(seqnum, "0x", 2) == 0) {
		sscanf(seqnum+2, "%x", &ret);
	} else {
		sscanf(seqnum, "%d", &ret);
	}

	return ret;
}

int main(int argc,char *argv[]) {
	char option, opt_dst[18], opt_src[18], opt_bssid[18],
			opt_wds[18], opt_seqnum[8];
	extern char *optarg;
	struct optcfg cfg;
	int opt_srcset=0, opt_dstset=0, opt_bssidset=0,
			opt_wdsset=0, opt_seqnumset=0, opt_seqnumincset=0;
	int ret, plen, seqnum, i;
	unsigned char buffer[MAXPACKETSIZE];
	unsigned char src[6], dst[6], bssid[6], wds[6];
	struct ieee80211 *dot11ptr;
	struct ieee80211a4 *dot11ptra4;
	struct tx80211 in_tx;
	int drivertype = INJ_NODRIVER;

	memset(&cfg, 0, sizeof(cfg));
	/* setup defaults */
	cfg.count=1;

	printf("file2air v%s - inject 802.11 packets from binary files "
	"<jwright@hasborg.com>\n", VER);

	/* Cribbed from the GNU docs on getopt_long */
	while (1) {
		static struct option long_options[] =
		{
			{"interface", required_argument, 0, 'i'},
			{"filename", required_argument, 0, 'f'},
			{"count", required_argument, 0, 'n'},
			{"delay", required_argument, 0, 'w'},
			{"source", required_argument, 0, 's'},
			{"bssid", required_argument, 0, 'b'},
			{"dest", required_argument, 0, 'd'},
			{"wds", required_argument, 0, 'a'},
			{"help", no_argument, 0, 'h'},
			{"verbose", no_argument, 0, 'v'},
			{"driver", required_argument, 0, 'r'},
			{"channel", required_argument, 0, 'c'},
			{"seqnum", required_argument, 0, 'q'},
			{"seqnuminc", required_argument, 0, 'Q'},
			{"fast", no_argument, 0, 't'},
			{"pieces", required_argument, 0, 'p'},
			{0, 0, 0, 0}
		};
		/* getopt_long stores the option index here. */
		int option_index = 0;

		option = getopt_long (argc, argv, 
				"c:i:f:n:w:s:b:d:a:hvr:q:Q:tp:",
				long_options, &option_index);

		/* Detect the end of the options. */
		if (option == -1)
		break;

		switch (option) {
			case 'v':	
			cfg.verbose++;
			break;
			case 'c':
			cfg.channel = atoi(optarg);
			break;
			case 'i':	
			strncpy(cfg.device, optarg, sizeof(cfg.device)-1);
			break;
			case 'f':	
			strncpy(cfg.filename, optarg, sizeof(cfg.filename)-1);
			break;
			case 'n':   
			cfg.count = atoi(optarg);
			break;
			case 'w':   
			strncpy(cfg.usleep_s, optarg, sizeof(cfg.usleep_s)-1);
			break;
			case 's':  
			strncpy(opt_src, optarg, sizeof(opt_src)-1);
			opt_srcset=1;
			break;
			case 'd':   
			strncpy(opt_dst, optarg, sizeof(opt_dst)-1);
			opt_dstset=1;
			break;
			case 'b':   
			strncpy(opt_bssid, optarg, sizeof(opt_bssid)-1);
			opt_bssidset=1;
			break;
			case 'a':
			strncpy(opt_bssid, optarg, sizeof(opt_wds)-1);
			opt_wdsset=1;
			break;
			case 'r':
			drivertype = tx80211_resolvecard(optarg);
			break;
			case 'q':
			strncpy(opt_seqnum, optarg, sizeof(opt_seqnum)-1);
			opt_seqnumset=1;
			break;
			case 'Q':
			strncpy(opt_seqnum, optarg, sizeof(opt_seqnum)-1);
			opt_seqnumset=1;
			opt_seqnumincset=1;
			break;
			case 't':
			strncpy(cfg.usleep_s, "u100000", 
					sizeof(cfg.usleep_s)-1);
			break;
			case 'p':
			cfg.fragpieces = atoi(optarg);
			break;
			default:	
			usage("");
			exit(1);
		}
	}

	if (*cfg.device == 0 || *cfg.filename == 0) {
		usage("Must specify -i and -f");
		return(1);
	}

	if (drivertype == INJ_NODRIVER) {
		usage("Driver name not recognized.\n");
		return(1);
	}

	/* Initialize */
	if (tx80211_init(&in_tx, cfg.device, drivertype) < 0) {
		perror("tx80211_init");
		return 1;
	}

	/* Open the interface to get a socket */
	ret = tx80211_open(&in_tx);
	if (ret < 0) {
		fprintf(stderr, "Unable to open interface %s: %s.\n", 
		cfg.device, in_tx.errstr);
		return 1;
	}

	/* Set packet injection mode */
	ret = tx80211_setfunctionalmode(&in_tx, TX80211_FUNCMODE_INJECT);
	if (ret != 0) {
		fprintf(stderr, "Error setting mode, returned %d.\n", ret);
		return 1;
	}

	/* Switch to the given channel */
	if (cfg.channel != 0) {
		ret = tx80211_setchannel(&in_tx, cfg.channel);
		if (ret < 0) {
			fprintf(stderr, "Error setting channel, returned %d."
					"\n", ret);
			return 1;
		}
	}

	/* Amount of time to sleep between packets.  If we get uXXX, treat that 
	   as a sleep time in usec, otherwise assume it is in seconds  */
	if (*cfg.usleep_s != 0) {
		if (*cfg.usleep_s == 'u') {
			cfg.usleep_s[0] = '0';
			cfg.usleep = atoi(cfg.usleep_s);
		} else {
			cfg.usleep = (atoi(cfg.usleep_s) * 1000000);
		}
	} else {
		cfg.usleep = 0;
	}


	/* Test address parameters to detect malformed MAC's */
	if (opt_srcset) {
		if (string_to_mac(opt_src, src) != 0) {
			usage("Invalid src address.");
			return(1);
		}
	}

	if (opt_dstset) {
		if (string_to_mac(opt_dst, dst) != 0) {
			usage("Invalid dst address.");
			return(1);
		}
	}

	if (opt_bssidset) {
		if (string_to_mac(opt_bssid, bssid) != 0) {
			usage("Invalid bssid address.");
			return(1);
		}
	}

	if (opt_wdsset) {
		if (string_to_mac(opt_wds, wds) != 0) {
			usage("Invalid WDS address.");
			return(1);
		}
	}

	/* Read file to inject, storing contents in buffer, return packet 
	   length */
	plen = readfile(buffer, &cfg);
	if (plen < MINPACKETSIZE) {
		fprintf(stderr, "Error reading input file %s.\n", cfg.filename);
		return(-1);
	}

	dot11ptr = (struct ieee80211 *)&buffer[0];
	dot11ptra4 = (struct ieee80211a4 *)&buffer[0];

	/* If we passed alternative source, destination or bssid addresses at 
	the command line, copy them over the addresses used in the input file. 
	XXX This is broken, since it does not take into considertation the
	status of the From and To DS flags.  For practical purposes, it 
	assumes that we are injecting packets as a wireless station to the AP */
	if (opt_dstset) {
		memcpy(dot11ptr->addr1, dst, sizeof(dot11ptr->addr1));
	}

	if (opt_srcset) {
		memcpy(dot11ptr->addr2, src, sizeof(dot11ptr->addr2));
	}

	if (opt_bssidset) {
		memcpy(dot11ptr->addr3, bssid, sizeof(dot11ptr->addr3));
	}

	if (opt_seqnumset) {
		/* Test driver for capability to specify sequence
		   number */
		if ((tx80211_getcapabilities(&in_tx) & TX80211_CAP_SEQ)
				== 0) {
			fprintf(stderr, "Driver does not support "
					"specifying a "
					"sequence number.\n");
			return -1;
		}

		seqnum = getseqnum(opt_seqnum);

		/* test for invalid sequence number > 4095 */
		if (seqnum > 4095) {
			fprintf(stderr, "Invalid sequence numberi "
					"(max 4095).\n");
			return(-1);
		}

	}

	if (cfg.fragpieces > 0) {
		/* Fragment payload into the specified number of
		   fragments */
		if ((tx80211_getcapabilities(&in_tx) &
				TX80211_CAP_FRAG) == 0) {
			fprintf(stderr, "Driver does not support "
					"fragmentation.\n");
			return -1;
		}
	}

	if (opt_wdsset) {
		if (plen < A4MINLEN) {
			fprintf(stderr, "Frame length (%d) too small for WDS."
					"\n", plen);
			return(-1);
		} else {
			memcpy(dot11ptra4->addr4, wds, 
					sizeof(dot11ptra4->addr4));
			if (opt_seqnumset) dot11ptra4->sequence = seqnum;
		}

	} else { /* Assume 3-address header */
		if (opt_seqnumset) dot11ptr->sequence = seqnum;

	}


	/* Send the data as a frame */
	printf("Transmitting packets ... ");
	fflush(stdout);
	for (i=0; i < cfg.count; i++) {

		if (cfg.verbose) {
			lamont_hdump(buffer, plen);
			printf("Packet length: %d\n", plen);
		}
		ret = sendpackets(&in_tx, &cfg, buffer, plen);
		if (ret < plen) {
			fprintf(stderr, "Error transmitting packet: %s\n",
					in_tx.errstr);
			return -1;
		}
		usleep(cfg.usleep);

		/* Support for spoofing sequential sequence numbers */
		if (opt_seqnumincset) {
			dot11ptr->sequence++;
			if (dot11ptr->sequence > 4095) {
				dot11ptr->sequence=0;
			}
		}
	}

	/* Close the socket */
	tx80211_close(&in_tx);

	printf("Done\n");

	return(0);
}

