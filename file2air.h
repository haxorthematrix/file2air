/*
 * file2air - injects binary files as packets onto 802.11 networks
 *
 * $Id: file2air.h,v 1.8 2007/02/08 20:47:52 jwright Exp $
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

#define MAXCHANNEL 11
#define MAXPACKETSIZE 2312
#define MINPACKETSIZE 10
#define A4MINLEN 30
#define PROGNAME "file2air"
#define VER "1.1"

struct optcfg {
    char		device[IFNAMSIZ+1];
    int			verbose;
    char		filename[1024];
    int			mode;
    int			monitor;
    int			channel;
    int			count;
    char		usleep_s[16+1];
    int			usleep;
    int         fragpieces;
};

struct ieee80211 {
    u8    version:2;
    u8    type:2;
    u8    subtype:4;
    u8    to_ds:1;
    u8    from_ds:1;
    u8    more_frag:1;
    u8    retry:1;
    u8    pwrmgmt:1;
    u8    more_data:1;
    u8    wep:1;
    u8    order:1;
    u16	  duration;
    u8    addr1[6];
    u8    addr2[6];
    u8    addr3[6];
    u16   fragment:4;
    u16   sequence:12;
} __attribute__ ((packed));

struct ieee80211a4 {
    u8    version:2;
    u8    type:2;
    u8    subtype:4;
    u8    to_ds:1;
    u8    from_ds:1;
    u8    more_frag:1;
    u8    retry:1;
    u8    pwrmgmt:1;
    u8    more_data:1;
    u8    wep:1;
    u8    order:1;
    u16	  duration;
    u8    addr1[6];
    u8    addr2[6];
    u8    addr3[6];
    u8    addr4[6];
    u16   fragment:4;
    u16   sequence:12;
} __attribute__ ((packed));

/* Prototypes */
void usage(char *n);
int sendpackets(struct tx80211 *in_tx, struct optcfg *cfg, 
                unsigned char *packet, int plen);
