/*
 * file2air - injects binary files as packets onto 802.11 networks
 *
 * $Id: crc.h,v 1.1 2005/03/16 11:23:41 jwright Exp $
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

unsigned long crc32(unsigned char *buffer,int buffer_len);

