/*
 *  aesrandom.h
 *  Copyright (C) 2014
 *
 *  Contributors:
 *      Glenn Washburn <crass@berlios.de>
 *      Paul E. Jones <paulej@packetizer.com>
 *      Mauro Gilardi <galvao.m@gmail.com>
 *      Alon Bar-Lev <alon.barlev@gmail.com>
 *
 * This software is licensed as "freeware."  Permission to distribute
 * this software in source and binary forms is hereby granted without a
 * fee.  THIS SOFTWARE IS PROVIDED 'AS IS' AND WITHOUT ANY EXPRESSED OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * THE AUTHOR SHALL NOT BE HELD LIABLE FOR ANY DAMAGES RESULTING FROM
 * THE USE OF THIS SOFTWARE, EITHER DIRECTLY OR INDIRECTLY, INCLUDING,
 * BUT NOT LIMITED TO, LOSS OF DATA OR DATA BEING RENDERED INACCURATE.
 *
 */

#ifndef __AESCRYPT_AESRANDOM_H__

void *aesrandom_open();
void aesrandom_close(void *aesrandom);
int aesrandom_read(void *aesrandom, unsigned char *buffer, size_t size);

#endif /* __AESCRYPT_AESRANDOM_H__ */
