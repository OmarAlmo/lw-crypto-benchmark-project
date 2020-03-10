/*
 * util.c
 *
 * Copyright (C) 2014
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

#include <string.h>

/*
 * explicit_bzero taken from NetBSD, modified to be a pure wrapper to
 * memset()
 * The compiler will not optimize a call to a volatile function pointer
 * so we use this function to clean up sensitive memory areas.
 */

void *memset_secure(void *b, int c, size_t len)
{
    static void *(*volatile memset_impl)(void *, int, size_t) = memset;
    return (*memset_impl)(b, c, len);
}
