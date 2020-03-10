/*
 *  aesrandom.c
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

#include <stdio.h>

#include "aesrandom.h"

#ifdef WIN32

#include <windows.h>

void *aesrandom_open()
{
    HCRYPTPROV hProv;
    DWORD      result_code;

    if (!CryptAcquireContext(   &hProv,
                                NULL,
                                NULL,
                                PROV_RSA_FULL,
                                CRYPT_VERIFYCONTEXT))
    {
        result_code = GetLastError();
        if (GetLastError() == (DWORD)NTE_BAD_KEYSET)
        {
            if (!CryptAcquireContext(   &hProv,
                                        NULL,
                                        NULL,
                                        PROV_RSA_FULL,
                                        CRYPT_NEWKEYSET|CRYPT_VERIFYCONTEXT))
            {
                result_code = GetLastError();
            }
            else
            {
                result_code = ERROR_SUCCESS;
            }
        }

        if (result_code != ERROR_SUCCESS)
        {
            return NULL;
        }
    }

    return (void*)hProv;
}

void aesrandom_close(void *aesrandom)
{
    CryptReleaseContext((HCRYPTPROV)aesrandom, 0);
}

int aesrandom_read(void *aesrandom, unsigned char *buffer, size_t size)
{
    if (!CryptGenRandom((HCRYPTPROV)aesrandom,
                        size,
                        (BYTE *) buffer))
    {
        return 0;
    }

    return size;
}

#else

void *aesrandom_open()
{
    return fopen("/dev/urandom", "r");
}

void aesrandom_close(void *aesrandom)
{
    fclose((FILE*)aesrandom);
}

int aesrandom_read(void *aesrandom, unsigned char *buffer, size_t size)
{
    return fread(buffer, 1, size, (FILE*)aesrandom);
}

#endif
