/*
 *  AES Crypt for Linux
 *  Copyright (C) 2007-2017
 *
 *  Contributors:
 *      Glenn Washburn <crass@berlios.de>
 *      Paul E. Jones <paulej@packetizer.com>
 *      Mauro Gilardi <galvao.m@gmail.com>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <unistd.h> /* getopt */
#include <getopt.h>
#include <assert.h>
#include <stdlib.h> /* malloc */
#include <time.h>   /* time */
#include <errno.h>  /* errno */
#include "aescrypt.h"
#include "password.h"
#include "keyfile.h"
#include "util.h"
#include "aesrandom.h"

#define KAT_SUCCESS 0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR -3
#define KAT_CRYPTO_FAILURE -4

#define MAX_FILE_NAME 256
#define MAX_MESSAGE_LENGTH 32
#define MAX_ASSOCIATED_DATA_LENGTH 32

/*
 *  encrypt_stream
 *
 *  This function is called to encrypt the open data steam "infp".
 */
int encrypt_stream(FILE *infp, FILE *outfp, unsigned char *passwd, int passlen)
{
    aes_context aes_ctx;
    sha256_context sha_ctx;
    aescrypt_hdr aeshdr;
    sha256_t digest;
    unsigned char IV[16];
    unsigned char iv_key[48];
    unsigned i, j;
    size_t bytes_read;
    unsigned char buffer[32];
    unsigned char ipad[64], opad[64];
    time_t current_time;
    pid_t process_id;
    void *aesrand;
    unsigned char tag_buffer[256];

    /*
     * Open the source for random data.  Note that while the entropy
     * might be lower with /dev/urandom than /dev/random, it will not
     * fail to produce something.  Also, we're going to hash the result
     * anyway.
     */
    if ((aesrand = aesrandom_open()) == NULL)
    {
        perror("Error open random:");
        return -1;
    }

    /*
     * Create the 16-octet IV and 32-octet encryption key
     * used for encrypting the plaintext file.  We do
     * not trust the rand() function, so we improve on
     * that by also hashing the random digits and using
     * only a portion of the hash.  This IV and key
     * generation could be replaced with any good random
     * source of data.
     */
    memset(iv_key, 0, 48);
    for (i = 0; i < 48; i += 16)
    {
        memset(buffer, 0, 32);
        sha256_starts(&sha_ctx);
        for (j = 0; j < 256; j++)
        {
            if ((bytes_read = aesrandom_read(aesrand, buffer, 32)) != 32)
            {
                fprintf(stderr, "Error: Couldn't read from random : %u\n",
                        (unsigned)bytes_read);
                aesrandom_close(aesrand);
                return -1;
            }
            sha256_update(&sha_ctx, buffer, 32);
        }
        sha256_finish(&sha_ctx, digest);
        memcpy(iv_key + i, digest, 16);
    }

    /*
     * Write an AES signature at the head of the file, along
     * with the AES file format version number.
     */
    buffer[0] = 'A';
    buffer[1] = 'E';
    buffer[2] = 'S';
    buffer[3] = (unsigned char)0x02; /* Version 2 */
    buffer[4] = '\0';                /* Reserved for version 0 */
    if (fwrite(buffer, 1, 5, outfp) != 5)
    {
        fprintf(stderr, "Error: Could not write out header data\n");
        aesrandom_close(aesrand);
        return -1;
    }

    /* Write out the CREATED-BY tag */
    // j = 11 +                     /* "CREATED-BY\0" */
    //     strlen(PACKAGE_NAME) +   /* Program name */
    //     1 +                      /* Space */
    //     strlen(PACKAGE_VERSION); /* Program version ID */

    /*
     * Our extension buffer is only 256 octets long, so
     * let's not write an extension if it is too big
     */
    if (j < 256)
    {
        buffer[0] = '\0';
        buffer[1] = (unsigned char)(j & 0xff);
        if (fwrite(buffer, 1, 2, outfp) != 2)
        {
            fprintf(stderr, "Error: Could not write tag to AES file (1)\n");
            aesrandom_close(aesrand);
            return -1;
        }

        strncpy((char *)tag_buffer, "CREATED_BY", 255);
        tag_buffer[255] = '\0';
        if (fwrite(tag_buffer, 1, 11, outfp) != 11)
        {
            fprintf(stderr, "Error: Could not write tag to AES file (2)\n");
            aesrandom_close(aesrand);
            return -1;
        }

        // sprintf((char *)tag_buffer, "%s %s", PACKAGE_NAME, PACKAGE_VERSION);
        j = strlen((char *)tag_buffer);
        if (fwrite(tag_buffer, 1, j, outfp) != j)
        {
            fprintf(stderr, "Error: Could not write tag to AES file (3)\n");
            aesrandom_close(aesrand);
            return -1;
        }
    }

    /* Write out the "container" extension */
    buffer[0] = '\0';
    buffer[1] = (unsigned char)128;
    if (fwrite(buffer, 1, 2, outfp) != 2)
    {
        fprintf(stderr, "Error: Could not write tag to AES file (4)\n");
        aesrandom_close(aesrand);
        return -1;
    }
    memset(tag_buffer, 0, 128);
    if (fwrite(tag_buffer, 1, 128, outfp) != 128)
    {
        fprintf(stderr, "Error: Could not write tag to AES file (5)\n");
        aesrandom_close(aesrand);
        return -1;
    }

    /* Write out 0x0000 to indicate that no more extensions exist */
    buffer[0] = '\0';
    buffer[1] = '\0';
    if (fwrite(buffer, 1, 2, outfp) != 2)
    {
        fprintf(stderr, "Error: Could not write tag to AES file (6)\n");
        aesrandom_close(aesrand);
        return -1;
    }

    /*
     * We will use an initialization vector comprised of the current time
     * process ID, and random data, all hashed together with SHA-256.
     */
    current_time = time(NULL);
    for (i = 0; i < 8; i++)
    {
        buffer[i] = (unsigned char)(current_time >> (i * 8));
    }
    process_id = getpid();
    for (i = 0; i < 8; i++)
    {
        buffer[i + 8] = (unsigned char)(process_id >> (i * 8));
    }

    sha256_starts(&sha_ctx);
    sha256_update(&sha_ctx, buffer, 16);

    for (i = 0; i < 256; i++)
    {
        if (aesrandom_read(aesrand, buffer, 32) != 32)
        {
            fprintf(stderr, "Error: Couldn't read from /dev/random\n");
            aesrandom_close(aesrand);
            return -1;
        }
        sha256_update(&sha_ctx,
                      buffer,
                      32);
    }

    sha256_finish(&sha_ctx, digest);

    memcpy(IV, digest, 16);

    /* We're finished collecting random data */
    aesrandom_close(aesrand);

    /* Write the initialization vector to the file */
    if (fwrite(IV, 1, 16, outfp) != 16)
    {
        fprintf(stderr, "Error: Could not write out initialization vector\n");
        return -1;
    }

    /* Hash the IV and password 8192 times */
    memset(digest, 0, 32);
    memcpy(digest, IV, 16);
    for (i = 0; i < 8192; i++)
    {
        sha256_starts(&sha_ctx);
        sha256_update(&sha_ctx, digest, 32);
        sha256_update(&sha_ctx,
                      passwd,
                      (unsigned long)passlen);
        sha256_finish(&sha_ctx,
                      digest);
    }

    /* Set the AES encryption key */
    aes_set_key(&aes_ctx, digest, 256);

    /*
     * Set the ipad and opad arrays with values as
     * per RFC 2104 (HMAC).  HMAC is defined as
     *   H(K XOR opad, H(K XOR ipad, text))
     */
    memset(ipad, 0x36, 64);
    memset(opad, 0x5C, 64);

    for (i = 0; i < 32; i++)
    {
        ipad[i] ^= digest[i];
        opad[i] ^= digest[i];
    }

    sha256_starts(&sha_ctx);
    sha256_update(&sha_ctx, ipad, 64);

    /*
     * Encrypt the IV and key used to encrypt the plaintext file,
     * writing that encrypted text to the output file.
     */
    for (i = 0; i < 48; i += 16)
    {
        /*
         * Place the next 16 octets of IV and key buffer into
         * the input buffer.
         */
        memcpy(buffer, iv_key + i, 16);

        /*
         * XOR plain text block with previous encrypted
         * output (i.e., use CBC)
         */
        for (j = 0; j < 16; j++)
        {
            buffer[j] ^= IV[j];
        }

        /* Encrypt the contents of the buffer */
        aes_encrypt(&aes_ctx, buffer, buffer);

        /* Concatenate the "text" as we compute the HMAC */
        sha256_update(&sha_ctx, buffer, 16);

        /* Write the encrypted block */
        if (fwrite(buffer, 1, 16, outfp) != 16)
        {
            fprintf(stderr, "Error: Could not write iv_key data\n");
            return -1;
        }

        /* Update the IV (CBC mode) */
        memcpy(IV, buffer, 16);
    }

    /* Write the HMAC */
    sha256_finish(&sha_ctx, digest);
    sha256_starts(&sha_ctx);
    sha256_update(&sha_ctx, opad, 64);
    sha256_update(&sha_ctx, digest, 32);
    sha256_finish(&sha_ctx, digest);
    /* Write the encrypted block */
    if (fwrite(digest, 1, 32, outfp) != 32)
    {
        fprintf(stderr, "Error: Could not write iv_key HMAC\n");
        return -1;
    }

    /* Re-load the IV and encryption key with the IV and
     * key to now encrypt the datafile.  Also, reset the HMAC
     * computation.
     */
    memcpy(IV, iv_key, 16);

    /* Set the AES encryption key */
    aes_set_key(&aes_ctx, iv_key + 16, 256);

    /*
     * Set the ipad and opad arrays with values as
     * per RFC 2104 (HMAC).  HMAC is defined as
     *   H(K XOR opad, H(K XOR ipad, text))
     */
    memset(ipad, 0x36, 64);
    memset(opad, 0x5C, 64);

    for (i = 0; i < 32; i++)
    {
        ipad[i] ^= iv_key[i + 16];
        opad[i] ^= iv_key[i + 16];
    }

    /* Wipe the IV and encryption key from memory */
    memset_secure(iv_key, 0, 48);

    sha256_starts(&sha_ctx);
    sha256_update(&sha_ctx, ipad, 64);

    /* Initialize the last_block_size value to 0 */
    aeshdr.last_block_size = 0;

    while ((bytes_read = fread(buffer, 1, 16, infp)) > 0)
    {
        /*
         * XOR plain text block with previous encrypted
         * output (i.e., use CBC)
         */
        for (i = 0; i < 16; i++)
        {
            buffer[i] ^= IV[i];
        }

        /* Encrypt the contents of the buffer */
        aes_encrypt(&aes_ctx, buffer, buffer);

        /* Concatenate the "text" as we compute the HMAC */
        sha256_update(&sha_ctx, buffer, 16);

        /* Write the encrypted block */
        if (fwrite(buffer, 1, 16, outfp) != 16)
        {
            fprintf(stderr, "Error: Could not write to output file\n");
            return -1;
        }

        /* Update the IV (CBC mode) */
        memcpy(IV, buffer, 16);

        /* Assume this number of octets is the file modulo */
        aeshdr.last_block_size = bytes_read;
    }

    /* Check to see if we had a read error */
    if (ferror(infp))
    {
        fprintf(stderr, "Error: Couldn't read input file\n");
        return -1;
    }

    /* Write the file size modulo */
    buffer[0] = (char)(aeshdr.last_block_size & 0x0F);
    if (fwrite(buffer, 1, 1, outfp) != 1)
    {
        fprintf(stderr, "Error: Could not write the file size modulo\n");
        return -1;
    }

    /* Write the HMAC */
    sha256_finish(&sha_ctx, digest);
    sha256_starts(&sha_ctx);
    sha256_update(&sha_ctx, opad, 64);
    sha256_update(&sha_ctx, digest, 32);
    sha256_finish(&sha_ctx, digest);
    if (fwrite(digest, 1, 32, outfp) != 32)
    {
        fprintf(stderr, "Error: Could not write the file HMAC\n");
        return -1;
    }

    /* Flush the output buffer to ensure all data is written to disk */
    if (fflush(outfp))
    {
        fprintf(stderr, "Error: Could not flush output file buffer\n");
        return -1;
    }

    return 0;
}

int readFile(char *fileName, char *out_msg)
{
    FILE *file = fopen(fileName, "r");
    char *code;
    size_t n = 0;
    int c;

    if (file == NULL)
        return -1; // could not open file
    fseek(file, 0, SEEK_END);
    long f_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    code = (char *)malloc(f_size + 1);

    while ((c = fgetc(file)) != EOF)
    {
        code[n++] = (char)c;
    }

    code[n] = '\0';
    strcpy(out_msg, code);
    free(code);
    fclose(file);
    return 0;
}

int get_file_size(char *file_name)
{
    // opening the file in read mode
    FILE *fp = fopen(file_name, "r");

    // checking if the file exist or not
    if (fp == NULL)
    {
        printf("%s File Not Found!\n", file_name);
        return -1;
    }

    fseek(fp, 0L, SEEK_END);

    // calculating the size of the file
    int res = ftell(fp);
    // closing the file
    fclose(fp);

    return res;
}

/*
 *  decrypt_stream
 *
 *  This function is called to decrypt the open data steam "infp".
 */
int decrypt_stream(FILE *infp, FILE *outfp, unsigned char *passwd, int passlen)
{
    aes_context aes_ctx;
    sha256_context sha_ctx;
    aescrypt_hdr aeshdr;
    sha256_t digest;
    unsigned char IV[16];
    unsigned char iv_key[48];
    unsigned i, j, n;
    size_t bytes_read;
    unsigned char buffer[64], buffer2[32];
    unsigned char *head, *tail;
    unsigned char ipad[64], opad[64];
    int reached_eof = 0;

    /* Read the file header */
    if ((bytes_read = fread(&aeshdr, 1, sizeof(aeshdr), infp)) !=
        sizeof(aescrypt_hdr))
    {
        if (feof(infp))
        {
            fprintf(stderr, "Error: Input file is too short.\n");
        }
        else
        {
            perror("Error reading the file header:");
        }
        return -1;
    }

    if (!(aeshdr.aes[0] == 'A' && aeshdr.aes[1] == 'E' &&
          aeshdr.aes[2] == 'S'))
    {
        fprintf(stderr, "Error: Bad file header (not aescrypt file or is corrupted? [%x, %x, %x])\n", aeshdr.aes[0], aeshdr.aes[1], aeshdr.aes[2]);
        return -1;
    }

    /* Validate the version number and take any version-specific actions */
    if (aeshdr.version == 0)
    {
        /*
         * Let's just consider the least significant nibble to determine
         * the size of the last block
         */
        aeshdr.last_block_size = (aeshdr.last_block_size & 0x0F);
    }
    else if (aeshdr.version > 0x02)
    {
        fprintf(stderr, "Error: Unsupported AES file version: %d\n",
                aeshdr.version);
        return -1;
    }

    /* Skip over extensions present v2 and later files */
    if (aeshdr.version >= 0x02)
    {
        do
        {
            if ((bytes_read = fread(buffer, 1, 2, infp)) != 2)
            {
                if (feof(infp))
                {
                    fprintf(stderr, "Error: Input file is too short.\n");
                }
                else
                {
                    perror("Error reading the file extensions:");
                }
                return -1;
            }
            /* Determine the extension length, zero means no more extensions */
            i = j = (((int)buffer[0]) << 8) | (int)buffer[1];
            while (i--)
            {
                if ((bytes_read = fread(buffer, 1, 1, infp)) != 1)
                {
                    if (feof(infp))
                    {
                        fprintf(stderr, "Error: Input file is too short.\n");
                    }
                    else
                    {
                        perror("Error reading the file extensions:");
                    }
                    return -1;
                }
            }
        } while (j);
    }

    /* Read the initialization vector from the file */
    if ((bytes_read = fread(IV, 1, 16, infp)) != 16)
    {
        if (feof(infp))
        {
            fprintf(stderr, "Error: Input file is too short.\n");
        }
        else
        {
            perror("Error reading the initialization vector:");
        }
        return -1;
    }

    /* Hash the IV and password 8192 times */
    memset(digest, 0, 32);
    memcpy(digest, IV, 16);
    for (i = 0; i < 8192; i++)
    {
        sha256_starts(&sha_ctx);
        sha256_update(&sha_ctx, digest, 32);
        sha256_update(&sha_ctx,
                      passwd,
                      passlen);
        sha256_finish(&sha_ctx,
                      digest);
    }

    /* Set the AES encryption key */
    aes_set_key(&aes_ctx, digest, 256);

    /* Set the ipad and opad arrays with values as
     * per RFC 2104 (HMAC).  HMAC is defined as
     *   H(K XOR opad, H(K XOR ipad, text))
     */
    memset(ipad, 0x36, 64);
    memset(opad, 0x5C, 64);

    for (i = 0; i < 32; i++)
    {
        ipad[i] ^= digest[i];
        opad[i] ^= digest[i];
    }

    sha256_starts(&sha_ctx);
    sha256_update(&sha_ctx, ipad, 64);

    /* If this is a version 1 or later file, then read the IV and key
     * for decrypting the bulk of the file.
     */
    if (aeshdr.version >= 0x01)
    {
        for (i = 0; i < 48; i += 16)
        {
            if ((bytes_read = fread(buffer, 1, 16, infp)) != 16)
            {
                if (feof(infp))
                {
                    fprintf(stderr, "Error: Input file is too short.\n");
                }
                else
                {
                    perror("Error reading input file IV and key:");
                }
                return -1;
            }

            memcpy(buffer2, buffer, 16);

            sha256_update(&sha_ctx, buffer, 16);
            aes_decrypt(&aes_ctx, buffer, buffer);

            /*
             * XOR plain text block with previous encrypted
             * output (i.e., use CBC)
             */
            for (j = 0; j < 16; j++)
            {
                iv_key[i + j] = (buffer[j] ^ IV[j]);
            }

            /* Update the IV (CBC mode) */
            memcpy(IV, buffer2, 16);
        }

        /* Verify that the HMAC is correct */
        sha256_finish(&sha_ctx, digest);
        sha256_starts(&sha_ctx);
        sha256_update(&sha_ctx, opad, 64);
        sha256_update(&sha_ctx, digest, 32);
        sha256_finish(&sha_ctx, digest);

        if ((bytes_read = fread(buffer, 1, 32, infp)) != 32)
        {
            if (feof(infp))
            {
                fprintf(stderr, "Error: Input file is too short.\n");
            }
            else
            {
                perror("Error reading input file digest:");
            }
            return -1;
        }

        if (memcmp(digest, buffer, 32))
        {
            fprintf(stderr, "Error: Message has been altered or password is incorrect\n");
            return -1;
        }

        /*
         * Re-load the IV and encryption key with the IV and
         * key to now encrypt the datafile.  Also, reset the HMAC
         * computation.
         */
        memcpy(IV, iv_key, 16);

        /* Set the AES encryption key */
        aes_set_key(&aes_ctx, iv_key + 16, 256);

        /*
         * Set the ipad and opad arrays with values as
         * per RFC 2104 (HMAC).  HMAC is defined as
         *   H(K XOR opad, H(K XOR ipad, text))
         */
        memset(ipad, 0x36, 64);
        memset(opad, 0x5C, 64);

        for (i = 0; i < 32; i++)
        {
            ipad[i] ^= iv_key[i + 16];
            opad[i] ^= iv_key[i + 16];
        }

        /* Wipe the IV and encryption key from memory */
        memset_secure(iv_key, 0, 48);

        sha256_starts(&sha_ctx);
        sha256_update(&sha_ctx, ipad, 64);
    }

    /*
     * Decrypt the balance of the file
     *
     * Attempt to initialize the ring buffer with contents from the file.
     * Attempt to read 48 octets of the file into the ring buffer.
     */
    if ((bytes_read = fread(buffer, 1, 48, infp)) < 48)
    {
        if (!feof(infp))
        {
            perror("Error reading input file ring:");
            return -1;
        }
        else
        {
            /*
             * If there are less than 48 octets, the only valid count
             * is 32 for version 0 (HMAC) and 33 for version 1 or
             * greater files ( file size modulo + HMAC)
             */
            if ((aeshdr.version == 0x00 && bytes_read != 32) ||
                (aeshdr.version >= 0x01 && bytes_read != 33))
            {
                fprintf(stderr, "Error: Input file is corrupt (1:%u).\n",
                        (unsigned)bytes_read);
                return -1;
            }
            else
            {
                /*
                 * Version 0 files would have the last block size
                 * read as part of the header, so let's grab that
                 * value now for version 1 files.
                 */
                if (aeshdr.version >= 0x01)
                {
                    /*
                     * The first octet must be the indicator of the
                     * last block size.
                     */
                    aeshdr.last_block_size = (buffer[0] & 0x0F);
                }
                /*
                 * If this initial read indicates there is no encrypted
                 * data, then there should be 0 in the last_block_size field
                 */
                if (aeshdr.last_block_size != 0)
                {
                    fprintf(stderr, "Error: Input file is corrupt (2).\n");
                    return -1;
                }
            }
            reached_eof = 1;
        }
    }
    head = buffer + 48;
    tail = buffer;

    while (!reached_eof)
    {
        /* Check to see if the head of the buffer is past the ring buffer */
        if (head == (buffer + 64))
        {
            head = buffer;
        }

        if ((bytes_read = fread(head, 1, 16, infp)) < 16)
        {
            if (!feof(infp))
            {
                perror("Error reading input file:");
                return -1;
            }
            else
            {
                /* The last block for v0 must be 16 and for v1 it must be 1 */
                if ((aeshdr.version == 0x00 && bytes_read > 0) ||
                    (aeshdr.version >= 0x01 && bytes_read != 1))
                {
                    fprintf(stderr, "Error: Input file is corrupt (3:%u).\n",
                            (unsigned)bytes_read);
                    return -1;
                }

                /*
                 * If this is a v1 file, then the file modulo is located
                 * in the ring buffer at tail + 16 (with consideration
                 * given to wrapping around the ring, in which case
                 * it would be at buffer[0])
                 */
                if (aeshdr.version >= 0x01)
                {
                    if ((tail + 16) < (buffer + 64))
                    {
                        aeshdr.last_block_size = (tail[16] & 0x0F);
                    }
                    else
                    {
                        aeshdr.last_block_size = (buffer[0] & 0x0F);
                    }
                }

                /* Indicate that we've reached the end of the file */
                reached_eof = 1;
            }
        }

        /*
         * Process data that has been read.  Note that if the last
         * read operation returned no additional data, there is still
         * one one ciphertext block for us to process if this is a v0 file.
         */
        if ((bytes_read > 0) || (aeshdr.version == 0x00))
        {
            /* Advance the head of the buffer forward */
            if (bytes_read > 0)
            {
                head += 16;
            }

            memcpy(buffer2, tail, 16);

            sha256_update(&sha_ctx, tail, 16);
            aes_decrypt(&aes_ctx, tail, tail);

            /*
             * XOR plain text block with previous encrypted
             * output (i.e., use CBC)
             */
            for (i = 0; i < 16; i++)
            {
                tail[i] ^= IV[i];
            }

            /* Update the IV (CBC mode) */
            memcpy(IV, buffer2, 16);

            /*
             * If this is the final block, then we may
             * write less than 16 octets
             */
            n = ((!reached_eof) ||
                 (aeshdr.last_block_size == 0))
                    ? 16
                    : aeshdr.last_block_size;

            /* Write the decrypted block */
            if ((i = fwrite(tail, 1, n, outfp)) != n)
            {
                perror("Error writing decrypted block:");
                return -1;
            }

            /* Move the tail of the ring buffer forward */
            tail += 16;
            if (tail == (buffer + 64))
            {
                tail = buffer;
            }
        }
    }

    /* Verify that the HMAC is correct */
    sha256_finish(&sha_ctx, digest);
    sha256_starts(&sha_ctx);
    sha256_update(&sha_ctx, opad, 64);
    sha256_update(&sha_ctx, digest, 32);
    sha256_finish(&sha_ctx, digest);

    /* Copy the HMAC read from the file into buffer2 */
    if (aeshdr.version == 0x00)
    {
        memcpy(buffer2, tail, 16);
        tail += 16;
        if (tail == (buffer + 64))
        {
            tail = buffer;
        }
        memcpy(buffer2 + 16, tail, 16);
    }
    else
    {
        memcpy(buffer2, tail + 1, 15);
        tail += 16;
        if (tail == (buffer + 64))
        {
            tail = buffer;
        }
        memcpy(buffer2 + 15, tail, 16);
        tail += 16;
        if (tail == (buffer + 64))
        {
            tail = buffer;
        }
        memcpy(buffer2 + 31, tail, 1);
    }

    if (memcmp(digest, buffer2, 32))
    {
        if (aeshdr.version == 0x00)
        {
            fprintf(stderr, "Error: Message has been altered or password is incorrect\n");
        }
        else
        {
            fprintf(stderr, "Error: Message has been altered and should not be trusted\n");
        }

        return -1;
    }

    /* Flush the output buffer to ensure all data is written to disk */
    if (fflush(outfp))
    {
        fprintf(stderr, "Error: Could not flush output file buffer\n");
        return -1;
    }

    return 0;
}

/*
 *  usage
 *
 *  Displays the program usage to the user.
 */
void usage(const char *progname)
{
    const char *progname_real; /* contains the real name of the program */
                               /*  (without path) */

    progname_real = strrchr(progname, '/');

    if (progname_real == NULL) /* no path in progname: use progname */
    {
        progname_real = progname;
    }
    else
    {
        progname_real++;
    }

    fprintf(stderr, "\nusage: %s {-e|-d} [ { -p <password> | -k <keyfile> } ] { [-o <output filename>] <file> | <file> [<file> ...] }\n\n",
            progname_real);
}

/*
 *  version
 *
 *  Displays the program version to the user.
 */
void version(const char *progname)
{
    const char *progname_real; /* contains the real name of the program */
                               /*  (without path) */

    progname_real = strrchr(progname, '/');

    if (progname_real == NULL) /* no path in progname: use progname */
    {
        progname_real = progname;
    }
    else
    {
        progname_real++;
    }

    // fprintf(stderr, "\n%s version %s (%s)\n\n",
    //         progname_real, PACKAGE_VERSION, PACKAGE_DATE);
}

/*
 *  cleanup
 *
 *  Removes output files that are not fully and properly created.
 */
void cleanup(const char *outfile)
{
    if (strcmp(outfile, "-") && outfile[0] != '\0')
    {
        unlink(outfile);
    }
}

void showUsage()
{
    printf(
        " ./ace128 [file_name to encrypt] options\n"
        "\t--key=SOMECAHRATER\n"
        "\t--nonce=SOMECAHRATER\n"
        "\t--associate-data=SOMECAHRATER\n");
}

int benchmark_one_file(char *file_name, unsigned char *key, int keylen,
                       FILE *run_time_fp, int debug)
{
    double encryption_time = 0.0, decryption_time = 0.0;

    size_t length_of_file = get_file_size(file_name);
    double total_d_time;
    int func_ret;
    clock_t total_time = clock();

    FILE *inread = fopen(file_name, "r");
    FILE *outread = fopen("something_idc", "w");
    printf("key %s| len %d | strlen %d \n", key, keylen, strlen(key));
    // encryption
    clock_t t;
    t = clock();
    func_ret = encrypt_stream(inread, outread, key, keylen);
    t = clock() - t;
    encryption_time += ((double)t) / CLOCKS_PER_SEC; // in seconds

    fclose(inread), fclose(outread);

    inread = fopen("something_idc", "r");
    outread = fopen("some_random_decrypt", "w");
    // decryption
    t = clock();
    func_ret = decrypt_stream(inread, outread, key, keylen);
    t = clock() - t;
    decryption_time += ((double)t) / CLOCKS_PER_SEC; // in seconds a

    fclose(inread), fclose(outread);

    total_time = clock() - total_time;
    total_d_time = ((double)total_time) / CLOCKS_PER_SEC;
    printf("\n");

    // output current bench mark result to the csv file
    fprintf(run_time_fp, "%s,%d,%f,%f,%f\n", file_name, length_of_file,
            encryption_time, decryption_time, total_d_time);
    printf("It takes  %.2f s\n", total_d_time);

    return 0;
}

/*
 * main
 *
 */
int main(int argc, char *argv[])
{
    printf("==================================================================\n");
    if (argc < 2 || argc > 7)
    {
        printf("Please provided the file to encrypt\n");
        showUsage();
        return -1;
    };

    unsigned char key[16] = "some_secret_key";
    printf("key %s\n", key);

    encryptmode_t mode = UNINIT;

    int debug = strcmp(argv[argc - 1], "debug") == 0 ? 1 : 0;
    int previous = get_file_size("run_time_bench_mark.csv");
    FILE *benchmark_fp = fopen("run_time_bench_mark.csv", previous == -1 ? "wr" : "a");

    if (previous == -1)
    {
        fprintf(benchmark_fp, "file_name,file_sizes,encryption_time(s),decryption_time(s),total_time(s)\n");
    }
    int result = benchmark_one_file(argv[1], key, 16, benchmark_fp, debug);

    // file_name,run_time_fp,key, keylen
    fclose(benchmark_fp);

    printf("==================================================================\n");

    return 0;
}
