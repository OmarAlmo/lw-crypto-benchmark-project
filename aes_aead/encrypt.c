/* Reference implementation of ACE-128 AEAD
   Written by:
   Kalikinkar Mandal <kmandal@uwaterloo.ca>
*/

#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <stdint.h>

#include "aes.h"
#include "crypto_aead.h"
#include "hmac-sha256.h"
#include "api.h"

#define KAT_SUCCESS 0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR -3
#define KAT_CRYPTO_FAILURE -4

/*
   *rate_bytes: positions of rate bytes in state
*/
const unsigned char rate_bytes[8] = {0, 1, 2, 3, 16, 17, 18, 19};

/*
   *ace_ad: processing associated data
   *adlen: byte-length of ad
   *ad: associated data
   *state: state after initialization,
           and output state is stored
	   in "state" (inplace)
*/
int ace_ad(
    unsigned char *state,
    const unsigned char *ad,
    const u64 adlen)
{
   // unsigned char i, lblen;
   // u64 j, ad64len = adlen / 8;
   // lblen = (unsigned char)(adlen % 8);

   // if (adlen == 0)
   //         return (KAT_SUCCESS);

   // //Absorbing associated data
   // for (j = 0; j < ad64len; j++)
   // {
   //         for (i = 0; i < 8; i++)
   //                 state[rate_bytes[i]] ^= ad[8 * j + ((u64)i)];
   //         //Domain seperator
   //         state[STATEBYTES - 1] ^= (0x01);

   //         ace_permutation(state);
   // }

   // //Process the last 64-bit block.
   // if (lblen != 0)
   // {
   //         for (i = 0; i < lblen; i++)
   //                 state[rate_bytes[i]] ^= ad[ad64len * 8 + (u64)i];

   //         state[rate_bytes[lblen]] ^= (0x80); //Padding: 10*
   //         //Domain seperator
   //         state[STATEBYTES - 1] ^= (0x01);
   //         ace_permutation(state);
   // }
   // else
   // {
   //         state[rate_bytes[0]] ^= (0x80); //Padding: 10*
   //         //Domain seperator
   //         state[STATEBYTES - 1] ^= (0x01);
   //         ace_permutation(state);
   // }

   return (KAT_SUCCESS);
}

/*
   *ace_gentag: generate tag
   *k: key
   *state: state before tag generation
   *tlen: length of tag in byte
   *tag: tag
*/
int ace_gentag(
    unsigned char *tag,
    const unsigned char tlen,
    unsigned char *state,
    const unsigned char *k)
{
   // unsigned char i;
   // if (CRYPTO_KEYBYTES == 16 && tlen == 16)
   // {
   //         //Absorbing first 64-bit (8 bytes) key
   //         for (i = 0; i < 8; i++)
   //                 state[rate_bytes[i]] ^= k[i];

   //         ace_permutation(state);

   //         //Absorbing last 64-bit key
   //         for (i = 0; i < 8; i++)
   //                 state[rate_bytes[i]] ^= k[8 + i];

   //         ace_permutation(state);
   //         //Extracting 128-bit tag from A and C
   //         for (i = 0; i < 8; i++)
   //         {
   //                 tag[i] = state[i];
   //                 tag[8 + i] = state[16 + i];
   //         }
   // }
   // else
   // {
   //         printf("Invalid key and tag length pair.\n");
   //         return KAT_CRYPTO_FAILURE;
   // }
   return KAT_SUCCESS;
}

/*
   *crypto_aead_encrypt: encrypt message and produce tag
   *k: key
   *npub: nonce
   *nsec: NULL
   *adlen: length of ad
   *ad: associated data
   *mlen: length of message
   *m: message to be encrypted
   *clen: ciphertext length + tag length
   *c: ciphertext, followed by tag
*/
int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k)
{
   int w_size = aes_init(sizeof(k));

   uint8_t *w = malloc(w_size + 1);

   aes_key_expansion((uint8_t *)k, w);
   uint8_t *plain_text = malloc(sizeof(m) + 1);

   plain_text = (uint8_t *)m;
   uint8_t *cipher = malloc(16);

   aes_cipher(plain_text, cipher, w);

   uint8_t mac[HMAC_SHA256_BYTES];
   hmac_sha256(mac, k, 256, m, 0);
   c = malloc(sizeof(cipher) + 1);

   c = (char *)cipher;
   clen = strlen(c);

   free(cipher);
   free(w);
   return KAT_SUCCESS;
}

int crypto_aead_decrypt(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k)
{
   int w_size = aes_init(sizeof(k));
   uint8_t *plain_text;
   uint8_t *w = malloc(w_size + 1);
   uint8_t *cipher_uint8 = (uint8_t *)c;
   aes_inv_cipher(
       plain_text,
       cipher_uint8,
       w);
   m = (unsigned char *)plain_text;

   uint8_t mac[HMAC_SHA256_BYTES];
   hmac_sha256(mac, k, 256, m, 0);

   free(plain_text);
   free(w);

   return KAT_SUCCESS;
}
