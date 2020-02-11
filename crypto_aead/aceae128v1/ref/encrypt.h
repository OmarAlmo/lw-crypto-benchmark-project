#include "api.h"
#include "crypto_aead.h"
#include "executable_helper.h"
#include <stdio.h>
#include <stdlib.h>

#define KAT_SUCCESS 0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR -3
#define KAT_CRYPTO_FAILURE -4

#define MAX_FILE_NAME 256
#define MAX_MESSAGE_LENGTH 32
#define MAX_ASSOCIATED_DATA_LENGTH 32

int get_file_size(char *file_name) {

  // opening the file in read mode
  FILE *fp = fopen(file_name, "r");

  // checking if the file exist or not
  if (fp == NULL) {
    printf("File Not Found!\n");
    return -1;
  }

  fseek(fp, 0L, SEEK_END);

  // calculating the size of the file
  int res = ftell(fp);

  // closing the file
  fclose(fp);

  return res;
}

int encrypt(char *file_name) {
  size_t length_of_file = get_file_size(file_name);
  printf("%lu is the length of the file\n", length_of_file);

  char *plain_text = malloc(length_of_file + 1);
  readFile(file_name, plain_text);
  printf("%s\n", plain_text);

  // counting numbers of encryption needs to be done
  int numbers_encrypted_rounds = length_of_file / MAX_MESSAGE_LENGTH + 1;
  printf("for size %llu we are encrypting %d times\n", length_of_file,
         numbers_encrypted_rounds);

  unsigned char key[CRYPTO_KEYBYTES] = "some_secret_key";
  unsigned char nonce[CRYPTO_NPUBBYTES] = "some_public_nonce";
  unsigned char msg[MAX_MESSAGE_LENGTH];
  unsigned char msg2[MAX_MESSAGE_LENGTH];

  unsigned char ad[MAX_ASSOCIATED_DATA_LENGTH] = "some_associated_data";
  unsigned long long adlen = strlen(ad);

  unsigned char ct[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES + 1]; // verfication tag
  unsigned long long clen, mlen2, mlen = MAX_MESSAGE_LENGTH;
  int count = 1;
  int func_ret, ret_val = KAT_SUCCESS;

  for (int begin_index = 0; begin_index < length_of_file;
       begin_index += MAX_MESSAGE_LENGTH) {
    int end_index = (begin_index + MAX_MESSAGE_LENGTH);
    end_index = end_index > length_of_file ? length_of_file : end_index;
    printf("============================================\n");
    printf("start from %d ends to %d\n", begin_index, end_index);

    strncpy(msg, plain_text + begin_index, end_index - begin_index);

    printf("%s\n", msg);

    func_ret =
        crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key);
    if (func_ret == KAT_SUCCESS) {
      printf("The cipher Text %s \n", ct);
    }

    func_ret = crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen,
                                   nonce, key);
    if (func_ret == KAT_SUCCESS) {
      printf("The plain Text %02x \n", msg2);
    }
    printf("Is the decryption success ? <%d>\n", func_ret == KAT_SUCCESS);
    printf("The decrypted plaint Text %02x \n", msg2);

    if (mlen != mlen2) {
      printf("crypto_aead_decrypt returned bad 'mlen': Got <%llu>, expected "
             "<%llu>\n",
             mlen2, mlen);
      ret_val = KAT_CRYPTO_FAILURE;
      // break;
    }
    if (memcmp(msg, msg2, mlen)) {
      printf("crypto_aead_decrypt did not recover the plaintext\n");
      ret_val = KAT_CRYPTO_FAILURE;
      // break;
    }
    printf("Is the process success ? <%d>\n", ret_val == KAT_SUCCESS);
    printf("============================================\n");

    memset(ct, '\0', sizeof(ct));
    memset(msg2, '\0', sizeof(msg2));
    memset(msg, '\0', sizeof(msg));
    clen = 0, mlen2 = 0;
  }

  free(plain_text);
  return 0;
}

int encrypt_with_key(char *file_name, char *key) { return -1; }
