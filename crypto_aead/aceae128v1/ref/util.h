#include "api.h"
#include "crypto_aead.h"
#include "executable_helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define KAT_SUCCESS 0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR -3
#define KAT_CRYPTO_FAILURE -4

#define MAX_FILE_NAME 256
#define MAX_MESSAGE_LENGTH 32
#define MAX_ASSOCIATED_DATA_LENGTH 32

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

/**
 * check the given argument is a file or not
 * */
int arg_file_checker(char *file_name)
{
  FILE *fp = fopen(file_name, "r");
  if (fp == NULL)
  {
    return 0;
  }
  fclose(fp);
  return 1;
}

int show_status(double percent)
{
  int x;
  for (x = 0; x < percent; x++)
  {
    printf("|");
  }
  printf("%.2f%%\r", percent);
  fflush(stdout);
  system("sleep 1");

  return (EXIT_SUCCESS);
}

/**
 * Parse the argument content if it is a file
 * */

int parse_arg(char *argv, char *dest)
{
  if (arg_file_checker(argv) == 1)
  {
    size_t length_of_file = get_file_size(argv);
    if (length_of_file > strlen(dest) - 1)
    {
      printf("%s is too big \n", argv);
      return -1;
    }
    return readFile(argv, dest);
  }
  else
  {
    memset(dest, "\0", sizeof(dest));
    strcpy(dest, argv);
  }
  return 0;
}

int benchmark_one_file(char *file_name, unsigned char *key,
                       unsigned char *nonce, unsigned char *ad,
                       FILE *run_time_fp, int debug)
{
  size_t length_of_file = get_file_size(file_name);

  char *plain_text = malloc(length_of_file + 1);
  readFile(file_name, plain_text);

  // counting numbers of encryption needs to be done
  int numbers_encrypted_rounds = length_of_file / MAX_MESSAGE_LENGTH + 1;

  int begin_index = 0;
  printf("%s contains %lu characters\n", file_name, length_of_file);
  printf("for size %llu we are encrypting %d times\n", length_of_file,
         numbers_encrypted_rounds);

  unsigned char msg[MAX_MESSAGE_LENGTH];
  unsigned char msg2[MAX_MESSAGE_LENGTH];
  unsigned long long adlen = strlen(ad);

  unsigned char ct[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES + 1]; // verfication tag
  unsigned long long clen, mlen2, mlen = MAX_MESSAGE_LENGTH;
  int count = 1;
  int func_ret, ret_val = KAT_SUCCESS;

  // runtime benchmark in terms enc and dec
  double encryption_time = 0.0, decryption_time = 0.0, percent_completion = 0.0;

  // defining the output file name in format name.enc and name.dec
  char copy_file_name[strlen(file_name) + 5];
  strcpy(copy_file_name, file_name);
  FILE *enc_output_fp = fopen(strcat(copy_file_name, ".enc"), "wr");

  strcpy(copy_file_name, file_name);
  FILE *dec_output_fp = fopen(strcat(copy_file_name, ".dec"), "wr");

  double total_d_time;
  clock_t total_time = clock();
  // batch the huge file into blocks to perform ace
  for (begin_index = 0; begin_index < length_of_file;
       begin_index += MAX_MESSAGE_LENGTH)
  {
    int end_index = (begin_index + MAX_MESSAGE_LENGTH);
    end_index = end_index > length_of_file ? length_of_file : end_index;

    strncpy(msg, plain_text + begin_index, end_index - begin_index);

    // encryption
    clock_t t;
    t = clock();
    func_ret =
        crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key);
    t = clock() - t;
    encryption_time += ((double)t) / CLOCKS_PER_SEC; // in seconds

    if (func_ret == KAT_SUCCESS)
    {
      fprintf(enc_output_fp, "%02x", ct);
    }

    // decryption
    t = clock();
    func_ret = crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen,
                                   nonce, key);
    t = clock() - t;
    decryption_time += ((double)t) / CLOCKS_PER_SEC; // in seconds a

    if (func_ret == KAT_SUCCESS)
    {
      fprintf(dec_output_fp, "%s", msg2);
    }

    if (mlen != mlen2)
    {
      ret_val = KAT_CRYPTO_FAILURE;
    }

    if (memcmp(msg, msg2, mlen))
    {
      ret_val = KAT_CRYPTO_FAILURE;
    }
    if (debug)
    {
      printf("============================================\n");
      printf("Encryptingmsg starting from %d ends to %d\n", begin_index,
             end_index);
      printf("Is the process success ? <%s>\n",
             ret_val == KAT_SUCCESS ? "true" : "false");
      printf("Is the decryption success ? <%s>\n",
             ret_val == KAT_SUCCESS ? "true" : "false");
      printf("============================================\n");
    }
    memset(ct, '\0', sizeof(ct));
    memset(msg2, '\0', sizeof(msg2));
    memset(msg, '\0', sizeof(msg));
    clen = 0, mlen2 = 0;

    printf("[");
    percent_completion = ((double)begin_index / length_of_file) * 100;
    for (int x = 0; x < (int)percent_completion; x++)
    {
      printf("|");
    }
    printf("%.2f%%]\r", percent_completion);

    fflush(stdout);
  }

  total_time = clock() - total_time;
  total_d_time = ((double)total_time) / CLOCKS_PER_SEC;
  printf("\n");
  // output current bench mark result to the csv file
  fprintf(run_time_fp, "%s,%d,%f,%f,%f\n", file_name, length_of_file,
          encryption_time, decryption_time, total_d_time);
  printf("It takes  %.2f s\n", total_d_time);

  fclose(enc_output_fp);
  fclose(dec_output_fp);
  free(plain_text);
  return 0;
}
