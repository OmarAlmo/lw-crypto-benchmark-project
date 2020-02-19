#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "crypto_hash.h"
#include "api.h"
#include "util.h"

#define KAT_SUCCESS 0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR -3
#define KAT_CRYPTO_FAILURE -4

#define MAX_FILE_NAME 256
#define MAX_MESSAGE_LENGTH 1024

int benchmark_one_file(char *file_name)
{
    int length_of_file = get_file_size(file_name);
    if (length_of_file <= 0)
    {
        printf("%s is an empty file can't hash an empty file\n", file_name);
        exit(-1);
    }
    unsigned char digest[CRYPTO_BYTES];
    unsigned char msg[MAX_MESSAGE_LENGTH];

    unsigned long long mlen;

    char *plain_text = malloc(length_of_file + 1);
    readFile(file_name, plain_text);

    // counting numbers of encryption needs to be done
    int numbers_encrypted_rounds = length_of_file / MAX_MESSAGE_LENGTH + 1;
    int begin_index = 0;
    printf("%s contains %lu characters\n", file_name, length_of_file);
    printf("for size %llu we are encrypting %d times\n", length_of_file,
           numbers_encrypted_rounds);

    int ret_val = KAT_SUCCESS;
    int count = 1;

    // defining the output file name in format name.enc and name.dec
    char copy_file_name[strlen(file_name) + 6];
    strcpy(copy_file_name, file_name);
    FILE *hash_output_fp = fopen(strcat(copy_file_name, ".hash"), "wr");

    double total_d_time, hash_time = 0.0;
    clock_t total_time = clock();
    // batch the huge file into blocks to perform ace
    for (begin_index = 0; begin_index < length_of_file;
         begin_index += MAX_MESSAGE_LENGTH)
    {
        int end_index = (begin_index + MAX_MESSAGE_LENGTH);
        end_index = end_index > length_of_file ? length_of_file : end_index;

        strncpy(msg, plain_text + begin_index, end_index - begin_index);

        mlen = strlen(msg);

        // encryption
        clock_t t;
        t = clock();
        t = clock() - t;
        hash_time += ((double)t) / CLOCKS_PER_SEC; // in seconds

        ret_val = crypto_hash(digest, msg, mlen);
        if (ret_val != 0)
        {
            printf("Fail to hash the given inputs\n");
            ret_val = KAT_CRYPTO_FAILURE;
            break;
        }
        if (ret_val == KAT_SUCCESS)
            fprintf(hash_output_fp, "%02x", digest);

        memset(msg, '\0', sizeof(msg));
        memset(digest, '\0', sizeof(digest));
        mlen = 0;
    }
    fclose(hash_output_fp);
    free(plain_text);
    return ret_val;
    return 0;
}

int main(int argc, char **argv)
{

    if (argc < 2)
    {
        printf("Invalid Argument Size, please provide a file to encrypt");
        return -1;
    }
    benchmark_one_file(argv[1]);
    return 0;
}
