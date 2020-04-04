// disable deprecation for sprintf and fopen
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <string.h>

#include <stdlib.h>

#include "crypto_aead.h"
#include "api.h"
#include "util.h"

#define KAT_SUCCESS 0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR -3
#define KAT_CRYPTO_FAILURE -4

#define MAX_FILE_NAME 256
#define MAX_MESSAGE_LENGTH 32
#define MAX_ASSOCIATED_DATA_LENGTH 32

void showUsage()
{
    printf(
        " ./ace128 [file_name to encrypt] options\n"
        "\t--key=SOMECAHRATER\n"
        "\t--nonce=SOMECAHRATER\n"
        "\t--associate-data=SOMECAHRATER\n");
}

int benchmark_one_file(char *file_name, unsigned char *key,
                       unsigned char *nonce, unsigned char *ad,
                       FILE *run_time_fp, int debug)
{

    FILE *fp;
    long lSize;
    char *buffer;

    fp = fopen ( file_name , "rb" );
    if( !fp ) perror(file_name),exit(1);

    fseek( fp , 0L , SEEK_END);
    lSize = ftell( fp );
    rewind( fp );

    /* allocate memory for entire content */
    buffer = calloc( 1, lSize+1 );
    if( !buffer ) fclose(fp),fputs("memory alloc fails",stderr),exit(1);

    /* copy the file into the buffer */
    if( 1!=fread( buffer , lSize, 1 , fp) )
        fclose(fp),free(buffer),fputs("entire read fails",stderr),exit(1);
    fclose(fp);

    /* do your work here, buffer is a string contains the whole text */
    printf("%s contains %lu characters\n", file_name, lSize);

    unsigned char msg[lSize+1];
    unsigned char msg2[lSize+1];
    unsigned long long adlen = strlen(ad);

    unsigned char ct[lSize + CRYPTO_ABYTES + 1]; // verfication tag
    unsigned long long clen, mlen2, mlen = lSize;

    int func_ret, ret_val = KAT_SUCCESS;

    // runtime benchmark in terms enc and dec
    double encryption_time = 0.0, decryption_time = 0.0, percent_completion = 0.0;
    double total_d_time;

    clock_t total_time = clock();
    
    // encryption
    clock_t t = clock();
    func_ret =
        crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key);
    t = clock() - t;
    encryption_time += ((double)t) / CLOCKS_PER_SEC; // in seconds

    // // // decryption
    t = clock();
    func_ret = crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen,
                                    nonce, key);
    t = clock() - t;
    decryption_time += ((double)t) / CLOCKS_PER_SEC; // in seconds a

    // // finallize and write to file
    total_time = clock() - total_time;
    total_d_time = ((double)total_time) / CLOCKS_PER_SEC;
    printf("\n");
    // // output current bench mark result to the csv file
    fprintf(run_time_fp, "%s,%d,%f,%f,%f\n", file_name, lSize,
            encryption_time, decryption_time, total_d_time);
    // printf("It takes  %.2f s\n", total_d_time);

    free(buffer);
    return 0;
}

int main(int argc, char **argv)
{
    system("clear");
    printf("==================================================================\n");
    if (argc < 2 || argc > 7)
    {
        printf("Please provided the file to encrypt\n");
        showUsage();
        return -1;
    };

    unsigned char key[CRYPTO_KEYBYTES] = "some_secret_key";
    unsigned char nonce[CRYPTO_NPUBBYTES] = "some_nonce";
    unsigned char ad[MAX_ASSOCIATED_DATA_LENGTH] = "some_ad";
    int debug = strcmp(argv[argc - 1], "debug") == 0 ? 1 : 0;
    int previous = get_file_size("photon-beetle_run_time_bench_mark.csv");
    FILE *benchmark_fp = fopen("photon-beetle_run_time_bench_mark.csv", previous == -1 ? "wr" : "a");

    // switch (argc)
    // {
    // case 3:
    //     if (parse_arg(argv[2], key) != 0)
    //     {
    //         printf("%s file is too big \n", argv[2]);
    //     }
    //     break;
    // case 4:
    //     if (parse_arg(argv[3], nonce) != 0)
    //     {
    //         printf("%s file is too big \n", argv[3]);
    //         exit(-1);
    //     }

    //     break;
    // case 5:
    //     if (parse_arg(argv[4], ad) != 0)
    //     {
    //         printf("%s file is too big \n", argv[4]);
    //         exit(-1);
    //     }
    //     break;
    // }

    if (previous == -1)
    {
        fprintf(benchmark_fp, "file_name,file_sizes,encryption_time(s),decryption_time(s),total_time(s)\n");
    }
    int result = benchmark_one_file(argv[1], key, nonce, ad, benchmark_fp, debug);

    fclose(benchmark_fp);
    printf("==================================================================\n");
    return 0;
}
