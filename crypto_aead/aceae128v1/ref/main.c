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

    FILE *benchmark_fp = fopen("run_time_bench_mark.csv", "w+");

    switch (argc)
    {
    case 3:
        if (parse_arg(argv[2], key) != 0)
        {
            printf("%s file is too big \n", argv[2]);
        }
        break;
    case 4:
        if (parse_arg(argv[3], nonce) != 0)
        {
            printf("%s file is too big \n", argv[3]);
            exit(-1);
        }

        break;
    case 5:
        if (parse_arg(argv[4], ad) != 0)
        {
            printf("%s file is too big \n", argv[4]);
            exit(-1);
        }
        break;
    }
    fprintf(benchmark_fp, "file_name,file_sizes,encryption_time(s),decryption_time(s),total_time(s)\n");
    int result = benchmark_one_file(argv[1], key, nonce, ad, benchmark_fp, debug);

    fclose(benchmark_fp);
    printf("==================================================================\n");
    return 0;
}
