#include <stdio.h>
#include <string.h>

#include <stdlib.h>

#include "crypto_aead.h"
#include "api.h"
#include "util.h"
#include <time.h>


int main(int argc, char **argv)
{
    int previous = get_file_size("photon_run_time_bench_mark.csv");
    FILE *benchmark_fp = fopen("photon_run_time_bench_mark.csv", previous == -1 ? "wr" : "a");
    
    int FILE_SIZE  = 0;
    char *n = argv[1];
    int num = atoi(n);
    int iterations = num * 4096;

    unsigned char t,state[500];
    unsigned long long s[500];
    int i,j ;
    unsigned char plaintext[4096];
    unsigned char ad[4096];
    unsigned char ciphertext[4096];
    unsigned char key[16];
    unsigned char iv[16];
    unsigned char mac[16];
    unsigned long long  msglen, adlen, clen;    // msg, adlen, clen in bytes.
    unsigned char maclen = 16;
    unsigned int  success;

    msglen = 1003;
    adlen = 1003;

    double encryption_time = 0.0, decryption_time = 0.0, percent_completion = 0.0, final_time = 0.0;
    clock_t time;
    printf("herre");
    for (int roundj = 0; roundj < iterations; roundj++){
        for (i = 0; i < 16; i++) key[i] = 0;
        for (i = 0; i < 16; i++) iv[i] = 0;
        key[0] = 1;
        for (i = 0; i < 4096; i++) plaintext[i]  = i%256;
        for (i = 0; i < 4096; i++) ciphertext[i] = 0;
        for (i = 0; i < 4096; i++) ad[i] = i%7;

        // printf("\nPLAINTEXT::");
        // for( i = 0; i < msglen; i++) printf("%2x", plaintext[i]);
        /* End encryption */
        time = clock();
            crypto_aead_encrypt(ciphertext,&clen,plaintext,msglen,ad,adlen,0,iv,key);
        time = clock() - time;
        encryption_time += ((double)time) / CLOCKS_PER_SEC;
        /* End end */
        for( i = 0; i < msglen; i++) plaintext[i] = 0;
        
        // printf("\nCIPHERTEXT::");
        // for( i = 0; i < msglen; i++) printf("%2x", ciphertext[i]);

        /* Begin decryption */
        time = clock();
            t = crypto_aead_decrypt(plaintext,&msglen,0,ciphertext,clen,ad,adlen,iv,key);
        time = clock() - time;
        decryption_time +=((double)time)/ CLOCKS_PER_SEC;
        /* End decryption */
        
        // printf("\nPLAINTEXT::");
        // for( i = 0; i < msglen; i++) printf("%2x", plaintext[i]);

        FILE_SIZE += 4196;
    }
    final_time = encryption_time + decryption_time;
    fprintf(benchmark_fp, "%d,%f,%f,%f\n", FILE_SIZE,encryption_time, decryption_time, final_time);
    printf("It takes  %.2f s\n", final_time);
}
   