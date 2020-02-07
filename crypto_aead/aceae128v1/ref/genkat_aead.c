//
// NIST-developed software is provided by NIST as a public service.
// You may use, copy and distribute copies of the software in any medium,
// provided that you keep intact this entire notice. You may improve,
// modify and create derivative works of the software or any portion of
// the software, and you may copy and distribute such modifications or
// works. Modified works should carry a notice stating that you changed
// the software and should note the date and nature of any such change.
// Please explicitly acknowledge the National Institute of Standards and
// Technology as the source of the software.
//
// NIST-developed software is expressly provided "AS IS." NIST MAKES NO
// WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT OR ARISING BY OPERATION
// OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT AND DATA ACCURACY. NIST
// NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE
// UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST
// DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE
// OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY,
// RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
//
// You are solely responsible for determining the appropriateness of using and
// distributing the software and you assume all risks associated with its use,
// including but not limited to the risks and costs of program errors, compliance
// with applicable laws, damage to or loss of data, programs or equipment, and
// the unavailability or interruption of operation. This software is not intended
// to be used in any situation where a failure could cause risk of injury or
// damage to property. The software developed by NIST employees is not subject to
// copyright protection within the United States.
//

// disable deprecation for sprintf and fopen
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <string.h>

#include <stdlib.h>

#include "crypto_aead.h"
#include "api.h"
#include "executable_helper.h"

#define KAT_SUCCESS 0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR -3
#define KAT_CRYPTO_FAILURE -4

#define MAX_FILE_NAME 256
#define MAX_MESSAGE_LENGTH 32
#define MAX_ASSOCIATED_DATA_LENGTH 32

void init_buffer(unsigned char *buffer, unsigned long long numbytes);

void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length);

int generate_test_vectors();

int encrypt(char *file_name);

int encrypt_with_key(char *file_name, char *key_name);

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		printf("Please provided the file to encrypt");
		return -1;
	}

	encrypt(argv[1]);

	return 0;
}

int generate_test_vectors()
{
	FILE *fp;
	char fileName[MAX_FILE_NAME];
	unsigned char key[CRYPTO_KEYBYTES];
	unsigned char nonce[CRYPTO_NPUBBYTES];
	unsigned char msg[MAX_MESSAGE_LENGTH];
	unsigned char msg2[MAX_MESSAGE_LENGTH];
	unsigned char ad[MAX_ASSOCIATED_DATA_LENGTH];
	unsigned char ct[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES];
	unsigned long long clen, mlen2;
	int count = 1;
	int func_ret, ret_val = KAT_SUCCESS;

	init_buffer(key, sizeof(key));
	init_buffer(nonce, sizeof(nonce));
	init_buffer(msg, sizeof(msg));
	init_buffer(ad, sizeof(ad));

	sprintf(fileName, "../LWC_AEAD_KAT_%d_%d.txt", (CRYPTO_KEYBYTES * 8), (CRYPTO_NPUBBYTES * 8));

	if ((fp = fopen(fileName, "w")) == NULL)
	{
		fprintf(stderr, "Couldn't open <%s> for write\n", fileName);
		return KAT_FILE_OPEN_ERROR;
	}

	// for (unsigned long long mlen = 0; (mlen <= MAX_MESSAGE_LENGTH) && (ret_val == KAT_SUCCESS); mlen++)
	// {

	// 	for (unsigned long long adlen = 0; adlen <= MAX_ASSOCIATED_DATA_LENGTH; adlen++)
	// 	{
	unsigned long long mlen = MAX_MESSAGE_LENGTH;
	unsigned long long adlen = MAX_ASSOCIATED_DATA_LENGTH;

	fprintf(fp, "Count = %d\n", count++);

	fprint_bstr(fp, "Key = ", key, CRYPTO_KEYBYTES);

	fprint_bstr(fp, "Nonce = ", nonce, CRYPTO_NPUBBYTES);

	fprint_bstr(fp, "PT = ", msg, mlen);

	fprint_bstr(fp, "AD = ", ad, adlen);

	printf("msg: %s\n", msg);

	if ((func_ret = crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key)) != 0)
	{
		fprintf(fp, "crypto_aead_encrypt returned <%d>\n", func_ret);
		ret_val = KAT_CRYPTO_FAILURE;
		// break;
	}

	fprint_bstr(fp, "CT = ", ct, clen);

	fprintf(fp, "\n");

	if ((func_ret = crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key)) != 0)
	{
		fprintf(fp, "crypto_aead_decrypt returned <%d>\n", func_ret);
		ret_val = KAT_CRYPTO_FAILURE;
		// break;
	}

	if (mlen != mlen2)
	{
		fprintf(fp, "crypto_aead_decrypt returned bad 'mlen': Got <%llu>, expected <%llu>\n", mlen2, mlen);
		ret_val = KAT_CRYPTO_FAILURE;
		// break;
	}

	if (memcmp(msg, msg2, mlen))
	{
		fprintf(fp, "crypto_aead_decrypt did not recover the plaintext\n");
		ret_val = KAT_CRYPTO_FAILURE;
		// break;
	}
	// 	}
	// }

	fclose(fp);

	return ret_val;
}

void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length)
{
	fprintf(fp, "%s", label);

	for (unsigned long long i = 0; i < length; i++)
		fprintf(fp, "%02X", data[i]);

	fprintf(fp, "\n");
}

void init_buffer(unsigned char *buffer, unsigned long long numbytes)
{
	for (unsigned long long i = 0; i < numbytes; i++)
		buffer[i] = (unsigned char)i;
}

int encrypt_with_key(char *file_name, char *key)
{
	return -1;
}

int encrypt(char *file_name)
{
	size_t length_of_file = get_file_size(file_name);
	printf("%lu is the length of the file\n", length_of_file);

	char *plain_text = malloc(length_of_file + 1);
	readFile(file_name, plain_text);
	printf("%s\n", plain_text);

	// counting numbers of encryption needs to be done
	int numbers_encrypted_rounds = length_of_file / MAX_MESSAGE_LENGTH + 1;
	printf("for size %llu we are encrypting %d times\n", length_of_file, numbers_encrypted_rounds);

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

	for (int begin_index = 0; begin_index < length_of_file; begin_index += MAX_MESSAGE_LENGTH)
	{
		int end_index = (begin_index + MAX_MESSAGE_LENGTH);
		end_index = end_index > length_of_file ? length_of_file : end_index;
		printf("============================================\n");
		printf("start from %d ends to %d\n", begin_index, end_index);

		strncpy(msg, plain_text + begin_index, end_index - begin_index);

		printf("%s\n", msg);
		// memset(msg, '\0', sizeof(msg));

		// func_ret = crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key);
		// if (func_ret == KAT_SUCCESS)
		// {
		// 	printf("The cipher Text %s \n", ct);
		// }

		// func_ret = crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key);
		// if (func_ret == KAT_SUCCESS)
		// {
		// 	printf("The plain Text %02x \n", msg2);
		// }
		// printf("Is the  decryption success ? <%d>\n", func_ret == KAT_SUCCESS);
		// printf("The plaint Text %02x \n", msg2);
		// if (mlen != mlen2)
		// {
		// 	printf("crypto_aead_decrypt returned bad 'mlen': Got <%llu>, expected <%llu>\n", mlen2, mlen);
		// 	ret_val = KAT_CRYPTO_FAILURE;
		// 	// break;
		// }
		// if (memcmp(msg, msg2, mlen))
		// {
		// 	printf("crypto_aead_decrypt did not recover the plaintext\n");
		// 	ret_val = KAT_CRYPTO_FAILURE;
		// 	// break;
		// }
		// printf("Is the process success ? <%d>\n", ret_val == KAT_SUCCESS);
		// printf("============================================\n");

		memset(ct, '\0', sizeof(ct));
		memset(msg2, '\0', sizeof(msg2));
		memset(msg, '\0', sizeof(msg));
		clen = 0, mlen2 = 0;
	}

	free(plain_text);
	return 0;
}