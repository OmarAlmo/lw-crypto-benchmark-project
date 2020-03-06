
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
