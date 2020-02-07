#include <stdio.h>
#include <string.h>

#include <stdlib.h>

size_t get_file_size(char *file_name) {
  FILE *file = fopen(file_name, "r");
  // get the numbers of lines in the file
  fseek(file, 0, SEEK_END);

  long f_size = ftell(file);
  fseek(file, 0, SEEK_SET);
  fclose(file);
  return (size_t)f_size;
}

int readFile(char *fileName, char *out_msg) {
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

  while ((c = fgetc(file)) != EOF) {
    code[n++] = (char)c;
  }

  code[n] = '\0';
  strcpy(out_msg, code);
  free(code);
  return 0;
}

// int copy_char_to_buffer(char *out_msg, char *src_msg) {
//   int count = 0;
//   char *src_msg_ptr = src_msg;
//   while (*src_msg_ptr != '\0') {

//     out_msg[count] = ()*src_msg_ptr
//   }
// }
