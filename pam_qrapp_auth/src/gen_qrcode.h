#include <qrencode.h>

#ifndef GEN_QR_CODE_H
#define GEN_QR_CODE_H

void get_random_string(char *random_str,int length);
char *write_to_str(char *dest_str,const char *src_str);

static char *writeUTF8_margin(int realwidth, const char* white,
                             const char *reset, const char* full,char *tstr);

static char *writeUTF8(const QRcode *qrcode, const char *outfile, int use_ansi, int invert);

char *get_qrcode_string(const char *src);

#endif