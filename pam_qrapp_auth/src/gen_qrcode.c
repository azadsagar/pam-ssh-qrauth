#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <qrencode.h>
#include "gen_qrcode.h"
#include "base64.h"

static int margin = 2;
static int version = 0;

//static QRencodeMode hint = QR_MODE_8;
static QRecLevel level = QR_ECLEVEL_L;

char *write_to_str(char *dest_str,const char *src_str)
{
	while(*src_str){
		*dest_str = *src_str;
		dest_str++;
		src_str++;
	}

	return dest_str;
}

static char *writeUTF8_margin(int realwidth, const char* white,
                             const char *reset, const char* full,char *tstr)
{
	int x, y;

	for (y = 0; y < margin/2; y++) {
		tstr=write_to_str(tstr,white);
		for (x = 0; x < realwidth; x++){
			tstr = write_to_str(tstr,full);
		}
		tstr = write_to_str(tstr,reset);
		*tstr='\n';
		tstr++;
	}

	return tstr;
}

static char *writeUTF8(const QRcode *qrcode, const char *outfile, int use_ansi, int invert)
{
	int x, y;
	int realwidth;
	const char *white, *reset;
	const char *empty, *lowhalf, *uphalf, *full;
	int allocate_mem;
	char *tstr;
	char *backup_tstr;

	empty = " ";
	lowhalf = "\342\226\204";
	uphalf = "\342\226\200";
	full = "\342\226\210";

	if (invert) {
		const char *tmp;

		tmp = empty;
		empty = full;
		full = tmp;

		tmp = lowhalf;
		lowhalf = uphalf;
		uphalf = tmp;
	}

	if (use_ansi){
		if (use_ansi == 2) {
			white = "\033[38;5;231m\033[48;5;16m";
		} else {
			white = "\033[40;37;1m";
		}
		reset = "\033[0m";
	} else {
		white = "";
		reset = "";
	}

	realwidth = (qrcode->width + margin * 2);

	allocate_mem = ((realwidth * 3) + 2) * ((realwidth/2) + 1);
	tstr = (char *)malloc(allocate_mem);

	if(!tstr){
		perror("Memory allocation failed !");
		exit(EXIT_FAILURE);
	}

	backup_tstr = tstr;

	/* top margin */
	tstr=writeUTF8_margin(realwidth, white, reset, full,tstr);

	/* data */
	for(y = 0; y < qrcode->width; y += 2) {
		unsigned char *row1, *row2;
		row1 = qrcode->data + y*qrcode->width;
		row2 = row1 + qrcode->width;

		tstr = write_to_str(tstr,white);

		for (x = 0; x < margin; x++) {
			tstr = write_to_str(tstr,full);
		}

		for (x = 0; x < qrcode->width; x++) {
			if(row1[x] & 1) {
				if(y < qrcode->width - 1 && row2[x] & 1) {
					tstr = write_to_str(tstr,empty);
				} else {
					tstr = write_to_str(tstr,lowhalf);
				}
			} else if(y < qrcode->width - 1 && row2[x] & 1) {
				tstr = write_to_str(tstr,uphalf);
			} else {
				tstr = write_to_str(tstr,full);
			}
		}

		for (x = 0; x < margin; x++){
			tstr = write_to_str(tstr,full);
		}

		tstr = write_to_str(tstr,reset);
		*tstr='\n';
		tstr++;
	}

	/* bottom margin */
	tstr=writeUTF8_margin(realwidth, white, reset, full, tstr);
	*tstr='\0';

	return backup_tstr;
}

char *get_qrcode_string(const char *src)
{
    //char *text_msg = "some random text";
	//char msg[31];
	char *str_QRcode=NULL;

	//get_random_string(msg,30);

	int input_src_length = strlen(src);

	/* const int encoded_length = Base64encode_len(30);
	char *text_msg = malloc(encoded_length + 1);

	Base64encode(text_msg,msg,30);

	text_msg[encoded_length] = '\0';

    const int length = strlen(text_msg); */

    QRcode *qrcode;

    qrcode = QRcode_encodeData(input_src_length,src,version,level);

    if(qrcode == NULL)
    {
        fprintf(stderr,"Failed to get encoded code");
        exit(EXIT_FAILURE);
    }

    str_QRcode=writeUTF8(qrcode,"-",0,0);
    QRcode_free(qrcode);
	//free(text_msg);

    return str_QRcode;
}