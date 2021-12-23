#!/bin/bash
autoreconf -i
[ $? -eq 0 ] && ./configure || exit 1
[ $? -eq 0 ] && cp config.h src/ || exit 1
cd src
gcc -I$PWD -fPIC -c pam_qrapp_auth.c websocket_client.c gen_qrcode.c string_crypt.c base64.c utils.c
gcc -shared -o pam_qrapp_auth.so pam_qrapp_auth.o websocket_client.o gen_qrcode.o string_crypt.o base64.o utils.o -lpam -lqrencode -lssl -lcrypto -lpthread -lwebsockets
rm -f *.o