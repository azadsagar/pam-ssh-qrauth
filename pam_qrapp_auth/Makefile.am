AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I build

pamdir = $(libdir)/security

pam_LTLIBRARIES   = pam_qrapp_auth.la


MODULES_LDFLAGS = -module -avoid-version -shared

CORE_SRC  = src/base64.h 			src/base64.c
CORE_SRC += src/gen_qrcode.h		src/gen_qrcode.c
CORE_SRC += src/string_crypt.h		src/string_crypt.c
CORE_SRC += src/utils.h 			src/utils.c
CORE_SRC += src/websocket_client.h 	src/websocket_client.c


pam_qrapp_auth_la_SOURCES = \
	src/pam_qrapp_auth.c \
	$(CORE_SRC)
pam_qrapp_auth_la_LIBADD  = -lpam -lqrencode -lssl -lcrypto -lpthread -lwebsockets
pam_qrapp_auth_la_CFLAGS  = $(AM_CFLAGS)
pam_qrapp_auth_la_LDFLAGS = $(AM_LDFLAGS) $(MODULES_LDFLAGS) -export-symbols-regex "pam_sm_(setcred|open_session|authenticate)"


