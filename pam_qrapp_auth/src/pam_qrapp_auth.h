#include <sys/types.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include "config.h"

#ifndef PAM_QRAPP_AUTH_H
#define PAM_QRAPP_AUTH_H

#define MODULE_NAME   "pam_qrapp_auth"

#ifndef UNUSED_ATTR
# if __GNUC__ >= 3 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
#  define UNUSED_ATTR __attribute__((__unused__))
# else
#  define UNUSED_ATTR
# endif
#endif

typedef struct Params {
  const char *secret_filename_spec;
  const char *authtok_prompt;
  enum { NULLERR=0, NULLOK, SECRETNOTFOUND } nullok;
  int        noskewadj;
  int        echocode;
  int        fixed_uid;
  int        no_increment_hotp;
  uid_t      uid;
  enum { PROMPT = 0, TRY_FIRST_PASS, USE_FIRST_PASS } pass_mode;
  int        forward_pass;
  int        debug;
  int        no_strict_owner;
  int        allowed_perm;
  time_t     grace_period;
  int        allow_readonly;
} Params;

void log_message(int priority, pam_handle_t *pamh,
                        const char *format, ...);


static int converse(pam_handle_t *pamh, int nargs,
                    PAM_CONST struct pam_message **message,
                    struct pam_response **response);

static const char *get_user_name(pam_handle_t *pamh, const Params *params);

static const char *get_rhost(pam_handle_t *pamh, const Params *params);

static size_t
getpwnam_buf_max_size();

static int setuser(int uid);

static int setgroup(int gid);

static int drop_privileges(pam_handle_t *pamh, const char *username, int uid,
                           int *old_uid, int *old_gid);

static void
conv_error(pam_handle_t *pamh, const char* text);

void conv_info(pam_handle_t *pamh, const char* text);
char *conv_read(pam_handle_t *pamh,const char *text,int echocode);

static int parse_user(pam_handle_t *pamh, const char *name, uid_t *uid);

static int parse_args(pam_handle_t *pamh, int argc, const char **argv,
                      Params *params);

static int pam_qrapp_auth(pam_handle_t *pamh, int argc, const char *argv[]);

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED_ATTR, int argc, const char *argv[]);

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh UNUSED_ATTR,
                int flags UNUSED_ATTR,
                int argc UNUSED_ATTR,
                const char **argv UNUSED_ATTR);

#endif