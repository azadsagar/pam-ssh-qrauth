#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <time.h>
#include <syslog.h>
#include <stdarg.h>

#ifdef HAVE_SYS_FSUID_H
#include <sys/fsuid.h>
#endif


#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "pam_qrapp_auth.h"

#include "websocket_client.h"

void log_message(int priority, pam_handle_t *pamh,
                        const char *format, ...) {
  char *service = NULL;
  if (pamh)
    pam_get_item(pamh, PAM_SERVICE, (void *)&service);
  if (!service)
    service = "";

  char logname[80];
  snprintf(logname, sizeof(logname), "%s(" MODULE_NAME ")", service);

  va_list args;
  va_start(args, format);
#if !defined(DEMO) && !defined(TESTING)
  openlog(logname, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
  vsyslog(priority, format, args);
  closelog();
#else
  if (!error_msg) {
    error_msg = strdup("");
  }
  {
    char buf[1000];
    vsnprintf(buf, sizeof buf, format, args);
    const int newlen = strlen(error_msg) + 1 + strlen(buf) + 1;
    char* n = malloc(newlen);
    if (n) {
      snprintf(n, newlen, "%s%s%s", error_msg, strlen(error_msg)?"\n":"",buf);
      free(error_msg);
      error_msg = n;
    } else {
      fprintf(stderr, "Failed to malloc %d bytes for log data.\n", newlen);
    }
  }
#endif

  va_end(args);

  if (priority == LOG_EMERG) {
    // Something really bad happened. There is no way we can proceed safely.
    exit(1);
  }
}

static int converse(pam_handle_t *pamh, int nargs,
                    PAM_CONST struct pam_message **message,
                    struct pam_response **response) {
  struct pam_conv *conv;
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS) {
    return retval;
  }
  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static const char *get_user_name(pam_handle_t *pamh, const Params *params) {
  // Obtain the user's name
  const char *username;
  if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS ||
      !username || !*username) {
    log_message(LOG_ERR, pamh,
                "pam_get_user() failed to get a user name"
                " when checking verification code");
    return NULL;
  }
  if (params->debug) {
    log_message(LOG_INFO, pamh, "debug: start of pam_qrapp_auth for \"%s\"", username);
  }
  return username;
}

static const char *get_rhost(pam_handle_t *pamh, const Params *params) {
  // Get the remote host
  PAM_CONST void *rhost;
  if (pam_get_item(pamh, PAM_RHOST, &rhost) != PAM_SUCCESS) {
    log_message(LOG_ERR, pamh, "pam_get_rhost() failed to get the remote host");
    return NULL;
  }
  if (params->debug) {
    log_message(LOG_INFO, pamh, "debug: pam_qrapp_auth for host \"%s\"",
                rhost);
  }
  return (const char *)rhost;
}


static size_t
getpwnam_buf_max_size()
{
#ifdef _SC_GETPW_R_SIZE_MAX
  const ssize_t len = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (len <= 0) {
    return 4096;
  }
  return len;
#else
  return 4096;
#endif
}

static int setuser(int uid) {
#ifdef HAVE_SETFSUID
  // The semantics for setfsuid() are a little unusual. On success, the
  // previous user id is returned. On failure, the current user id is returned.
  int old_uid = setfsuid(uid);
  if (uid != setfsuid(uid)) {
    setfsuid(old_uid);
    return -1;
  }
#else
#ifdef linux
#error "Linux should have setfsuid(). Refusing to build."
#endif
  int old_uid = geteuid();
  if (old_uid != uid && seteuid(uid)) {
    return -1;
  }
#endif
  return old_uid;
}

static int setgroup(int gid) {
#ifdef HAVE_SETFSGID
  // The semantics of setfsgid() are a little unusual. On success, the
  // previous group id is returned. On failure, the current groupd id is
  // returned.
  int old_gid = setfsgid(gid);
  if (gid != setfsgid(gid)) {
    setfsgid(old_gid);
    return -1;
  }
#else
  int old_gid = getegid();
  if (old_gid != gid && setegid(gid)) {
    return -1;
  }
#endif
  return old_gid;
}


// Drop privileges and return 0 on success.
static int drop_privileges(pam_handle_t *pamh, const char *username, int uid,
                           int *old_uid, int *old_gid) {
  // Try to become the new user. This might be necessary for NFS mounted home
  // directories.

  // First, look up the user's default group
  #ifdef _SC_GETPW_R_SIZE_MAX
  int len = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (len <= 0) {
    len = 4096;
  }
  #else
  int len = 4096;
  #endif
  char *buf = malloc(len);
  if (!buf) {
    log_message(LOG_ERR, pamh, "Out of memory");
    return -1;
  }
  struct passwd pwbuf, *pw;
  if (getpwuid_r(uid, &pwbuf, buf, len, &pw) || !pw) {
    log_message(LOG_ERR, pamh, "Cannot look up user id %d", uid);
    free(buf);
    return -1;
  }
  gid_t gid = pw->pw_gid;
  free(buf);

  int gid_o = setgroup(gid);
  int uid_o = setuser(uid);
  if (uid_o < 0) {
    if (gid_o >= 0) {
      if (setgroup(gid_o) < 0 || setgroup(gid_o) != gid_o) {
        // Inform the caller that we were unsuccessful in resetting the group.
        *old_gid = gid_o;
      }
    }
    log_message(LOG_ERR, pamh, "Failed to change user id to \"%s\"",
                username);
    return -1;
  }
  if (gid_o < 0 && (gid_o = setgroup(gid)) < 0) {
    // In most typical use cases, the PAM module will end up being called
    // while uid=0. This allows the module to change to an arbitrary group
    // prior to changing the uid. But there are many ways that PAM modules
    // can be invoked and in some scenarios this might not work. So, we also
    // try changing the group _after_ changing the uid. It might just work.
    if (setuser(uid_o) < 0 || setuser(uid_o) != uid_o) {
      // Inform the caller that we were unsuccessful in resetting the uid.
      *old_uid = uid_o;
    }
    log_message(LOG_ERR, pamh,
                "Failed to change group id for user \"%s\" to %d", username,
                (int)gid);
    return -1;
  }

  *old_uid = uid_o;
  *old_gid = gid_o;
  return 0;
}


// Show error message to the user.
static void
conv_error(pam_handle_t *pamh, const char* text) {
  PAM_CONST struct pam_message msg = {
    .msg_style = PAM_ERROR_MSG,
    .msg       = text,
  };
  PAM_CONST struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  const int retval = converse(pamh, 1, &msgs, &resp);
  if (retval != PAM_SUCCESS) {
    log_message(LOG_ERR, pamh, "Failed to inform user of error");
  }
  free(resp);
}

char *conv_read(pam_handle_t *pamh,const char *text,int echocode){
  PAM_CONST struct pam_message msg = { 
    .msg_style = echocode,
    .msg       = text
  };

  PAM_CONST struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  int retval = converse(pamh, 1, &msgs, &resp);

  char *ret = NULL;
  if (retval != PAM_SUCCESS || resp == NULL || resp->resp == NULL ||
      *resp->resp == '\000') {
    log_message(LOG_ERR, pamh, "Did not receive verification code from user");
    if (retval == PAM_SUCCESS && resp && resp->resp) {
      ret = resp->resp;
    }
  } else {
    ret = resp->resp;
  }

  // Deallocate temporary storage
  if (resp) {
    if (!ret) {
      free(resp->resp);
    }
    free(resp);
  }

  return ret;

}

void conv_info(pam_handle_t *pamh, const char* text)
{
    PAM_CONST struct pam_message msg = {
        .msg_style  = PAM_TEXT_INFO,
        .msg        = text
    };

    PAM_CONST struct pam_message *msgs = &msg;
    struct pam_response *resp = NULL;
    const int retval = converse(pamh,1,&msgs,&resp);

    if(retval != PAM_SUCCESS)
    {
        log_message(LOG_ERR,pamh,"Failed to print info message");
    }

    free(resp);
}

// parse a user name.
// input: user name
// output: uid
// return: 0 on success.
static int parse_user(pam_handle_t *pamh, const char *name, uid_t *uid) {
  char *endptr;
  errno = 0;
  const long l = strtol(name, &endptr, 10);
  if (!errno && endptr != name && l >= 0 && l <= INT_MAX) {
    *uid = (uid_t)l;
    return 0;
  }
  const size_t len = getpwnam_buf_max_size();
  char *buf = malloc(len);
  if (!buf) {
    log_message(LOG_ERR, pamh, "Out of memory");
    return -1;
  }
  struct passwd pwbuf, *pw;
  if (getpwnam_r(name, &pwbuf, buf, len, &pw) || !pw) {
    free(buf);
    log_message(LOG_ERR, pamh, "Failed to look up user \"%s\"", name);
    return -1;
  }
  *uid = pw->pw_uid;
  free(buf);
  return 0;
}

/* static int parse_args(pam_handle_t *pamh, int argc, const char **argv,
                      Params *params) {
  params->debug = 0;
  params->echocode = PAM_PROMPT_ECHO_OFF;
  for (int i = 0; i < argc; ++i) {
    if (!strncmp(argv[i], "secret=", 7)) {
      params->secret_filename_spec = argv[i] + 7;
    } else if (!strncmp(argv[i], "authtok_prompt=", 15)) {
      params->authtok_prompt = argv[i] + 15;
    } else if (!strncmp(argv[i], "user=", 5)) {
      uid_t uid;
      if (parse_user(pamh, argv[i] + 5, &uid) < 0) {
        return -1;
      }
      params->fixed_uid = 1;
      params->uid = uid;
    } else if (!strncmp(argv[i], "allowed_perm=", 13)) {
      char *remainder = NULL;
      const int perm = (int)strtol(argv[i] + 13, &remainder, 8);
      if (perm == 0 || strlen(remainder) != 0) {
        log_message(LOG_ERR, pamh,
                    "Invalid permissions in setting \"%s\"."
                    " allowed_perm setting must be a positive octal integer.",
                    argv[i]);
        return -1;
      }
      params->allowed_perm = perm;
    } else if (!strcmp(argv[i], "no_strict_owner")) {
      params->no_strict_owner = 1;
    } else if (!strcmp(argv[i], "debug")) {
      params->debug = 1;
    } else if (!strcmp(argv[i], "try_first_pass")) {
      params->pass_mode = TRY_FIRST_PASS;
    } else if (!strcmp(argv[i], "use_first_pass")) {
      params->pass_mode = USE_FIRST_PASS;
    } else if (!strcmp(argv[i], "forward_pass")) {
      params->forward_pass = 1;
    } else if (!strcmp(argv[i], "noskewadj")) {
      params->noskewadj = 1;
    } else if (!strcmp(argv[i], "no_increment_hotp")) {
      params->no_increment_hotp = 1;
    } else if (!strcmp(argv[i], "nullok")) {
      params->nullok = NULLOK;
    } else if (!strcmp(argv[i], "allow_readonly")) {
      params->allow_readonly = 1;
    } else if (!strcmp(argv[i], "echo-verification-code") ||
               !strcmp(argv[i], "echo_verification_code")) {
      params->echocode = PAM_PROMPT_ECHO_ON;
    } else if (!strncmp(argv[i], "grace_period=", 13)) {
      char *remainder = NULL;
      const time_t grace = (time_t)strtol(argv[i] + 13, &remainder, 10);
      if (grace < 0 || *remainder) {
        log_message(LOG_ERR, pamh,
                    "Invalid value in setting \"%s\"."
                    "grace_period must be a positive number of seconds.",
                    argv[i]);
        return -1;
      }
      params->grace_period = grace;
    } else {
      log_message(LOG_ERR, pamh, "Unrecognized option \"%s\"", argv[i]);
      return -1;
    }
  }
  return 0;
} */


static int pam_qrapp_auth(pam_handle_t *pamh, int argc, const char *argv[])
{
    Params params = {0};
    params.allowed_perm=0600;
    char *username = get_user_name(pamh,&params);

    if(!username){
      return PAM_AUTH_ERR;
    }
    
    return auth_via_websocket(username,pamh);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED_ATTR, int argc, const char *argv[]) {
  return pam_qrapp_auth(pamh, argc, argv);
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh UNUSED_ATTR,
                int flags UNUSED_ATTR,
                int argc UNUSED_ATTR,
                const char **argv UNUSED_ATTR) {
  return PAM_SUCCESS;
}