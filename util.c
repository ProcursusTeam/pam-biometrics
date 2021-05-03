#include "util.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <libproc.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>

static inline bool isRemoteName(const char * name) {
  if (CASECOMPARE(name, "sshd") || CASECOMPARE(name, "telnetd") || CASECOMPARE(name, "mosh-server")) {
    return true;
  }
  return false;
}

// https://github.com/Yubico/pam-u2f/blob/d46b5ed35017b089c30dd21305ac2147fcfc24f0/util.c#L1768-L1799
static int _converse(pam_handle_t *pamh, int nargs,
                     const struct pam_message **message,
                     struct pam_response **response) {
  struct pam_conv *conv;
  int retval;

  retval = pam_get_item(pamh, PAM_CONV, (void *) &conv);

  if (retval != PAM_SUCCESS) {
    return retval;
  }

  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

char *converse(pam_handle_t *pamh, int echocode, const char *prompt) {
  const struct pam_message msg = {.msg_style = echocode,
                                  .msg = (char *) (uintptr_t) prompt};
  const struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  int retval = _converse(pamh, 1, &msgs, &resp);
  char *ret = NULL;

  if (retval != PAM_SUCCESS || resp == NULL || resp->resp == NULL ||
      *resp->resp == '\000') {

    if (retval == PAM_SUCCESS && resp && resp->resp) {
      ret = resp->resp;
    }
  } else {
    ret = resp->resp;
  }

  // Deallocate temporary storage.
  if (resp) {
    if (!ret) {
      free(resp->resp);
    }
    free(resp);
  }

  return ret;
}

pid_t getPPIDOfPID(pid_t pid) {
  struct kinfo_proc proc;
  size_t len = sizeof(proc);
  int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
  if (sysctl(mib, 4, &proc, &len, NULL, 0) < 0) {
        return 0;
  }
  if (len == 0) {
        return 0;
  }
  return proc.kp_eproc.e_ppid;
}

char* getNameOfPID(pid_t pid) {
  char* pathbuf = calloc(PROC_PIDPATHINFO_MAXSIZE, 1);
  proc_name(pid, pathbuf, PROC_PIDPATHINFO_MAXSIZE);
  return pathbuf;
}

bool isRemote() {
  pid_t pid = getpid();

  while (pid != 0) {
    char* name = getNameOfPID(pid);

    if (name == NULL) {
      return false;
    }

    if (isRemoteName(name)) {
      free(name);
      return true;
    }

    free(name);
    pid = getPPIDOfPID(pid);
  }

  return false;
}
