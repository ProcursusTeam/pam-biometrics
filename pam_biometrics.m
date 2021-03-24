/**
  * pam_biometrics
  *
  * Face ID and Touch ID are trademarks of Apple Inc.,
  * registered in the U.S. and other countries and regions.
  */

#include <pwd.h>
#include <stdlib.h>
#include <os/log.h>
#include <os/activity.h>
#include <CoreFoundation/CoreFoundation.h>
#include <LocalAuthentication/LocalAuthentication.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include "util.h"

#define PAM_DEFINE_LOG(category) \
static os_log_t PAM_LOG_ ## category () { \
static dispatch_once_t once; \
static os_log_t log; \
dispatch_once(&once, ^{ log = os_log_create("com.apple.pam", #category); }); \
return log; \
};

PAM_DEFINE_LOG(biometrics)
#define PAM_LOG PAM_LOG_biometrics()

CFRunLoopRef runLoop;
LAContext *context;

void TimerCallback(CFRunLoopTimerRef timer, void* info) {
    [context invalidate];
    CFRunLoopStop(runLoop);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    os_log_debug(PAM_LOG, "pam_biometrics: pam_sm_authenticate");

    __block
    int retval = PAM_AUTH_ERR;
    int timeout = 10;
    const char *user = NULL;
    const char *prompt = NULL;
    bool disableOnSSH = false;
    bool allowWatch = false;
    CFStringRef reason = NULL;
    LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;

    for (int i = 0; i < argc; i++) {
        if (COMPARE(argv[i], "timeout="))
            sscanf(argv[i], "timeout=%d", &timeout);

        if (COMPARE(argv[i], "prompt="))
            prompt = argv[i] + 7;

        if (COMPARE(argv[i], "disableonssh"))
            disableOnSSH = true;

        if (COMPARE(argv[i], "allowwatch"))
            allowWatch = true;
    }

    if (disableOnSSH && isSSH()) {
        retval = PAM_IGNORE;
        goto cleanup;
    }
    if (allowWatch)
        policy = LAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch;

    context = [[LAContext alloc] init];

    // check if device supports biometrics
    if (![context canEvaluatePolicy:policy error:nil]) {
        retval = PAM_IGNORE;
        goto cleanup;
    }

    /* get information about user to authenticate for */
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL ||
        getpwnam(user) == NULL) {
        os_log_error(PAM_LOG, "unable to obtain the username.");
        retval = PAM_USER_UNKNOWN;
        goto cleanup;
    }

    converse(pamh, PAM_TEXT_INFO, "Use Face ID/Touch ID to authenticate...");

    char *cmd = getprogname();
    if (cmd != NULL)
        reason = CFStringCreateWithFormat(NULL, NULL, CFSTR("%s is requesting to authenticate as %s"), cmd, user);
    else
        reason = CFStringCreateWithFormat(NULL, NULL, CFSTR("requesting to authenticate as %s"), user);

    runLoop = CFRunLoopGetCurrent();

    [context evaluatePolicy:policy
            localizedReason:(__bridge NSString *)reason
            reply:^(BOOL success, NSError* error) {
        if (success)
            retval = PAM_SUCCESS;
        CFRunLoopStop(runLoop);
    }];

    CFRunLoopTimerContext ctx = { 0, NULL, NULL, NULL, NULL };
    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(
        NULL, CFAbsoluteTimeGetCurrent() + timeout, 0, 0, 0, TimerCallback, &ctx);

    // Add timeout
    CFRunLoopAddTimer(runLoop, timer, kCFRunLoopDefaultMode);

    CFRunLoopRun();

cleanup:
	os_log_debug(PAM_LOG, "pam_biometrics: pam_sm_authenticate returned %d", retval);
    return retval;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    return PAM_SUCCESS;
}
