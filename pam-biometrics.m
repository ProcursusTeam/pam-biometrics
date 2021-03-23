#include <CoreFoundation/CoreFoundation.h>
#include <LocalAuthentication/LocalAuthentication.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include "util.h"

#define MESSAGE "PAM Authentication"

#define COMPARE(X, Y) (strncmp(X, Y, strlen(Y)) == 0)

int timeout = 10;
const char *prompt = NULL;
bool disableOnSSH = false;

void TimerCallback(CFRunLoopTimerRef timer, void* info) {
    CFRunLoopStop(CFRunLoopGetCurrent());
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    for (int i = 0; i < argc; i++) {
        if (COMPARE(argv[i], "timeout=")) {
            sscanf(argv[i], "timeout=%d", &timeout);
        }
        if (COMPARE(argv[i], "prompt=")) {
            prompt = argv[i] + 7;
        }
        if (COMPARE(argv[i], "disableonssh")) {
            disableOnSSH = true;
        }
    }

    if (disableOnSSH && isSSH()) return PAM_IGNORE;

    __block BOOL result = NO;
    LAContext* context = [[LAContext alloc] init];

    // check if device supports biometrics
    if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil]) {
        return PAM_IGNORE;
    }

    [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
             localizedReason:@"authenticate"
             reply:^(BOOL success, NSError* error) {
                result = success;
                CFRunLoopStop(CFRunLoopGetCurrent());
             }];

    CFRunLoopTimerContext ctx = { 0, NULL, NULL, NULL, NULL };
    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(
        NULL, CFAbsoluteTimeGetCurrent() + timeout, 0, 0, 0, TimerCallback, &ctx);

    // Add timeout
    CFRunLoopAddTimer(CFRunLoopGetCurrent(), timer, kCFRunLoopDefaultMode);

    CFRunLoopRun();

    return result ? PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    return PAM_SUCCESS;
}
