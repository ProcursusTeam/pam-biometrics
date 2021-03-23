#include <CoreFoundation/CoreFoundation.h>
#include <LocalAuthentication/LocalAuthentication.h>
#include <libgen.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include "util.h"

int timeout = 10;
const char *prompt = NULL;
bool disableOnSSH = false;
bool allowWatch = false;
LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;

CFRunLoopRef runLoop;
LAContext *context;

void TimerCallback(CFRunLoopTimerRef timer, void* info) {
    [context invalidate];
    CFRunLoopStop(runLoop);
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
        if (COMPARE(argv[i], "allowwatch")) {
            allowWatch = true;
        }
    }

    if (disableOnSSH && isSSH()) return PAM_IGNORE;
    if (allowWatch) {
        policy = LAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch;
    }

    __block BOOL result = NO;
    context = [[LAContext alloc] init];

    // check if device supports biometrics
    if (![context canEvaluatePolicy:policy error:nil]) {
        return PAM_IGNORE;
    }

    converse(pamh, PAM_TEXT_INFO, "Use FaceID/TouchID to authenticate...");

    CFStringRef reason;
    const char *user = NULL;
    pam_get_user(pamh, &user, NULL);

    char *cmd = getenv("_");

    if (cmd != NULL) {
        reason = CFStringCreateWithFormat(NULL, NULL, CFSTR("%s is requesting to authenticate as %s"), basename(cmd), user);
    } else {
        reason = CFStringCreateWithFormat(NULL, NULL, CFSTR("requesting to authenticate as %s"), user);
    }

    runLoop = CFRunLoopGetCurrent();

    [context evaluatePolicy:policy
            localizedReason:(__bridge NSString *)reason
            reply:^(BOOL success, NSError* error) {
        result = success;
        CFRunLoopStop(runLoop);
    }];

    CFRunLoopTimerContext ctx = { 0, NULL, NULL, NULL, NULL };
    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(
        NULL, CFAbsoluteTimeGetCurrent() + timeout, 0, 0, 0, TimerCallback, &ctx);

    // Add timeout
    CFRunLoopAddTimer(runLoop, timer, kCFRunLoopDefaultMode);

    CFRunLoopRun();

    return result ? PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    return PAM_SUCCESS;
}
