#include <CoreFoundation/CoreFoundation.h>
#include <LocalAuthentication/LocalAuthentication.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define TIMEOUT 10

void TimerCallback(CFRunLoopTimerRef timer, void* info) {
    CFRunLoopStop(CFRunLoopGetCurrent());
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    __block BOOL result = NO;
    LAContext* context = [[LAContext alloc] init];

    [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
            localizedReason:@"authenticate"
                      reply:^(BOOL success, NSError* error) {
                          result = success;
                          CFRunLoopStop(CFRunLoopGetCurrent());
                      }];

    CFRunLoopTimerContext ctx = { 0, NULL, NULL, NULL, NULL };
    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(
      NULL, CFAbsoluteTimeGetCurrent() + TIMEOUT, 0, 0, 0, TimerCallback, &ctx);

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
