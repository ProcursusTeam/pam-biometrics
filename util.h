#include <security/pam_modules.h>

bool isSSH();
char *converse(pam_handle_t *pamh, int echocode, const char *prompt);
