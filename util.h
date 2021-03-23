#include <security/pam_modules.h>

#define COMPARE(X, Y) (strncmp(X, Y, strlen(Y)) == 0)

bool isSSH();
char *converse(pam_handle_t *pamh, int echocode, const char *prompt);
