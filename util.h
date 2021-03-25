#include <string.h>
#include <stdbool.h>
#include <security/pam_modules.h>

#define COMPARE(X, Y) (strncmp(X, Y, strlen(Y)) == 0)
#define CASECOMPARE(X, Y) (strncasecmp(X, Y, strlen(Y)) == 0)


bool isRemote();
char *converse(pam_handle_t *pamh, int echocode, const char *prompt);
