#ifndef _SLAPD_AUTH_TOKEN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
int auth_token(struct berval *dn, struct berval *cred);

#define _SLAPD_AUTH_TOKEN
#endif
