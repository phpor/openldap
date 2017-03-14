#include "portable.h"
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "slap.h"

typedef struct {
  char *data;
  size_t size;
}Response;

static char *dn2user(struct berval *dn) {
	int i = 0;
	while(i < dn->bv_len && dn->bv_val[i++] != '=');
	int j = i;
	while(j < dn->bv_len && dn->bv_val[j++] != ',');
	int user_len = j - i - 1;
	if (user_len <= 0 || user_len > 96) return NULL;
	char *user = (char *)malloc(user_len + 1);
	if (user == NULL) return NULL;
	memcpy(user, dn->bv_val + i, user_len); user[user_len] = '\0';
	return user;
}

static size_t curl_write(char *data, size_t size, size_t nmemb, void *userp) {
        size_t          len = size * nmemb;
	Response *response = (Response *)userp;
	if (response->size == -1) return -1; // error yet

	response->data = realloc(response->data, response->size + len + 1);
	if (response->data == NULL) {
		response->size = -1;
		return -1;
	}
	memcpy(&(response->data[response->size]), data, len);
	response->size += len;
	response->data[response->size] = 0;
	return len;
}
 

//int auth_token(char* user, char *pass) {
int auth_token(struct berval *dn, struct berval *cred) {
	char user[100];
	int  user_len;
	char *puser = dn2user(dn);
	if (puser == NULL) return 1;
	user_len = strlen(puser);
	if (user_len >= 100) {
		free(puser);
		return 1;
	}
	memcpy(user, puser, user_len);
	user[user_len] = '\0';
	free(puser);

	if (0 == strcmp(user, "admin")) return 0;
	int pass_len = cred->bv_len;
	if (pass_len <= 6 || pass_len >=96) { // password is invalid
		return 1;
	}
	char token[7];
	int token_len = 6;
	memcpy(token, cred->bv_val + cred->bv_len - token_len, token_len);
	token[token_len] = '\0';
	cred->bv_len -= token_len;

	char post_data[256];
	char url[256];
	memcpy(url, getenv("AUTH_URL"), strlen(getenv("AUTH_URL")));

	CURL *curl;
	CURLcode res;
	Response response;
	response.data = malloc(1);
	response.size = 0;

	sprintf(post_data, "username=%s&code=%s&app=ldap&ip=1.1.1.1", user, token);

	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url);

		/* size of the POST data */
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(post_data));

		/* pass in a pointer to the data - libcurl will not copy */
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);


		/* Perform the request, res will get the return code */ 
		res = curl_easy_perform(curl);
		/* Check for errors */ 
		if(res != CURLE_OK) {
			fprintf(stderr, "%s, curl_easy_perform() failed: %s\n", user, curl_easy_strerror(res));
			Debug( LDAP_DEBUG_TRACE, "fail, %s, call url (%s) fail\n", user, url, 0 );
		}

		/* always cleanup */ 
		curl_easy_cleanup(curl);

		const char *response_ok = "{\"retcode\":2000000,";
		if(response.size > 0) {
			if (0 == strncmp(response_ok, response.data, strlen(response_ok))) {
				free(response.data);
				return 0;
			}
			fprintf(stderr, "fail, %s, response: %s", user, response.data);
			Debug( LDAP_DEBUG_TRACE, "fail, %s, response: %s\n", user, response.data, 0 );
		} else {
			fprintf(stderr, "fail, %s, response: null", user);
			Debug( LDAP_DEBUG_TRACE, "fail, %s, response: null\n", user, 0, 0 );
		}
	} else {
		fprintf(stderr, "fail\tcurl_init_fail");
		Debug( LDAP_DEBUG_TRACE, "fail, %s, curl_init_fail\n", user, 0, 0 );
	}
	free(response.data);
	return 1;

}

