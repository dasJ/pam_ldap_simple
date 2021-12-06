#ifdef __STDC_ALLOC_LIB__
#define __STDC_WANT_LIB_EXT2__ 1
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include <ctype.h>
#include <ldap.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <syslog.h>

#include "pam_ldap_simple.h"

pam_ldap_simple_state_t *allocState() {
	pam_ldap_simple_state_t *state = calloc(1, sizeof(pam_ldap_simple_state_t));

	state->debug = 0;
	state->bindpwFile = NULL;

	state->ldapURI = NULL;
	state->ldapFilter = NULL;
	state->ldapScope = LDAP_SCOPE_SUBTREE;
	state->ldapDeref = LDAP_DEREF_NEVER;
	state->ldapBound = 0;

	return state;
}

void freeState(pam_ldap_simple_state_t **state) {
	pam_ldap_simple_state_t *s;

	s = *state;
	if (s == NULL)
		return;

	if (s->bindpwFile != NULL)
		free(s->bindpwFile);

	if (s->userdn != NULL)
		free(s->userdn);

	if (s->escapedUsername != NULL)
		free(s->escapedUsername);

	if (s->ldap != NULL && s->ldapBound)
		ldap_unbind_ext(s->ldap, NULL, NULL);

	if (s->ldapRes != NULL)
		ldap_msgfree(s->ldapRes);

	if (s->ldapURI != NULL)
		free(s->ldapURI);

	if (s->ldapBase != NULL)
		free(s->ldapBase);

	if (s->ldapBinddn != NULL)
		free(s->ldapBinddn);

	if (s->ldapBindpw != NULL) {
		register char *__xx__;
		if ((__xx__ = s->ldapBindpw))
			while (*__xx__)
				*__xx__++ = '\0';
		free(s->ldapBindpw);
		s->ldapBindpw = NULL;
	}

	if (s->ldapFilter != NULL)
		free(s->ldapFilter);

	memset(s, 0, sizeof(*s));
	free(s);
	*state = NULL;
}

int escapeString(const char *str, char *buf, size_t buflen) {
	int ret = PAM_BUF_ERR;
	char *p = buf;
	char *limit = p + buflen - 3;
	const char *s = str;

	while (p < limit && *s) {
		switch (*s) {
			case '*':
				strcpy(p, "\\2a");
				p += 3;
				break;
			case '(':
				strcpy(p, "\\28");
				p += 3;
				break;
			case ')':
				strcpy(p, "\\29");
				p += 3;
				break;
			case '\\':
				strcpy(p, "\\5c");
				p += 3;
				break;
			default:
				*p++ = *s;
				break;
		}
		s++;
	}

	if (*s == '\0') {
		/* got to the end */
		*p = '\0';
		ret = PAM_SUCCESS;
	}
	return ret;
}

int getAuthtok(pam_handle_t *pamh, int flags) {
	int rc;
	char *p;
	struct pam_message msg[1], *pmsg[1];
	struct pam_response *resp;
	struct pam_conv *conv;

	pmsg[0] = &msg[0];
	msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
	msg[0].msg = "Password: ";
	resp = NULL;

	rc = pam_get_item(pamh, PAM_CONV, (const void**) &conv);
	if (rc == PAM_SUCCESS)
		rc = conv->conv(1, (const struct pam_message**) pmsg, &resp, conv->appdata_ptr);
	else
		return rc;

	if (resp != NULL) {
		if ((flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL) {
			free(resp);
			return PAM_AUTH_ERR;
		}

		p = resp[0].resp;
		resp[0].resp = NULL;
	} else
		return PAM_CONV_ERR;

	free(resp);
	pam_set_item(pamh, PAM_AUTHTOK, p);

	return PAM_SUCCESS;
}

/* expected hook */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

/* expected hook */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	int rc;
	int i;
	char b[BUFSIZ];
	FILE *fp;
	struct timeval timeout;
	char filter[LDAP_FILT_MAXSIZ];
	LDAPMessage *msg;
	struct berval userbv, euserbv;
	/* Stuff from PAM - not freed */
	const char *raw_username;
	char *password;

	/* Allocate state */
	pam_ldap_simple_state_t *state = allocState();

	/* Parse arguments */
	for (i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "config=", 7)) {
			state->configFile = (char*) argv[i] + 7;
		} else if (!strcmp(argv[i], "debug")) {
			state->debug = 1;
		} else {
			syslog(LOG_ERR, "pam_ldap_simple: illegal option %s", argv[i]);
		}
	}

	/* Default config */
	if (state->configFile == NULL)
		state->configFile = DEFAULT_CONFIG_FILE;

	/* Parse config */
	fp = fopen(state->configFile, "r");
	if (fp == NULL) {
		syslog(LOG_ALERT, "pam_ldap_simple: missing file \"%s\"", state->configFile);
		freeState(&state);
		return PAM_SERVICE_ERR;
	}
	if (state->debug)
		syslog(LOG_DEBUG, "pam_ldap_simple: parsing config %s", state->configFile);
	while (fgets(b, sizeof(b), fp) != NULL) {
		char *k, *v;
		int len;
		if (*b == '\n' || *b == '#')
			continue;
		k = b;
		v = k;
		while (*v != '\0' && *v != ' ' && *v != '\t')
			v++;
		if (*v == '\0')
			continue;
		*v = '\0';
		/* skip all whitespaces between keyword and value */
		while (*v == ' ' || *v == '\t' || *v == '\0')
			v++;
		/* kick off all whitespaces and newline at the end of value */
		len = strlen(v) - 1;
		while (v[len] == ' ' || v[len] == '\t' || v[len] == '\n')
			--len;
		v[len + 1] = '\0';
		/* Parse values */
		if (!strcasecmp(k, "uri"))
			CHECKPOINTER(state->ldapURI = strdup(v));
		else if (!strcasecmp(k, "base"))
			CHECKPOINTER(state->ldapBase = strdup(v));
		else if (!strcasecmp(k, "binddn"))
			CHECKPOINTER(state->ldapBinddn = strdup(v));
		else if (!strcasecmp(k, "bindpw"))
			CHECKPOINTER(state->ldapBindpw = strdup(v));
		else if (!strcasecmp(k, "bindpwfile"))
			CHECKPOINTER(state->bindpwFile = strdup(v));
		else if (!strcasecmp(k, "filter"))
			CHECKPOINTER(state->ldapFilter = strdup(v));
		else if (!strcasecmp(k, "debug"))
			state->debug = atoi(v);
		else if (!strcasecmp(k, "scope")) {
			if (!strncasecmp(v, "sub", 3))
				state->ldapScope = LDAP_SCOPE_SUBTREE;
			else if (!strncasecmp(v, "one", 3))
				state->ldapScope = LDAP_SCOPE_ONELEVEL;
			else if (!strncasecmp(v, "base", 4))
				state->ldapScope = LDAP_SCOPE_BASE;
			else
				syslog(LOG_ERR, "pam_ldap_simple: unknown scope value %s", v);
		}
		else if (!strcasecmp(k, "deref")) {
			if (!strncasecmp(v, "never", 5))
				state->ldapDeref = LDAP_DEREF_NEVER;
			else if (!strncasecmp(v, "searching", 9))
				state->ldapDeref = LDAP_DEREF_SEARCHING;
			else if (!strncasecmp(v, "finding", 7))
				state->ldapDeref = LDAP_DEREF_FINDING;
			else if (!strncasecmp(v, "always", 6))
				state->ldapDeref = LDAP_DEREF_ALWAYS;
			else
				syslog(LOG_ERR, "pam_ldap_simple: unknown deref value %s", v);
		}
	}

	/* Handle bindpwfile */
	if (state->bindpwFile != NULL) {
		if (state->debug)
			syslog(LOG_DEBUG, "pam_ldap_simple: reading \"%s\"", state->bindpwFile);

		fp = fopen(state->bindpwFile, "r");
		if (fp == NULL) {
			syslog(LOG_ALERT, "pam_ldap_simple: missing file \"%s\"", state->bindpwFile);
			freeState(&state);
			return PAM_SERVICE_ERR;
		}
		if (!fgets(b, sizeof(b), fp)) {
			syslog(LOG_ALERT, "pam_ldap_simple: cannot read \"%s\"", state->bindpwFile);
			freeState(&state);
			return PAM_SERVICE_ERR;
		}
		/* Trailing whitespace */
		int end = strlen(b);
		while (isspace(b[end - 1])) end--;
		b[end] = '\0';
		CHECKPOINTER(state->ldapBindpw = strdup(b));
	}

	/* Clear buffer */
	memset(b, 0, BUFSIZ);

	/* Require URI */
	if (state->ldapURI == NULL) {
		syslog(LOG_ALERT, "pam_ldap_simple: missing \"uri\" in file \"%s\"", state->configFile);
		freeState(&state);
		return PAM_SERVICE_ERR;
	}
	/* Default filter */
	if (state->ldapFilter == NULL)
		CHECKPOINTER(state->ldapFilter = strdup("(uid=%s)"));

	/* Debug output */
	if (state->debug) {
		syslog(LOG_DEBUG, "pam_ldap_simple: uri=%s base=%s binddn=%s scope=%d deref=%d filter=%s",
			state->ldapURI,
			state->ldapBase,
			state->ldapBinddn,
			state->ldapScope,
			state->ldapDeref,
			state->ldapFilter);
	}

	/* Get username */
	rc = pam_get_user(pamh, &raw_username, NULL);
	if (rc != PAM_SUCCESS) {
		syslog(LOG_ALERT, "pam_ldap_simple: unable to retrieve the username");
		freeState(&state);
		return rc;
	}

	if (state->debug)
		syslog(LOG_DEBUG, "pam_ldap_simple: raw username is %s", raw_username);

	/* Escape the username */
	userbv.bv_val = (char*) raw_username;
	userbv.bv_len = strlen(raw_username);
	if (ldap_bv2escaped_filter_value(&userbv, &euserbv) != 0) {
		syslog(LOG_ALERT, "pam_ldap_simple: unable to escape the username");
		freeState(&state);
		return PAM_USER_UNKNOWN;
	}
	state->escapedUsername = euserbv.bv_val;
	if (state->debug)
		syslog(LOG_DEBUG, "pam_ldap_simple: escaped username is %s", state->escapedUsername);

	/* Get password */
	rc = getAuthtok(pamh, flags);
	if (rc != PAM_SUCCESS) {
		syslog(LOG_ALERT, "pam_ldap_simple: unable to get the auth token");
		freeState(&state);
		return rc;
	}
	rc = pam_get_item(pamh, PAM_AUTHTOK, (const void**) &password);
	if (rc != PAM_SUCCESS) {
		syslog(LOG_ALERT, "pam_ldap_simple: unable to get the password");
		freeState(&state);
		return rc;
	}
	if (password == NULL || password[0] == '\0') {
		syslog(LOG_ERR, "pam_ldap_simple: no password provided");
		freeState(&state);
		return PAM_AUTH_ERR;
	}

	/* Establish LDAP connection */
	int lal = -1;
	if (state->debug)
		ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &lal);

	if (state->debug)
		syslog(LOG_DEBUG, "pam_ldap_simple: ldap_initialize");

	rc = ldap_initialize(&state->ldap, state->ldapURI);
	if (rc != LDAP_SUCCESS) {
		syslog(LOG_ALERT, "pam_ldap_simple: ldap_initialize %s", ldap_err2string(rc));
		freeState(&state);
		return PAM_SERVICE_ERR;
	}
	if (!state->ldap) {
		syslog(LOG_ALERT, "pam_ldap_simple: ldap_initialize returned nothing");
		freeState(&state);
		return PAM_SERVICE_ERR;
	}

	if (state->debug)
		syslog(LOG_DEBUG, "pam_ldap_simple: ldap_set_option");

	/* Insert our options */
	rc = 3;
	(void) ldap_set_option(state->ldap, LDAP_OPT_DEREF, &state->ldapDeref);
	(void) ldap_set_option(state->ldap, LDAP_OPT_PROTOCOL_VERSION, &rc);

	if (state->debug)
		syslog(LOG_DEBUG, "pam_ldap_simple: ldap_sasl_bind_s");

	/* Bind */
	struct berval cred;
	if (state->ldapBindpw != NULL) {
		cred.bv_val = state->ldapBindpw;
		cred.bv_len = strlen(cred.bv_val);
	}
	rc = ldap_sasl_bind_s(state->ldap, state->ldapBinddn, LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		syslog(LOG_ALERT, "pam_ldap_simple: ldap_sasl_bind_s %s", ldap_err2string(rc));
		freeState(&state);
		return PAM_AUTHINFO_UNAVAIL;
	}
	state->ldapBound = 1;
	if (state->ldapBindpw != NULL)
		memset(cred.bv_val, 0, cred.bv_len + 1);

	/* Build filter */
	if (snprintf(filter, sizeof filter, state->ldapFilter, state->escapedUsername) < 0) {
		syslog(LOG_ALERT, "pam_ldap_simple: cannot format filter");
		freeState(&state);
		return PAM_SERVICE_ERR;
	}
	if (state->debug)
		syslog(LOG_DEBUG, "pam_ldap_simple: final filter is %s", filter);

	if (state->debug)
		syslog(LOG_DEBUG, "pam_ldap_simple: ldap_search_ext_s");

	/* Search */
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;
	rc = ldap_search_ext_s(
		state->ldap,
		state->ldapBase,
		state->ldapScope,
		filter,
		(char*[]){NULL}, /* attrs */
		0, /* attrsonly */
		NULL, /* serverctrls */
		NULL, /* clientctrls */
		&timeout, /* timeout */
		10000, /* sizelimit */
		&state->ldapRes);

	if (rc != LDAP_SUCCESS) {
		syslog(LOG_ERR, "pam_ldap_simple: ldap_search_ext_s %s", ldap_err2string(rc));
		freeState(&state);
		return PAM_USER_UNKNOWN;
	}

	if (state->debug)
		syslog(LOG_DEBUG, "pam_ldap_simple: ldap_count_entries");

	/* Count */
	rc = ldap_count_entries(state->ldap, state->ldapRes);
	if (rc == 0) {
		syslog(LOG_WARNING, "pam_ldap_simple: no LDAP user found for %s", state->escapedUsername);
		freeState(&state);
		return PAM_USER_UNKNOWN;
	}
	if (rc != 1) {
		syslog(LOG_ERR, "pam_ldap_simple: not exactly one user returned, got %d for %s", rc, state->escapedUsername);
		freeState(&state);
		return PAM_USER_UNKNOWN;
	}

	if (state->debug)
		syslog(LOG_DEBUG, "pam_ldap_simple: ldap_first_entry");

	/* Handle results */
	msg = ldap_first_entry(state->ldap, state->ldapRes);
	if (msg == NULL) {
		syslog(LOG_ERR, "pam_ldap_simple: no user returned");
		freeState(&state);
		return PAM_USER_UNKNOWN;
	}
	if (state->debug)
		syslog(LOG_DEBUG, "pam_ldap_simple: ldap_get_dn");
	state->userdn = ldap_get_dn(state->ldap, msg);
	if (state->userdn == NULL) {
		syslog(LOG_CRIT, "pam_ldap_simple: no userdn returned");
		freeState(&state);
		return PAM_SERVICE_ERR;
	}

	/* Bind as user */
	if (state->debug)
		syslog(LOG_DEBUG, "pam_ldap_simple: ldap_sasl_bind_s as %s", state->userdn);
	cred.bv_val = password;
	cred.bv_len = strlen(password);
	rc = ldap_sasl_bind_s(state->ldap, state->userdn, LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		syslog(LOG_ERR, "pam_ldap_simple: ldap_sasl_bind_s (for %s) %s", state->userdn, ldap_err2string(rc));
		freeState(&state);
		return PAM_AUTH_ERR;
	}
	state->ldapBound = 1;
	memset(cred.bv_val, 0, cred.bv_len + 1);

	freeState(&state);
	return PAM_SUCCESS;
}
