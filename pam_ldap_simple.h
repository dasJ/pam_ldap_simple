#ifndef PAM_LDAP_SIMPLE_H
#define PAM_LDAP_SIMPLE_H

#include <ldap.h>

#define DEFAULT_CONFIG_FILE "/etc/pam_ldap_simple"

#ifndef LDAP_FILT_MAXSIZ
#define LDAP_FILT_MAXSIZ 1024
#endif /* LDAP_FILT_MAXSIZ */

#define CHECKPOINTER(ptr) do { if ((ptr) == NULL) { \
	fclose(fp); \
	return PAM_BUF_ERR; \
} \
} while (0)

typedef struct pam_ldap_simple_state {
	int debug;

	char *configFile;
	char *bindpwFile;
	char *escapedUsername;
	char *userdn;

	LDAP        *ldap;
	LDAPMessage *ldapRes;
	char        *ldapURI;
	char        *ldapBase;
	char        *ldapBinddn;
	char        *ldapBindpw;
	char        *ldapFilter;
	int          ldapScope;
	int          ldapDeref;
	int          ldapBound;

} pam_ldap_simple_state_t;

#endif
