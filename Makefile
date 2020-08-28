LDFLAGS += -shared -lldap

.PHONY: all clean install pam_ldap_simple

all: pam_ldap_simple

pam_ldap_simple: pam_ldap_simple.so

pam_ldap_simple.so: pam_ldap_simple.o
	$(LD) $(LDFLAGS) $^ -o $@

pam_ldap_simple.o: pam_ldap_simple.c pam_ldap_simple.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm pam_ldap_simple.so pam_ldap_simple.o

install: pam_ldap_simple.so
	mkdir -p $(PREFIX)/lib/security
	cp -f $^ $(PREFIX)/lib/security/
