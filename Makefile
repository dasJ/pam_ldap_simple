LDFLAGS += -shared -lldap

.PHONY: all clean install pam_ldap_simple

all: pam_ldap_simple

pam_ldap_simple: pam_ldap_simple.so

pam_ldap_simple.so: pam_ldap_simple.o
	$(LD) $(LDFLAGS) -O3 $^ -o $@

pam_ldap_simple.o: pam_ldap_simple.c pam_ldap_simple.h
	$(CC) $(CFLAGS) -c -O3 $< -o $@

clean:
	rm pam_ldap_simple.so pam_ldap_simple.o

install: pam_ldap_simple.so
	mkdir -p $(PREFIX)/lib/security
	cp -f $^ $(PREFIX)/lib/security/
