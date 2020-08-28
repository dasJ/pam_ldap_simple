# pam_ldap_simple

Like `pam_ldap` but a lot more simple (and hopefully more flexible).

I originally started a more simple fork of `pam_ldap`, but since it used to be a lot of code, I started this rewrite instead.
The pam module is not intended to provide full UNIX authentication, but should be used for webservers, CUPS, etc.
Both configuration and code are a lot more simple and the debug output a lot more complete.

Maybe TLS could be implemented, but we don't need that for now.

## What it does

First, the pam module binds (anonymously if no credentials are specified) as the binddn specified in the config.
With this connection, the user is searched using the given search filter.
If the search returns **exactly** one match, a bind with the given DN and the user's password is attempted.

## pam arguments

- `config=` sets the path to a configuration file.
- `debug` allows enabling debug output, it does the same as the `debug` option in the config, but also debugs the config parser

## Configuration file

The syntax is the same as the config file of `pam_ldap`: key-value pairs, separated by spaces.
Comments are possible with `#` but the config parser is very primitive.

- `debug` Set to `0` or `1` to enable debug output in syslog (no passwords are logged)
- `uri` LDAP server URI
- `binddn` DN to bind with for searching the user (not setting means anonymous bind)
- `bindpw` Password for `binddn`
- `bindpwfile` File to read `bindpw` from, overrides `bindpw`, trailing whitespace is trimmed
- `filter` LDAP search filter, `%s` is substituted with the (escaped) username, defaults to `(uid=%s)`
- `scope` LDAP Search scope (`sub`, `one`, `base`), defaults to `sub`
- `deref` LDAP deref configuration (`never`, `searching`, `finding`, `always`), defaults to `never`
