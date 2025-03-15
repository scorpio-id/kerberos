#!/bin/bash

# add kerberos services
openrc default

rc-update add krb5kdc default
rc-update add krb5kadmind default

service krb5kdc start
service krb5kadmind start

# start application
/scorpio-kerberos