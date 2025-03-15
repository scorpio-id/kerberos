#!/bin/bash

# add kerberos services
openrc default
rc-update add krb5kdc default
service krb5kdc start

# start application
/scorpio-kerberos