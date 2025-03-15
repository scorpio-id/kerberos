FROM golang:latest as builder
WORKDIR /workspace

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o scorpio-kerberos cmd/main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM alpine:latest

RUN apk update
RUN apk add --no-cache bash
WORKDIR /

# Add configuration files
ADD /internal/config/local.yml /internal/config/local.yml
ADD /internal/config/krb5.conf /internal/config/krb5.conf

# Add swagger files
ADD /docs/swagger.json /docs/swagger.json
ADD /docs/swagger.yaml /docs/swagger.yaml

# Add krb5_newrealm script 
ADD /scripts/krb5_newrealm.sh /scripts/krb5_newrealm.sh

COPY --from=builder /workspace/scorpio-kerberos .

# install kerberos KDC, database, and kadmin
RUN apk add krb5
RUN apk add krb5-server

# copy the kdc.conf and krb5.conf from the builder to the correct locations on the image filesystem
ADD /internal/config/krb5.conf /etc/krb5.conf
ADD /internal/config/kdc.conf /etc/krb5kdc/kdc.conf

# create a new realm -- using default password
# permission script
RUN chmod +x /scripts/krb5_newrealm.sh
RUN { echo 'password\n'; echo 'password\n'; } | /scripts/krb5_newrealm.sh

# ensure KDC and kadmin are started by command above, otherwise use service <name> start

# provision the scorpio/admin@SCORPIO.IO service principal
# this is currently done by the application itself
# RUN kadmin.local add_principal -pw resetme scorpio/admin@KRB.SCORPIO.ORDINARYCOMPUTING.COM 

# the command to start the application
ENTRYPOINT ["/scorpio-kerberos"]