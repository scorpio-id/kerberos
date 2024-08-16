FROM golang:1.19.8 as builder
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
WORKDIR /

# Add configuration files
ADD /internal/config/local.yml /internal/config/local.yml

# Add swagger files
ADD /docs/swagger.json /docs/swagger.json
ADD /docs/swagger.yaml /docs/swagger.yaml

COPY --from=builder /workspace/scorpio-kerberos .

# install kerberos KDC, database, and kadmin
RUN sudo apt install -y krb5-kdc -y krb5-admin-server

# copy the kdc.conf and krb5.conf from the builder to the correct locations on the image filesystem
ADD /internal/config/krb5.conf /etc/krb5.conf
ADD /internal/config/kdc.conf /etc/krb5kdc/kdc.conf

# create a new realm -- using default password
RUN { echo 'resetme\n'; echo 'resetme\n'; } | sudo krb5_newrealm

# ensure KDC and kadmin are started by command above, otherwise use service <name> start

# provision the scorpio/admin@SCORPIO.IO service principal
RUN kadmin.local add_principal -pw resetme scorpio/admin@SCORPIO.ORDINARYCOMPUTING.COM 

# the command to start the application
ENTRYPOINT ["/scorpio-kerberos"]