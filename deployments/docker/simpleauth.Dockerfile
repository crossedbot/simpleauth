ARG OS=debian:bullseye-slim
ARG GOLANG_VERSION=1.19-bullseye
ARG CGO=0
ARG GOOS=linux
ARG GOARCH=amd64

FROM golang:${GOLANG_VERSION} AS gobuilder

ARG CGO
ARG GOOS
ARG GOARCH

RUN go version
WORKDIR /go/src
COPY . .
RUN cd cmd/simpleauth && \
    CGO_ENABLED='${CGO}' GOOS='${GOOS}' GOARCH='${GOARCH}' \
    make -f /go/src/Makefile build

#-------------------------------------------------------------------------------
FROM ${OS}

ARG POSTGRES_USER
ARG POSTGRES_PASSWORD

# TODO probably shouldn't have the password as an ENV
# but whatever. You probably shouldn't be running postgres
# in a container anyways (this is more for dev).
ENV POSTGRES_USER $POSTGRES_USER
ENV POSTGRES_PASSWORD $POSTGRES_PASSWORD
ENV SIMPLEAUTH_HOME /usr/local/simpleauth
ENV PATH ${SIMPLEAUTH_HOME}/bin:$PATH
RUN mkdir -vp ${SIMPLEAUTH_HOME}
WORKDIR ${SIMPLEAUTH_HOME}

COPY --from=gobuilder /go/bin/simpleauth ./bin/simpleauth
COPY --from=gobuilder /go/src/scripts/run.bash ./bin/run-simpleauth
COPY --from=gobuilder /go/src/secrets/* /root/.simpleauth/

EXPOSE 8080
# Use shell form (not exec) to be able to expand variables
ENTRYPOINT  run-simpleauth \
	-d "postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgresql:5432/auth" \
	-e "postgres"
