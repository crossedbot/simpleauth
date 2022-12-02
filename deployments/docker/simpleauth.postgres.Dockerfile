ARG OS_NICKNAME=bullseye
ARG OS=debian:bullseye-slim
ARG ARCH=x64

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

COPY --from=simpleauth-builder:latest /go/bin/simpleauth ./bin/simpleauth
COPY ./scripts/run.bash ./bin/run-simpleauth
COPY ./secrets/* /root/.simpleauth/

EXPOSE 8080
# Use shell form (not exec) to be able to expand variables
ENTRYPOINT  run-simpleauth -d "postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgresql:5432/auth" -e "postgres"
