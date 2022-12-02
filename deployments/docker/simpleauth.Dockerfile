ARG OS_NICKNAME=bullseye
ARG OS=debian:bullseye-slim
ARG ARCH=x64

FROM ${OS}

ENV SIMPLEAUTH_HOME /usr/local/simpleauth
ENV PATH ${SIMPLEAUTH_HOME}/bin:$PATH
RUN mkdir -vp ${SIMPLEAUTH_HOME}
WORKDIR ${SIMPLEAUTH_HOME}

COPY --from=simpleauth-builder /go/bin/simpleauth ./bin/simpleauth
COPY ./scripts/run.bash ./bin/run-simpleauth
COPY ./secrets/* /root/.simpleauth/

EXPOSE 8080
ENTRYPOINT [ "run-simpleauth", "-d", "mongodb://mongo:27017", "-e", "mongo" ]
