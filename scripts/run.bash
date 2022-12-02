#!/bin/bash

SIMPLEAUTH=$(command -v simpleauth)

log()
{
    echo "$(date +"%F %T"): $*"
}

join_by()
{
    local d=$1; shift;
    local f=$1; shift;
    printf %s "$f" "${@/#/$d}"
}

usage()
{
    echo -e "$(basename "$0") [-h] [-c <config.toml>] [-d <dbpath>]
    [-e <dbdialect>] [-p <port>] -g <grant>]...
    -- program to start the simpleauth service

    where:
        -h  show this help text
        -c  configuration file location; default is '${HOME}/.simpleauth/config.toml'
        -d  set authentication database address; default is 'mongodb://127.0.0.1:27017'
        -e  set database dialect type; default is 'mongodb'
        -p  set listening port of the HTTP service; default is '8080'
        -g  add an authentication grant"
        exit
}

# START #

conf="${HOME}/.simpleauth/config.toml"
port="8080"
db_path="mongodb://127.0.0.1:27017"
db_dialect="mongodb"
key="${HOME}/.simpleauth/key.pem"
cert="${HOME}/.simpleauth/cert.pem"
auth_grants=()

while getopts "hc:p:d:e:g:" opt; do
    case "$opt" in
    [h?]) usage
        ;;
    c) conf="${OPTARG}"
        ;;
    d) db_path="${OPTARG}"
        ;;
    e) db_dialect="${OPTARG}"
        ;;
    p) port="${OPTARG}"
        ;;
    g) auth_grants+=($OPTARG)
        ;;
    esac
done

conf_dir=$(dirname ${conf})
if [ ! -d ${conf_dir} ]; then
    log $(mkdir -vp ${conf_dir})
fi

auth_grants_str="[]"
if [ ${#auth_grants[@]} -gt 0 ]; then
    auth_grants_str="[\"$(join_by '", "' ${auth_grants[@]})\"]"
fi

cat <<EOF > ${conf}
    host="0.0.0.0"
    port=${port}
    read_timeout=30
    write_timeout=30

    database_path="${db_path}"
    database_dialect="${db_dialect}"
    private_key="${key}"
    certificate="${cert}"
    auth_grants=${auth_grants_str}
EOF
log "created '${conf}':
$(cat ${conf} | sed 's/^/\t/')"

$SIMPLEAUTH --config-file="${conf}"
