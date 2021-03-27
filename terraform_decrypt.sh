#!/usr/bin/env bash

help() {
    echo ${0##*/} usage
    echo "-k, --key  : private key for decrypting passphrase"
    exit 2
}

DECRYPT() {
    DATA=$(jq '[.resources[] | select(.type=="aws_instance") | .instances[].attributes | select(.password_data!="")]' terraform.tfstate)

    for a in $(seq 0 `echo $DATA | jq length-1`); do
        ID=$(echo $DATA | jq -r ".[$a] | .id")
        NM=$(echo $DATA | jq -r ".[$a] | .tags.Name")
        PI=$(echo $DATA | jq -r ".[$a] | .public_ip")
        echo $DATA | jq -r ".[$a] | .password_data" | base64 -d > ${host}.bin
        PD=$(openssl rsautl -decrypt -inkey ${1} -in ${host}.bin)
        rm -f ${host}.bin
        I="{\"id\":\"$ID\", \"name\":\"$NM\", \"public_ip\":\"$PI\", \"password_data\":\"$PD\"}"
        echo $I | jq .
    done
}


while (( "$#" )); do
    case $1 in
        -k|--key)
            if [ -z ${2} ]; then
                help
            else
                KEY=$2
            fi
            shift
        ;;
        *)
            help
        ;;
    esac
    shift
done

DECRYPT $KEY
