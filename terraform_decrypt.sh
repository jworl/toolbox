#!/usr/bin/env bash

# author: Joshua Worley
# contact: joshua.worley@warnermedia.com

help() {
    echo ${0##*/} usage
    echo "-k, --key     : path private key for decrypting passphrase"
    echo "-t, --tfstate : path to terraform.tfstate file"
    exit 2
}

DECRYPT() {
    DATA=$(jq '[.resources[] | select(.type=="aws_instance") | .instances[].attributes | select(.password_data!="")]' ${2})

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

TFSTATE="terraform.tfstate"

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
        -t|--tfstate)
            if [ -z ${2} ]; then
                help
            else
                TFSTATE=$2
            fi
            shift
        ;;
        *)
            help
        ;;
    esac
    shift
done

if [ -f ${TFSTATE} ]; then
    if [[ $(jq '.resources | length' ${TFSTATE}) -eq 0 ]]; then
        echo "[!] ${TFSTATE} has 0 resources"
        exit 2
    fi
    DECRYPT $KEY $TFSTATE
else
    echo "[!] did not find terraform.tfstate file."
    echo "[!] is this script in the same directory?"
    echo "[!] did you provide a valid path?"
fi
