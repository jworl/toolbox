#!/bin/bash
function help
{
    echo ${0##*/} usage
    echo -r, --region  : aws region
    echo -ta, --targetacctid : target account id.
    echo -tr, --targetacctrole : the target account role to assume
    exit 0
}
while (( "$#" )); do
case $1 in
    -r|--region)
     REGION=$2
     shift
    ;;
    -p|--profile)
     PROFILENAME=${2}
     shift
    ;;
    -ta|--targetacctid)
     TARGETACCTID=$2
     shift
    ;;
    -tr|--targetrole)
     TARGETROLE=$2
     shift
    ;;
    -s|--sessionname)
     SESSIONNAME=$2
     shift
    ;;
    -d|--duration)
     DURATION=$2
     shift
    ;;
    -e|--externalid)
     EXTERNALID="--external-id $2"
     shift
    ;;
    -c|--cmd)
     CMD=${2}
     shift
    ;;
    *)
    help     # unknown option
    ;;
esac
shift
done
# set defaults if not defined.
[ -z "$REGION" ] && REGION="us-east-1"
[ -z "$SESSIONNAME" ] && SESSIONNAME="wmcso"
[ -z "$DURATION" ] && DURATION="3600"
export AWS_DEFAULT_REGION=${REGION}
ROLE_ARN="arn:aws:iam::${TARGETACCTID}:role/${TARGETROLE}"
ROLE_SESSION_NAME=${SESSIONNAME}
CREDS=$(aws sts assume-role --profile ${PROFILENAME} --role-arn ${ROLE_ARN} --duration-seconds ${DURATION} ${EXTERNALID}  --role-session-name ${ROLE_SESSION_NAME})
if [ "$?" -ne "0" ]; then
echo "Failed to assume role ${ROLE_ARN}.  Exiting."
exit 1
fi
export AWS_ACCESS_KEY_ID=`echo ${CREDS} | jq -r '.Credentials | .AccessKeyId'`
export AWS_SECRET_ACCESS_KEY=`echo ${CREDS} | jq -r '.Credentials | .SecretAccessKey'`
export AWS_SECURITY_TOKEN=`echo ${CREDS} | jq -r '.Credentials | .SessionToken'`
export AWS_SECURITY_EXPIRATION=`echo ${CREDS} | jq -r '.Credentials | .Expiration'`
export AWS_SESSION_TOKEN=$AWS_SECURITY_TOKEN
export AWS_SELECTED_ROLE=$(aws iam list-account-aliases --output text | awk '{ print $NF }')-${TARGETROLE}
export PS1="\[\e[37m\]\u\[\e[m\]\[\e[36m\]@\[\e[m\]\[\e[32m\]\h\[\e[m\]:\[\e[36m\][\[\e[m\]\[\e[35m\]\W\[\e[m\]\[\e[36;40m\]]\[\e[m\]\[\e[37;40m\]${AWS_SELECTED_ROLE} (${AWS_DEFAULT_REGION})\[\e[m\]\[\e[31m\]>\[\e[m\] "
if [ -z "${CMD}" ]; then
/usr/local/bin/bash
else
${CMD}
fi
