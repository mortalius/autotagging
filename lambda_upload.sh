#!/bin/bash
lambda_archive="lambda_bundle.zip"
zip_targets="tagreplicator.py requirements.txt"

profile="profileX"
handler="tagreplicator.lambda_handler"
role="arn:aws:iam::205685244378:role/service-role/LAMBDA_ROLE"
function_name="tag replicator"
description="Propagates tags to snapshots and volumes based on tags from associated volumes/instances/amis"
``environment="Variables={REGION=us-east-1,DRYRUN=True,AMI_LOOKUP=False,TAGS=cost}"

# workaround for possible impossibility to set file world-readable
cp $zip_targets /tmp/
cd /tmp
chmod a+r $zip_targets
rm -f $lambda_archive
zip $lambda_archive $zip_targets


if [ "$1" == "update" ]; then
    echo "Updating $function_name"
    aws --profile $profile lambda update-function-code --function $function_name --zip-file fileb://$lambda_archive
elif [ "$1" == "delete" ]; then
    echo "Deleting $function_name"
    aws --profile $profile lambda delete-function --function $function_name
else
    echo "Creating $function_name"
    aws --profile $profile lambda create-function --function $function_name --runtime python2.7 \
                               --role "$role" \
                               --handler "$handler" \
                               --zip-file fileb://$lambda_archive \
                               --timeout 300 --memory-size 512 \
                               --description "$description" \
                               --environment "$environment"
fi