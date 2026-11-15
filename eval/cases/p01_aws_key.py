import boto3

s3 = boto3.client(
    "s3",
    aws_access_key_id="__HG_FAKE_AWS_KEY_ID__",
    aws_secret_access_key="__HG_FAKE_AWS_SECRET__",
)
