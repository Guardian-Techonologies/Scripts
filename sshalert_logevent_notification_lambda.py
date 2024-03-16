import base64
import boto3
import gzip
import json
import logging
import os
import re
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def log_payload(event):
    if 'awslogs' in event and 'data' in event['awslogs']:
        logger.setLevel(logging.DEBUG)
        logger.debug(event['awslogs']['data'])
        compressed_payload = base64.b64decode(event['awslogs']['data'])
        uncompressed_payload = gzip.decompress(compressed_payload)
        log_payload = json.loads(uncompressed_payload)
        return log_payload
    else:
        logger.error("Missing 'awslogs' key or 'data' key in 'awslogs'")
        return None

def error_details(payload):
    error_msg = ""
    log_events = payload['logEvents']
    logger.debug(payload)
    log_group = payload['logGroup']
    log_stream = payload['logStream']
    lambda_func_name = log_group.split('/')
    logger.debug(f'LogGroup: {log_group}')
    logger.debug(f'LogStream: {log_stream}')
    logger.debug(f'Function name: {lambda_func_name[3]}')
    logger.debug(log_events)
    for log_event in log_events:
        error_msg += log_event['message']
    logger.debug('Message: %s' % error_msg.split("\n"))
    return log_group, log_stream, error_msg, lambda_func_name

def is_ssh_failed_attempt(log_message):
    # Adjust the regular expression based on your log format
    ssh_failed_pattern = re.compile(r'Failed password for .* from .* port \d+')
    return bool(ssh_failed_pattern.search(log_message))



def publish_message(log_group, log_stream, error_msg, lambda_func_name, ssh_failed_attempts):
    sns_arn = os.environ.get('snsARN')  # Getting the SNS Topic ARN passed in by the environment variables.
    sns_client = boto3.client('sns')
    try:
        message = (
            "\nLambda error summary\n\n"
            "##########################################################\n"
            f"# LogGroup Name:- {log_group}\n"
            f"# LogStream:- {log_stream}\n"
            "# Log Message:-\n"
            f"# \t\t{error_msg.split('\n')}\n"
            "##########################################################\n"
        )

        # Include SSH failed attempts in the message
        if ssh_failed_attempts:
            message += "\nSSH Failed Attempts:\n"
            for attempt in ssh_failed_attempts:
                message += f"# {attempt}\n"
                print(message)

        # Sending the notification...
        sns_client.publish(
            TargetArn=sns_arn,
            Subject=f'Execution error for Lambda - {lambda_func_name[3]}',
            Message=message
        )
    except ClientError as e:
        logger.error(f"An error occurred: {e}")

def lambda_handler(event, context):
    payload = log_payload(event)
    if payload:
        log_group, log_stream, error_message, lambda_name = error_details(payload)
        ssh_failed_attempts = [log_event['message'] for log_event in payload['logEvents'] if is_ssh_failed_attempt(log_event['message'])]
        publish_message(log_group, log_stream, error_message, lambda_name, ssh_failed_attempts)

