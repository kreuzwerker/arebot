import argparse
import boto3
import json
import os

parser = argparse.ArgumentParser(description='Saves all messages from an AWS SQS queue into a folder.')

parser.add_argument(
    '-q', '--queue', dest='queue', type=str, required=True,
    help='The name of the AWS SQS queue to save.')

parser.add_argument(
    '-a', '--account', dest='account', type=str,
    help='The AWS account ID whose queue is being saved.')

parser.add_argument(
    '-o', '--output', dest='output', type=str, default='queue-messages',
    help='The output folder for saved messages.')

parser.add_argument(
    '-r', '--region', dest='aws_region', type=str, required=True,
    help='The AWS region where the queue is located.')

parser.add_argument(
    '-d', '--delete', dest='delete', default=False, action='store_true',
    help='Whether or not to delete saved messages from the queue.')

parser.add_argument(
    '-v', '--visibility', dest='visibility', type=int, default=60,
    help='The message visibility timeout for saved messages.')

args = parser.parse_args()

if not os.path.exists(args.output):
    os.makedirs(args.output)

c = boto3.client('sqs', region_name=args.aws_region)

count = 0
while True:
    messages = c.receive_message(
            QueueUrl=args.queue,
            MaxNumberOfMessages=10,
            AttributeNames=['All'],
            VisibilityTimeout=args.visibility)
    if len(messages) == 0 or not messages.has_key("Messages"): break


    for msg in messages["Messages"]:
        print msg
        filename = os.path.join(args.output, msg["MessageId"])
        obj = { 'id': msg["MessageId"],
                'attributes': msg["Attributes"],
                'body': msg["Body"] }

        with open(filename, 'w') as f:
            json.dump(obj, f, indent=2)
            count += 1
            print 'Saved message to {}'.format(filename)
            if args.delete:
                obj.delete()


print '{} messages saved'.format(count)
