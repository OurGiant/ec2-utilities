import argparse
import os
import stat
import sys
import uuid
from pathlib import Path
import boto3
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(funcName)s %(levelname)s %(message)s')
logging.getLogger('boto').setLevel(logging.CRITICAL)

parser = argparse.ArgumentParser()
parser.add_argument("--awsprofile", help="SAML account used to perform these actions")
parser.add_argument("--awsregion", help="AWS Region in which to perform these actions")
parser.add_argument("--projectname", help="Project Name attached to this image")
parser.add_argument("--env", help="Environment label attached to these actions")
parser.add_argument("--deptnumber", help="Department number used for billing these resources")

if len(sys.argv) == 1:
    print("Arguments required")
    parser.print_help()
    exit(1)
else:
    args = parser.parse_args()
    awsprofile = args.awsprofile
    env = args.env
    awsregion = args.awsregion
    projectname = str(args.projectname).lower()
    deptnumber = args.deptnumber


def create_key_pair(client_ec2, keyname):
    logging.info('Create SSH Key Pair')
    keyname = keyname + '-' + str(uuid.uuid4()).lower()

    userHome = str(Path.home())
    if Path(userHome + "/.ssh/").is_dir() is False:
        Path.mkdir(userHome + "/.ssh/")
    temp_key_dir = userHome + "/.ssh/"
    keyfile_name = temp_key_dir + keyname + '.pem'
    try:
        newKeyPair = client_ec2.create_key_pair(
            KeyName=keyname,
            TagSpecifications=[
                {
                    'ResourceType': 'key-pair',
                    'Tags': [
                        {
                            'Key': 'Type',
                            'Value': 'Temporary'
                        },
                        {
                            'Key': 'ProjectName',
                            'Value': projectname
                        },
                        {
                            'Key': 'Department Number',
                            'Value': deptnumber
                        },
                    ]
                },
            ]
        )
    except client_ec2.exceptions.ClientError as e:
        logging.critical('Unable to create keypair:' + e)
        exit(2)

    logging.info('Download SSH Key Pair')
    KeyMaterial = newKeyPair['KeyMaterial']

    with open(keyfile_name, 'w') as keyfile:
        keyfile.write(KeyMaterial)

    keyfile.close()

    os.chmod(keyfile_name, stat.S_IRUSR | stat.S_IWUSR)

    return keyfile_name, keyname


def main():
    logging.info('Open AWS session for ' + awsprofile)
    session = boto3.Session(profile_name=awsprofile, region_name='us-east-1')
    ec2client = session.client('ec2')
    try:
        ec2_regions = ec2client.describe_regions()
    except ec2client.exceptions.ClientError:
        logging.critical('Expired SAML Token. Request a new SAML token for profile ' + awsprofile)
        sys.exit(2)
    available_regions = []
    for region in ec2_regions['Regions']:
        available_regions.append(region['RegionName'])
    if awsregion not in available_regions:
        logging.critical('invalid region: ' + awsregion)
        sys.exit(2)

    logging.info('Create keypair for ' + env + ' territory search dataloader')
    keyfile_name, keyname = create_key_pair(ec2client, keyname=projectname + "-" + env)
    logging.info('New key ' + keyname + ' was stored locally in ' + keyfile_name)


if __name__ == "__main__":
    main()
