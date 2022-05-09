import argparse
import datetime
import json
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
parser.add_argument("--subnetid", help="subnet id used to launch this image")
parser.add_argument("--vpcid", help="subnet id used to launch this image")
parser.add_argument("--env", help="Environment label attached to these actions")
parser.add_argument("--deptnumber", help="Department number used for billing these resources")
parser.add_argument("--userdata", help="bash script to be run when the instance starts")
parser.add_argument("--interactive", action='store_true',
                    help="stop the script to interact with the instance after it starts and runs userdata")
parser.add_argument("--taggingfile", help="file containing mandatory tags")

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
    subnetid = args.subnetid
    vpcid = args.vpcid
    deptnumber = args.deptnumber
    userdata = args.userdata
    tagging_file = args.taggingfile
if args.interactive:
    interactive = True
else:
    interactive = False

this_now = datetime.datetime.utcnow()
this_year = this_now.strftime('%Y')
this_month = this_now.strftime('%m')
this_day = this_now.strftime('%d')
image_version = this_now.strftime('%Y%m%d%H%M%S')


def get_required_tagging(deptnum, enviro, projnm):
    tags = [
        {
            'Key': 'Department Name',
            'Value': deptnum
        },
        {
            'Key': 'Department Number',
            'Value': deptnum
        },
        {
            'Key': 'map-migrated',
            'Value': 'd-server-024arrfhwpuh1t'
        },
        {
            'Key': 'DataClassification',
            'Value': 'Internal'
        },
        {
            'Key': 'ProjectName',
            'Value': projnm
        },
        {
            'Key': 'Club',
            'Value': '000'
        },
        {
            'Key': 'Environment',
            'Value': enviro
        }
    ]

    return tags


def create_key_pair(client_ec2, keyname):
    logging.info('Create SSH Key Pair')
    keyname = keyname + '-' + str(uuid.uuid4()).lower()

    user_ssh_dir = Path(str(Path.home()) + "/.ssh/")
    if user_ssh_dir.is_dir() is False:
        user_ssh_dir.mkdir()
    temp_key_dir = str(user_ssh_dir)
    keyfile_name = temp_key_dir + keyname + '.pem'
    req_tags = get_required_tagging(deptnumber, env, projectname)
    req_tags.append({
        'Key': 'Type',
        'Value': 'Temporary'
    })

    try:
        newKeyPair = client_ec2.create_key_pair(
            KeyName=keyname,
            TagSpecifications=[
                {
                    'ResourceType': 'key-pair',
                    'Tags': req_tags
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


def get_latest_amzn2_ami(client_ec2):
    logging.info('Find the latest Amazon Linux 2 x86_64 HVM ebs Image')
    images = client_ec2.describe_images(
        ExecutableUsers=[
            'all',
        ],
        Filters=[
            {
                'Name': 'architecture',
                'Values': [
                    'x86_64',
                ]
            },
            {
                'Name': 'name',
                'Values': [
                    'amzn2-ami-hvm-2.0.' + this_year + '*ebs',
                ]
            },
            {
                'Name': 'is-public',
                'Values': [
                    'true',
                ]
            },
        ],
        IncludeDeprecated=False,
        DryRun=False
    )

    # The latest image will always be first. This is shoddy programming, and dangerous, but I need this now and don't want to loop through the names in this pass.
    latest_image_name = images['Images'][0]['Name']
    latest_image_id = images['Images'][0]['ImageId']
    logging.info('Lastest Image Name:' + latest_image_name)
    return latest_image_name, latest_image_id


def create_temporary_securitygroup(client_ec2, resource_ec2):
    group_name = 'temp-image-creator-' + projectname + '-' + awsregion

    logging.info('Creating security group:' + group_name)
    req_tags = get_required_tagging(deptnumber, env, projectname)
    req_tags.append({
        'Key': 'Type',
        'Value': 'Temporary'
    })
    try:
        create_group = client_ec2.create_security_group(
            Description='Temporary security group used to allow outbound access for image creation process',
            GroupName=group_name,
            VpcId=vpcid,
            TagSpecifications=[
                {
                    'ResourceType': 'security-group',
                    'Tags': req_tags
                },
            ],
            DryRun=False
        )
        temp_group_id = str(create_group['GroupId'])

    except client_ec2.exceptions.ClientError:
        logging.critical('This security group: ' + group_name + ' already exists in vpc: ' + vpcid)
        r_vpc = resource_ec2.Vpc(vpcid)
        sec_groups = r_vpc.security_groups.all()

        for sec_group in sec_groups:
            if sec_group.group_name == group_name:
                temp_group_id = sec_group.group_id

    logging.info('clean up any existing rules in:' + temp_group_id)
    default_sg_rules = client_ec2.describe_security_group_rules(
        Filters=[{'Name': 'group-id', 'Values': [temp_group_id]}], MaxResults=5)
    for rule in default_sg_rules['SecurityGroupRules']:
        target_rule = rule['SecurityGroupRuleId']
        logging.info('delete rule:' + target_rule)
        client_ec2.revoke_security_group_egress(
            GroupId=temp_group_id,
            SecurityGroupRuleIds=[
                target_rule,
            ]
        )

    logging.info('add egress to 443 rule to security group:' + temp_group_id)
    client_ec2.authorize_security_group_egress(
        DryRun=False,
        GroupId=temp_group_id,
        IpPermissions=[
            {
                'FromPort': 443,
                'IpProtocol': 'TCP',
                'IpRanges': [
                    {
                        'CidrIp': '0.0.0.0/0',
                        'Description': 'All Hosts'
                    },
                ],
                'ToPort': 443,
            },
        ],
        TagSpecifications=[
            {
                'ResourceType': 'security-group-rule',
                'Tags': [
                    {
                        'Key': 'ProjectName',
                        'Value': projectname
                    },
                ]
            },
        ]
    )

    return temp_group_id


def create_ssm_role(client_iam):
    prexisting_role = False
    rolename = projectname + '-image-creator-' + awsregion
    logging.info('Create role ' + str(rolename) + ' for instance')
    smm_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "ec2.amazonaws.com"
                    ]
                },
                "Action": [
                    "sts:AssumeRole"
                ]
            }
        ]
    }
    req_tags = get_required_tagging(deptnumber, env, projectname)
    req_tags.append({
        'Key': 'Type',
        'Value': 'Temporary'
    })
    try:
        create_role = client_iam.create_role(
            Path='/',
            RoleName=rolename,
            AssumeRolePolicyDocument=json.dumps(smm_role_policy),
            Description='Role used to connect to instance to aid in image creation',
            Tags=req_tags
        )

    except client_iam.exceptions.MalformedPolicyDocumentException:
        logging.critical('Your policy is malformed. Please evaluate and rerun')
        sys.exit(2)
    except client_iam.exceptions.EntityAlreadyExistsException:
        logging.info('This role already exists')
        prexisting_role = True
        create_role = client_iam.get_role(
            RoleName=rolename
        )

    role_name = create_role['Role']['RoleName']

    if prexisting_role is False:
        logging.info('Attach SSM policies to role ' + str(rolename))
        client_iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
        )

        client_iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn='arn:aws:iam::aws:policy/AmazonSSMFullAccess'
        )

    return role_name


def create_temporary_instance_profile(client_iam, rolename):
    prexisting_profile = False
    profile_name = projectname + '-temp-profile'
    logging.info('Create Instance Profile:' + profile_name)
    req_tags = get_required_tagging(deptnumber, env, projectname)
    req_tags.append({
        'Key': 'Type',
        'Value': 'Temporary'
    })
    try:
        create_ip = client_iam.create_instance_profile(
            InstanceProfileName=profile_name,
            Path='/',
            Tags=req_tags
        )
    except client_iam.exceptions.EntityAlreadyExistsException:
        logging.warning(f'There is already an Instance Profile with this name.')
        prexisting_profile = True
        create_ip = client_iam.get_instance_profile(
            InstanceProfileName=profile_name
        )

    if prexisting_profile is False:
        # https://forums.aws.amazon.com/thread.jspa?messageID=593651
        # AWS::IAM::InstanceProfile resources always take exactly 2 minutes to create
        waiter = client_iam.get_waiter('instance_profile_exists')
        waiter.wait(
            InstanceProfileName=profile_name,
            WaiterConfig={
                'Delay': 10,
                'MaxAttempts': 13
            }
        )

    profilearn = create_ip['InstanceProfile']['Arn']
    profilename = create_ip['InstanceProfile']['InstanceProfileName']
    profileid = create_ip['InstanceProfile']['InstanceProfileId']

    if prexisting_profile is False:
        client_iam.add_role_to_instance_profile(
            InstanceProfileName=profilename,
            RoleName=rolename
        )

    return profilearn, profilename, profileid


def read_userdata_fromscript(scriptfile):
    logging.info('Read user data script from :' + scriptfile)

    with open(scriptfile, 'r') as script:
        script_lines = script.readlines()
    script.close()
    script = ''.join(script_lines)
    user_data = script.encode('utf-8')

    return user_data


def launch_instance(client_ec2, resource_ec2, ami, ec2key, secgrp, profilearn, init_script):
    logging.info('Launch EC2 Instance')

    INSTANCE_TYPE = 't2.micro'
    hostname = ec2key
    req_tags = get_required_tagging(deptnumber, env, projectname)
    req_tags.append({
        'Key': 'Type',
        'Value': 'Temporary'
    })
    req_tags.append({
        'Key': 'Name',
        'Value': hostname
    })
    try:
        instance = client_ec2.run_instances(
            BlockDeviceMappings=[
                {
                    'DeviceName': '/dev/xvda',
                    'Ebs': {
                        'DeleteOnTermination': True,
                        'VolumeSize': 15,
                        'VolumeType': 'gp3',
                        'Encrypted': True
                    },
                },
            ],
            SubnetId=subnetid,
            ImageId=ami,
            KeyName=ec2key,
            InstanceType=INSTANCE_TYPE,
            UserData=init_script,
            MinCount=1,
            MaxCount=1,
            SecurityGroupIds=[
                secgrp,
            ],
            Monitoring={
                'Enabled': False
            },
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': req_tags
                },
            ],
        )

        instance_id = instance['Instances'][0]['InstanceId']
        logging.info('Waiting for running state')
        waiter = resource_ec2.meta.client.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])
        logging.info('Waiting for status ok')
        waiter = resource_ec2.meta.client.get_waiter('instance_status_ok')
        waiter.wait(InstanceIds=[instance_id])
    except client_ec2.exceptions.ClientError as e:
        logging.critical('Unable to create instance: ' + str(e))
        instance_id = None

    if interactive is True:
        if interactive is True:
            logging.info('Launching instance with IamProfileArn: ' + profilearn)
        logging.info('Attaching profile ' + profilearn + ' to instance:' + instance_id)
        client_ec2.associate_iam_instance_profile(
            IamInstanceProfile={
                'Arn': profilearn
            },
            InstanceId=instance_id
        )
        client_ec2.reboot_instances(
            InstanceIds=[
                instance_id,
            ],
            DryRun=False
        )
    describe_instance = client_ec2.describe_instances(InstanceIds=[instance_id])
    try:
        instance_volume_id = describe_instance['Reservations'][0]['Instances'][0]['BlockDeviceMappings'][0]['Ebs'][
            'VolumeId']
        tag_resource(client_ec2, instance_volume_id)
    except:
        logging.critical('Unable to tag the instance volume')

    return instance_id


def create_application_image(client_ec2, resource_ec2, ec2id):
    logging.info('Create AMI from EC2 instance :' + ec2id)
    image_name = projectname + '-v' + image_version
    req_tags = get_required_tagging(deptnumber, env, projectname)
    req_tags.append({'Key': 'Name', 'Value': image_name})
    create_image = client_ec2.create_image(
        BlockDeviceMappings=[
            {
                'DeviceName': '/dev/xvda',
                'Ebs': {
                    'Encrypted': True
                },
            },
        ],
        Description='Image created for ' + projectname + ' version ' + image_version,
        DryRun=False,
        InstanceId=ec2id,
        Name=image_name,
        NoReboot=True,
        TagSpecifications=[
            {
                'ResourceType': 'image',
                'Tags': req_tags
            }
        ]
    )

    image_id = create_image['ImageId']

    logging.info('Waiting for image to Exist')
    waiter = resource_ec2.meta.client.get_waiter('image_exists')
    waiter.wait(ImageIds=[image_id])

    logging.info('Waiting for image to be Available')
    waiter = resource_ec2.meta.client.get_waiter('image_available')
    waiter.wait(ImageIds=[image_id])

    images = client_ec2.describe_images(ImageIds=[image_id])
    image_snapshot = images['Images'][0]['BlockDeviceMappings'][0]['Ebs']['SnapshotId']
    tag_resource(client_ec2, image_snapshot)
    return image_id


def destroy_temp_instance(client_ec2, resource_ec2, ec2id):
    logging.info('Stop EC2 instance :' + ec2id)

    client_ec2.stop_instances(
        InstanceIds=[
            ec2id,
        ],
        Hibernate=False,
        DryRun=False,
        Force=True
    )

    logging.info('Waiting for instance to stop')
    waiter = resource_ec2.meta.client.get_waiter('instance_stopped')
    waiter.wait(InstanceIds=[ec2id])

    logging.info('Terminate EC2 instance :' + ec2id)

    client_ec2.terminate_instances(
        InstanceIds=[
            ec2id,
        ],
        DryRun=False
    )

    logging.info('Waiting for instance to terminate')
    waiter = resource_ec2.meta.client.get_waiter('instance_terminated')
    waiter.wait(InstanceIds=[ec2id])


def clean_up(client_ec2, secgrpid, keyn, keyf):
    logging.info('Clean up temporary resources used to create AMI')

    logging.info('Delete Security Group:' + secgrpid)
    try:
        client_ec2.delete_security_group(
            GroupId=secgrpid,
            DryRun=False
        )
    except:
        logging.critical("Unable to delete security group")
        pass
    logging.info('Delete EC2 KeyPair:' + keyn)
    try:
        client_ec2.delete_key_pair(
            KeyName=keyn
        )
        os.remove(keyf)
    except:
        logging.critical("Unable to delete ec2 keypair")
        pass


def clean_up_interactive(client_iam, profilename, role_name):
    logging.info('Clean up temporary resources used to create interactive instance')

    logging.info('Detach policies from the role:' + role_name)
    client_iam.detach_role_policy(
        RoleName=role_name,
        PolicyArn='arn:aws:iam::aws:policy/AmazonSSMFullAccess'
    )

    client_iam.detach_role_policy(
        RoleName=role_name,
        PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
    )

    logging.info('Remove role ' + role_name + ' from instance profile ' + profilename)
    client_iam.remove_role_from_instance_profile(
        InstanceProfileName=profilename,
        RoleName=role_name
    )

    logging.info('Delete the role: ' + role_name)
    try:
        client_iam.delete_role(
            RoleName=role_name
        )
    except client_iam.exceptions.DeleteConflictException as e:
        logging.critical('Unable to delete role:' + str(e))

    logging.info('Delete Instance Profile:' + profilename)
    try:
        client_iam.delete_instance_profile(
            InstanceProfileName=profilename
        )
    except client_iam.exceptions.NoSuchEntityException:
        logging.critical("Unable to delete instance profile")
        pass
    except client_iam.exceptions.DeleteConflictException:
        logging.critical('Roles still present in the Profile')
    pass


def tag_resource(ec2client, resource_id):
    logging.info('Tagging Resource: ' + resource_id)
    req_tags = get_required_tagging(deptnumber, env, projectname)
    ec2client.create_tags(Resources=[resource_id], Tags=req_tags)
    pass


def main():
    logging.info('Open AWS session for ' + awsprofile)
    # noinspection PyUnresolvedReferences
    session = boto3.Session(profile_name=awsprofile, region_name='us-east-1')
    ec2client = session.client('ec2')
    ec2resource = session.resource('ec2')
    iamclient = session.client('iam')
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

    app_image_id = None
    profilearn = None
    logging.info('Start building resources')
    keyfile_name, keyname = create_key_pair(ec2client, keyname=projectname + "-" + env)
    latest_ami_name, latest_ami_id = get_latest_amzn2_ami(ec2client)
    secgrp_id = create_temporary_securitygroup(ec2client, ec2resource)
    if interactive is True:
        rolenm = create_ssm_role(iamclient)
        profilearn, profilenm, profileid = create_temporary_instance_profile(iamclient, rolenm)
    init_script = read_userdata_fromscript(userdata)
    instance_id = launch_instance(ec2client, ec2resource, latest_ami_id, keyname, secgrp_id, profilearn, init_script)
    if interactive is True:
        print(
            f'Your instnace {instance_id} in ready for interaction.\nWhen you have completed all nessasary steps, return to this utility.')
        input("Type 'go' to continue: ")
    if instance_id is not None:
        app_image_id = create_application_image(ec2client, ec2resource, instance_id)
        destroy_temp_instance(ec2client, ec2resource, instance_id)
        if interactive is True:
            clean_up_interactive(iamclient, profilenm, rolenm)

    clean_up(ec2client, secgrp_id, keyname, keyfile_name)

    if app_image_id is not None:
        logging.info(f'Image ID created for {projectname} is {app_image_id}')
    else:
        logging.critical('Unable to create a custom AMI. Please investigate any error messages')


if __name__ == "__main__":
    main()
