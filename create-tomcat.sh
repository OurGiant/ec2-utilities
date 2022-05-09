#!/bin/bash

sudo yum -y install amazon-cloudwatch-agent openssl 

sudo amazon-linux-extras install -y tomcat9
sudo yum -y install tomcat-native
sudo amazon-linux-extras install -y java-openjdk11
sudo yum -y update
sudo systemctl enable tomcat
sudo rm -f /etc/alternatives/java
sudo ln -s /usr/lib/jvm/java-11-openjdk-11.0.13.0.8-1.amzn2.0.3.x86_64/bin/java /etc/alternatives/java
sudo rm /etc/alternatives/jre
sudo ln -s /usr/lib/jvm/java-11-openjdk-11.0.13.0.8-1.amzn2.0.3.x86_64 /etc/alternatives/jre
sudo openssl req -x509 -newkey rsa:2048 -nodes -out /usr/share/tomcat/conf/cert.pem -keyout /usr/share/tomcat/conf/cert.key -days 365 -subj "/C=US/ST=Florida/L=Orlanod/O=OurGiant Technologies/OGTECH/CN=*.ourgiant.net"


AWS_AVAIL_ZONE=$(curl --silent  http://169.254.169.254/latest/meta-data/placement/availability-zone)
AWS_REGION=$(echo $AWS_AVAIL_ZONE | rev | cut -c2- | rev)
AWS_INSTANCE_ID=$(curl --silent http://169.254.169.254/latest/meta-data/instance-id)
ROOT_VOLUME_IDS=$(aws ec2 describe-instances --region $AWS_REGION --instance-id $AWS_INSTANCE_ID --output text --query Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId)
DEPTNAME=$(aws --region us-east-1 ec2 describe-tags --filters "Name=resource-id,Values=$AWS_INSTANCE_ID" --query 'Tags[?Key==`Department Name`].Value' --output text)
DEPTNUM=$(aws --region us-east-1 ec2 describe-tags --filters "Name=resource-id,Values=$AWS_INSTANCE_ID" --query 'Tags[?Key==`Department Number`].Value' --output text)
aws ec2 create-tags --resources $ROOT_VOLUME_IDS --region $AWS_REGION --tags Key='Department Number',Value="$DEPTNUM" Key='Department Name',Value="$DEPTNAME"
aws ssm send-command --document-name "CrowdStrikeAgentInstallAWSLinux" --document-version "1" --targets '[{"Key":"InstanceIds","Values":["$ROOT_VOLUME_IDS"]}]' --parameters '{}' --timeout-seconds 600 --max-concurrency "50" --max-errors "0" --region $AWS_REGION

