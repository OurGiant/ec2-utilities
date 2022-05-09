#!/bin/bash

sudo yum -y install amazon-cloudwatch-agent openssl corretto8 nginx1

sudo systemctl enable nginx

sudo openssl req -x509 -newkey rsa:2048 -nodes -out /usr/share/tomcat/conf/cert.pem -keyout /usr/share/tomcat/conf/cert.key -days 365 -subj "/C=US/ST=Florida/L=Orlanod/O=OurGiant Technologies/OGTECH/CN=*.ourgiant.net"

sudo mkdir /opt/spring /var/log/spring && sudo chown spring /opt/spring /var/log/spring

sudo useradd spring

sudo yum -y update

cat <<EOF > /etc/systemd/system/vacations.service
[Unit]
Description= My App Spring Boot application
After=syslog.target

[Service]
User=deployer
ExecStart=/bin/java -jar /opt/spring/myapp.jar --spring.profiles.active=dev --server.port=8081 --logging.file.name=/var/log/spring/myapp.log --spring.redis.host=redis.host --app.rest.connect-timeout=3 --app.rest.read-timeout=5 SuccessExitStatus=143

[Install]
WantedBy=multi-user.target

EOF

systemctl enable vacations.service

cat <<EOF > /etc/nginx/nginx.conf
user  nginx;
worker_processes  10;
worker_rlimit_nofile 30000;

error_log  /var/log/nginx/error.log;

pid        /var/run/nginx.pid;


events {
	worker_connections  1024;
}


http {
	default_type  application/octet-stream;

	server_tokens off;

  log_format upstrm_cloudwatch escape=json
    '{'
      '"time_local":"\$time_local",'
      '"remote_addr":"\$remote_addr",'
      '"request_method":"\$request_method",'
      '"request_uri":"\$request_uri",'
      '"query_string":"\$query_string",'
      '"server_protocol":"\$server_protocol",'
      '"status":"\$status",'
      '"body_bytes_sent":"\$body_bytes_sent",'
      '"request_time":"\$request_time",'
      '"http_referrer":"\$http_referer",'
      '"http_user_agent":"\$http_user_agent",'
      '"ssl_protocol":"\$ssl_protocol",'
      '"ssl_cipher":"\$ssl_cipher",'
      '"http_x_forwarded_for":"\$http_x_forwarded_for",'
      '"upstream_response_time":"\$upstream_response_time",'
      '"body":"\$request_body",'
      '"dynatrace_cookie":"\$cookie_rxVisitor"'
    '}';


	limit_req_zone  \$binary_remote_addr zone=one:10m rate=200r/s;

	sendfile            on;
	tcp_nopush          on;
	tcp_nodelay         on;
	keepalive_timeout   65;
	types_hash_max_size 2048;


	error_page 403 = 404;

	gzip on;
	gzip_disable "msie6";

	gzip_comp_level 6;
	gzip_min_length 1100;
	gzip_buffers 16 8k;
	gzip_proxied any;
	gzip_types
	text/plain
	text/css
	text/js
	text/xml
	text/javascript
	application/javascript
	application/x-javascript
	application/xml
	application/xml+rss
	application/json;

	upstream myapp {
		server 127.0.0.1:8081;
	}

	server {
        listen 443 ssl;
        server_name  *.ourgiant.net *.elb.amazonaws.com ;

		access_log /var/log/nginx/access.log upstrm_cloudwatch;
		error_log /var/log/nginx/error.log ;

		ssl_certificate /etc/pki/tls/certs/cert.pem;
		ssl_certificate_key     /etc/pki/tls/private/cert.key;
		ssl_protocols TLSv1.2;
		ssl_prefer_server_ciphers on;
		ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
		ssl_ecdh_curve secp384r1;
		ssl_session_cache shared:SSL:10m;
		ssl_session_tickets off;
		ssl_session_timeout 5m;
		ssl_buffer_size 1400;

		location / {
			proxy_pass http://myapp\$request_uri;
			proxy_set_header Host            \$host;
			proxy_set_header X-Forwarded-For \$remote_addr;
		}

		if (\$request_method !~ ^(GET|HEAD|POST|PUT|DELETE|OPTIONS)$) {
			return 405;
		}
	}

}
EOF



AWS_AVAIL_ZONE=$(curl --silent  http://169.254.169.254/latest/meta-data/placement/availability-zone)
AWS_REGION=$(echo $AWS_AVAIL_ZONE | rev | cut -c2- | rev)
AWS_INSTANCE_ID=$(curl --silent http://169.254.169.254/latest/meta-data/instance-id)
ROOT_VOLUME_IDS=$(aws ec2 describe-instances --region $AWS_REGION --instance-id $AWS_INSTANCE_ID --output text --query Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId)
DEPTNAME=$(aws --region us-east-1 ec2 describe-tags --filters "Name=resource-id,Values=$AWS_INSTANCE_ID" --query 'Tags[?Key==`Department Name`].Value' --output text)
DEPTNUM=$(aws --region us-east-1 ec2 describe-tags --filters "Name=resource-id,Values=$AWS_INSTANCE_ID" --query 'Tags[?Key==`Department Number`].Value' --output text)
aws ec2 create-tags --resources $ROOT_VOLUME_IDS --region $AWS_REGION --tags Key='Department Number',Value="$DEPTNUM" Key='Department Name',Value="$DEPTNAME"
aws ssm send-command --document-name "CrowdStrikeAgentInstallAWSLinux" --document-version "1" --targets '[{"Key":"InstanceIds","Values":["$ROOT_VOLUME_IDS"]}]' --parameters '{}' --timeout-seconds 600 --max-concurrency "50" --max-errors "0" --region $AWS_REGION

