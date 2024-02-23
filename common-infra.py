import boto3
import json
import re
import logging
import datetime
from datetime import datetime
from dateutil.relativedelta import relativedelta

ADMINEC2='i-0151c61904a892097'
ACCOUNTID='086558720570'
HOMEDIR='/home/ubuntu/'

# 로깅 설정
log_file = f"{HOMEDIR}{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}-delete_resource.log"
logger = logging.getLogger()
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(log_file)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
logger.addHandler(console_handler)

# formatter 설정 (옵션)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - Line %(lineno)d - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)
# 로깅 예시


def check_ec2_resource(resource_client, resource_name):
    try:
        response = resource_client()
        #logger.debug(f"resource_instance: {response}")

        current_date = datetime.now()
        for reservation in response['Reservations']:
            for resource_instance in reservation['Instances']:

                if ADMINEC2 == resource_instance['InstanceId']:
                    logger.info("This is the admin. Ec2")
                    continue

                tags = resource_instance['Tags']
                has_expiration_date = any(tag['Key']== 'ExpirationDate' for tag in tags)

                if any([has_expiration_date == False,'Tags' not in resource_instance]):
                    logger.info(f"No tags are written for the {resource_name}({resource_instance['InstanceId']}) instance.")
                    continue
                for tag in tags:
                    if tag['Key']== 'ExpirationDate':
                        expiration_date_str = tag['Value']
                        if re.match(r'^\d{4}-\d{2}$', expiration_date_str):
                            expiration_date = datetime.strptime(expiration_date_str, '%Y-%m')
                            if current_date >= expiration_date:
                                logger.info(f"Deleting {resource_name} instance: {resource_instance['ResourceId']}")
                                # Uncomment the following line to actually delete the resource
                                # resource_client.terminate_instances(InstanceIds=[resource_instance['ResourceId']])
                            else:
                                logger.info(f"The expiration date of the {resource_name}({resource_instance['InstanceId']}) resource is still valid. Expiration date: {expiration_date}")
                        else:
                            logger.info(f"The tag format of {resource_name}({resource_instance['InstanceId']}) is incorrect.")

    except Exception as e:
        logger.error(f"An error occurred while checking the resource: {str(e)}")


def check_rds_resource(resource_client, resource_name):
    try:
        response = resource_client()
        #logger.debug(f"rds resource_instance : {response}")

        current_date = datetime.now()
        for instance in response['DBInstances']:
            # Check if there are tags associated with the instance
            if len(instance['TagList']) == 0:
                logger.info(f"No tags found for RDS instance {instance['DBInstanceIdentifier']}")
                continue
            
            tags = instance['TagList']
            has_expiration_date = any(tag['Key']== 'ExpirationDate' for tag in tags)
            if any([has_expiration_date == False,len(instance['TagList']) == 0]):
                logger.info(f"No tags found for RDS instance {instance['DBInstanceIdentifier']}")
                continue
            
            
            for tag in tags:
                if tag['Key'] == 'ExpirationDate':
                    expiration_date_str = tag['Value']
                    if re.match(r'^\d{4}-\d{2}$', expiration_date_str):
                        expiration_date = datetime.strptime(expiration_date_str, '%Y-%m')
                        if current_date >= expiration_date :
                            logger.info(f"Deleting {resource_name} instance: {instance['DBInstanceIdentifier']}({expiration_date})")
                            # Uncomment the following line to actually delete the resource
                            # rds_client.delete_db_instance(DBInstanceIdentifier=instance['DBInstanceIdentifier'])
                        else:
                            logger.info(f"Expiration date for {resource_name} instance {instance['DBInstanceIdentifier']} has not been reached yet.")
                    else:
                        logger.error(f"ExpirationDate format is incorrect for RDS instance {instance['DBInstanceIdentifier']}.")
    except Exception as e:
        logger.error(f"An error check resource occurred: {str(e)}")


def check_es_resource(resource_client, resource_name):
    try:
        current_date = datetime.now()
        domain_list = resource_client.list_domain_names()
        for domain in domain_list['DomainNames'] :

            response = resource_client.list_tags(ARN=f"arn:aws:es:ap-northeast-2:{ACCOUNTID}:domain/" + domain['DomainName']) 
            
            tags = response['TagList']
            has_expiration_date = any(tag['Key']== 'ExpirationDate' for tag in tags)
            if any([has_expiration_date == False, len(tags) == 0]):
                logger.info(f"No tags found for RDS instance {instance['DBInstanceIdentifier']}")

                continue
            
            
            for tag in tags:
                if tag['Key'] == 'ExpirationDate':
                    expiration_date_str = tag['Value']
                    if re.match(r'^\d{4}-\d{2}$', expiration_date_str):
                        expiration_date = datetime.strptime(expiration_date_str, '%Y-%m')
                        if current_date >= expiration_date :
                            logger.info(f"Deleting {resource_name} instance: {instance['DBInstanceIdentifier']}")
                            # Uncomment the following line to actually delete the resource
                            # rds_client.delete_db_instance(DBInstanceIdentifier=instance['DBInstanceIdentifier'])
                        else:
                            logger.info(f"Expiration date for {resource_name} instance {instance['DBInstanceIdentifier']} has not been reached yet.")
                    else:
                        logger.error(f"ExpirationDate format is incorrect for RDS instance {instance['DBInstanceIdentifier']}.")
    except Exception as e:
        logger.error(f"An error check resource occurred: {str(e)}")

def check_eks_resource(resource_client, resource_name):
    try:
        current_date = datetime.now()
        cluster_list = resource_client.list_clusters()
        for cluster_name in cluster_list['clusters']:
            response = resource_client.describe_cluster(name=cluster_name)

            tags = response['cluster']['tags']
            expiration_date_str = tags['ExpirationDate'] if 'ExpirationDate' in tags else None
            if expiration_date_str == None:
                logger.info(f"No tags are written for the {resource_name}({cluster_name}) instance.")                
                continue
            else:
                if re.match(r'^\d{4}-\d{2}$', expiration_date_str):
                    expiration_date = datetime.strptime(expiration_date_str, '%Y-%m')
                    if current_date >= expiration_date:
                        logger.info(f"Deleting {resource_name} instance: {cluster_name}")
                        # Uncomment the following line to actually delete the resource
                        # resource_client.delete_cluster(clusterName=response['cluster']['name'], clusterName=cluster_name)
                    else:
                        logger.info(f"Expiration date for {resource_name} instance {cluster_name} has not been reached yet.")
                else:
                    logger.error(f"ExpirationDate format is incorrect for {resource_name} {cluster_name}.")
                    
            cluster_nodegroup_list = resource_client.list_nodegroups(
                clusterName= cluster_name,
                maxResults=100
                )
            
            for cluster_nodegroup_name in cluster_nodegroup_list['nodegroups']:
                response = resource_client.describe_nodegroup(
                    clusterName = cluster_name,
                    nodegroupName = cluster_nodegroup_name
                )
                tags = response['nodegroup']['tags']
                
                expiration_date_str = tags['ExpirationDate'] if 'ExpirationDate' in tags else None
                if expiration_date_str == None:
                    logger.info(f"No tags are written for the {resource_name}_NODEGROUP({cluster_nodegroup_name}) instance.")                
                    continue
                else:
                    if re.match(r'^\d{4}-\d{2}$', expiration_date_str):
                        expiration_date = datetime.strptime(expiration_date_str, '%Y-%m')
                        if current_date >= expiration_date:
                            logger.info(f"Deleting {resource_name}_NODEGROUP instance: {cluster_nodegroup_name}")
                            # Uncomment the following line to actually delete the resource
                            # resource_client.delete_cluster(clusterName=response['cluster']['name'], clusterName=cluster_name)
                        else:
                            logger.info(f"Expiration date for {resource_name}_NODEGROUP instance {cluster_nodegroup_name} has not been reached yet.")
                    else:
                        logger.error(f"ExpirationDate format is incorrect for EKS cluster {cluster_nodegroup_name}.")
            
    except Exception as e:
        logger.error(f"An error occurred while checking the resource: {str(e)}")



def lambda_handler(event, context):
    try:
        aws_access_key_id = 'AKIARIJ2NII5LNYXLVMP'
        aws_secret_access_key = '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'
        region_name = 'ap-northeast-2'
        

        ec2_client = boto3.client('ec2', 
                            aws_access_key_id=aws_access_key_id,
                            aws_secret_access_key=aws_secret_access_key,
                            region_name=region_name)
        
        # RDS 클라이언트 생성
        rds_client = boto3.client('rds',
                                aws_access_key_id=aws_access_key_id,
                                aws_secret_access_key=aws_secret_access_key,
                                region_name=region_name)

        # OpenSearch Service 클라이언트 생성
        opensearch_client = boto3.client('es',
                                        aws_access_key_id=aws_access_key_id,
                                        aws_secret_access_key=aws_secret_access_key,
                                        region_name=region_name)

        # Kafka 클라이언트 생성
        kafka_client = boto3.client('kafka',
                                    aws_access_key_id=aws_access_key_id,
                                    aws_secret_access_key=aws_secret_access_key,
                                    region_name=region_name)

        # SageMaker 클라이언트 생성
        sagemaker_client = boto3.client('sagemaker',
                                        aws_access_key_id=aws_access_key_id,
                                        aws_secret_access_key=aws_secret_access_key,
                                        region_name=region_name)

        # EKS 클라이언트 생성
        eks_client = boto3.client('eks',
                                aws_access_key_id=aws_access_key_id,
                                aws_secret_access_key=aws_secret_access_key,
                                region_name=region_name)

        # # ElastiCache 클라이언트 생성
        # elasticache_client = boto3.client('elasticache',
        #                                 aws_access_key_id=aws_access_key_id,
        #                                 aws_secret_access_key=aws_secret_access_key,
        #                                 region_name=region_name)

        # # ELB 클라이언트 생성
        # elb_client = boto3.client('elb',
        #                         aws_access_key_id=aws_access_key_id,
        #                         aws_secret_access_key=aws_secret_access_key,
        #                         region_name=region_name)

        # # VPC 클라이언트 생성
        # vpc_client = boto3.client('ec2',
        #                         aws_access_key_id=aws_access_key_id,
        #                         aws_secret_access_key=aws_secret_access_key,
        #                         region_name=region_name)

        # # S3 클라이언트 생성
        # s3_client = boto3.client('s3',
        #                         aws_access_key_id=aws_access_key_id,
        #                         aws_secret_access_key=aws_secret_access_key,
        #                         region_name=region_name)

        # # ECR 클라이언트 생성
        # ecr_client = boto3.client('ecr',
        #                         aws_access_key_id=aws_access_key_id,
        #                         aws_secret_access_key=aws_secret_access_key,
        #                         region_name=region_name)

        # # EFS 클라이언트 생성
        # efs_client = boto3.client('efs',
        #                         aws_access_key_id=aws_access_key_id,
        #                         aws_secret_access_key=aws_secret_access_key,
        #                         region_name=region_name)

        # # CloudWatch 클라이언트 생성
        # cloudwatch_client = boto3.client('cloudwatch',
        #                                 aws_access_key_id=aws_access_key_id,
        #                                 aws_secret_access_key=aws_secret_access_key,
        #                                 region_name=region_name)


        check_ec2_resource(ec2_client.describe_instances, 'EC2')
        check_rds_resource(rds_client.describe_db_instances, 'RDS')
        check_es_resource(opensearch_client, 'OpenSearch')
        check_eks_resource(eks_client,"EKS")

    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")

if __name__ == '__main__':
    lambda_handler("event", "handler")

