import boto3
import os

SSH_RULE_NAME = os.environ['SSH_RULE_NAME']


def lambda_handler(event, context):

    boto3.client('sts').get_caller_identity()['Account']
    config_client = boto3.client('config')

    ec2_client = boto3.client('ec2')

    non_compliant_detail = config_client.get_compliance_details_by_config_rule(
        ConfigRuleName=SSH_RULE_NAME,
        ComplianceTypes=['NON_COMPLIANT'],
        Limit=100
    )
    results = non_compliant_detail['EvaluationResults']
    if len(results) > 0:
        print('None compliant resources with ' + SSH_RULE_NAME)
        for sec_group in results:
            sec_group_id = sec_group['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
            rsp = ec2_client.describe_security_groups(GroupIds=[sec_group_id])
            for sg in rsp['SecurityGroups']:
                for ip in sg['IpPermissions']:
                    if 'FromPort' in ip and ip['FromPort'] == 22:
                        for cidr in ip['IpRanges']:
                            if cidr['CidrIp'] == '0.0.0.0/0':
                                print("Revoking public access for " + sec_group_id)
                                ec2_client.revoke_security_group_ingress(
                                    GroupId=sec_group_id, IpPermissions=[ip]
                                )
