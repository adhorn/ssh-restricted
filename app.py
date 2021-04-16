#!/usr/bin/env python3
import json
from aws_cdk import (
    aws_iam as iam,
    aws_events as events,
    aws_lambda as lambda_,
    aws_config as config,
    aws_events_targets as targets,
    aws_cloudtrail as trail,
    aws_s3 as s3,
    core,
)


class SshRestrictedStack(core.Stack):
    def __init__(self, app: core.App, id: str) -> None:
        super().__init__(app, id)

        # Setting up a role to represent config service principal
        aws_role = iam.Role(
            self,
            'ConfigRole',
            assumed_by=iam.ServicePrincipal('config.amazonaws.com')
        )

        # Adding a managed policy to the above role
        aws_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSConfigRole"))

        # Setting up ConfigurationRecorder for AWS Config
        aws_config_recorder = config.CfnConfigurationRecorder(
            self,
            'ConfigRecorder',
            role_arn=aws_role.role_arn,
            recording_group={"allSupported": True}
        )

        # Setting up the S3 bucket for Config to deliver the changes
        aws_config_bucket = s3.Bucket(self, 'ConfigBucket')

        # Adding policies to the S3 bucket
        aws_config_bucket.add_to_resource_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            principals=[aws_role],
            resources=[aws_config_bucket.bucket_arn],
            actions=["s3:GetBucketAcl", "s3:ListBucket"]
        ))

        cst_resource = 'AWSLogs/' + core.Stack.of(self).account + '/Config/*'

        aws_config_bucket.add_to_resource_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            principals=[aws_role],
            resources=[aws_config_bucket.arn_for_objects(cst_resource)],
            actions=["s3:PutObject"],
            conditions={"StringEquals": {
                "s3:x-amz-acl": "bucket-owner-full-control"}}
        ))

        # Creating the deliverchannel for Config
        config.CfnDeliveryChannel(
            self,
            'ConfigDeliveryChannel',
            s3_bucket_name=aws_config_bucket.bucket_name
        )

        # Create CloulTrail trail
        trail.Trail(self, 'Trail')

        # Create Config managed rule
        aws_config_managed_rule = config.ManagedRule(
            self,
            "restricted-ssh",
            identifier=config.ManagedRuleIdentifiers.EC2_SECURITY_GROUPS_INCOMING_SSH_DISABLED
        )

        # You cant create a rule if recorder is not enabled
        aws_config_managed_rule.node.add_dependency(aws_config_recorder)

        # Event pattern triggered by change in the AWS Config compliance rule
        dtl = """{
                "requestParameters": {
                    "evaluations": {
                        "complianceType": [
                        "NON_COMPLIANT"
                        ]
                }
                },
                "additionalEventData": {
                    "managedRuleIdentifier": [
                        "INCOMING_SSH_DISABLED"
                    ]
                }
            }"""
        # detail needs to be a JSON object
        detail = json.loads(dtl)

        # Create an eventbridge rule to be triggered by AWS Config
        aws_event_rule = events.Rule(
            self,
            "Rule",
            description='rule that triggers a lambda function to revoke SSH public access directly after AWS Config NON COMFORM event',
            event_pattern=events.EventPattern(
                detail=detail,
                source=["aws.config"]
            )
        )

        # Create role for the lambda function
        aws_lambda_se_group_role = iam.Role(
            self,
            'aws_lambda_security_group_role',
            assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ])

        # Add policy to Lambda role
        aws_lambda_se_group_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=["*"],
            actions=["ec2:RevokeSecurityGroupIngress", "config:GetComplianceDetailsByConfigRule", "sts:GetCallerIdentity", "ec2:DescribeSecurityGroups"]))

        # Create lambda function and pass it the above role
        with open("lambda.py", encoding="utf8") as fp:
            handler_code = fp.read()

        aws_lambda_fn = lambda_.Function(
            self, "revoke-ssh-access",
            role=aws_lambda_se_group_role,
            code=lambda_.InlineCode(handler_code),
            handler="index.lambda_handler",
            timeout=core.Duration.seconds(300),
            runtime=lambda_.Runtime.PYTHON_3_7,
        )

        # Add environment variable for lambda function
        aws_lambda_fn.add_environment("SSH_RULE_NAME", aws_config_managed_rule.config_rule_name)

        # Adding the lambda function as a target of the rule
        aws_event_rule.add_target(targets.LambdaFunction(aws_lambda_fn))


app = core.App()
SshRestrictedStack(app, "SshRestrictedStack")
app.synth()
