#!/usr/bin/env python3
import json
from aws_cdk import (
    aws_iam as iam,
    aws_events as events,
    aws_lambda as lambda_,
    aws_config as config,
    aws_events_targets as targets,
    aws_cloudtrail as trail,
    core,
)

SSH_RULE_NAME = "ssh-restricted"


class SshRestrictedStack(core.Stack):
    def __init__(self, app: core.App, id: str) -> None:
        super().__init__(app, id)

        # Create CloulTrail trail
        awsCloudTrail = trail.Trail(self, 'Trail')

        # Create role for the lambda function
        awsLambdaSecGroupRole = iam.Role(
            self, 'aws_lambda_security_group_role',
            role_name='lambda-security_group_role',
            assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ])

        # Add RunTask policy to Lambda role
        awsLambdaSecGroupRole.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            resources=["*"],
            actions=["ec2:RevokeSecurityGroupIngress", "config:GetComplianceDetailsByConfigRule", "sts:GetCallerIdentity", "ec2:DescribeSecurityGroups"]))

        # Create lambda function and pass it the above role
        with open("lambda.py", encoding="utf8") as fp:
            handler_code = fp.read()

        lambdaFn = lambda_.Function(
            self, "revoke-ssh-access",
            role=awsLambdaSecGroupRole,
            code=lambda_.InlineCode(handler_code),
            handler="index.lambda_handler",
            timeout=core.Duration.seconds(300),
            runtime=lambda_.Runtime.PYTHON_3_7,
        )

        # Add environment variable for lambda function
        lambdaFn.add_environment("SSH_RULE_NAME", SSH_RULE_NAME)

        # Create Config managed rule
        config.ManagedRule(
            self,
            "restricted-ssh",
            config_rule_name=SSH_RULE_NAME,
            identifier=config.ManagedRuleIdentifiers.EC2_SECURITY_GROUPS_INCOMING_SSH_DISABLED
        )

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
        rule = events.Rule(
            self,
            "Rule",
            description='rule that triggers a lambda function to revoke SSH public access directly after AWS Config NON COMFORM event',
            rule_name='revoke-access-ssh',
            event_pattern=events.EventPattern(
                detail=detail,
                source=["aws.config"]
            )
        )

        # Adding the lambda function as a target of the rule
        rule.add_target(targets.LambdaFunction(lambdaFn))


app = core.App()
SshRestrictedStack(app, "SshRestrictedStack")
app.synth()
