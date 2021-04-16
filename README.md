
# SSH-Restricted 

## SSH-Restricted deploys an SSH compliance rule with auto-remediation via AWS Lambda if SSH access is public.



* SSH-Auto-Restricted checks incoming SSH traffic configurations for security groups using [AWS Config rule](https://docs.aws.amazon.com/config/latest/developerguide/restricted-ssh.html).
* The rule is COMPLIANT when IP addresses of the incoming SSH traffic in the security groups are restricted (CIDR other than 0.0.0.0/0)
* This rule applies only to IPv4.
* If a security group is changed with SSH traffic CIDR equal to 0.0.0.0/0, the AWS Config rule becomes NON_COMPLIANT
* The NON_COMPLIANT event triggers an Eventbridge rule which triggers an AWS Lambda function that removes the SSH incoming traffic 

### Architecture diagram of the app.

![](arch.png)


## Deploying the App to AWS Cloud

### Create Python Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate
```

### Install Python-specific modules

```bash
pip install -r requirements.txt
```

### Create Cloudformation from CDK

```bash
cdk synth
```

### Deploy

```bash
cdk deploy
```

## Useful commands

 * `cdk ls`          list all stacks in the app
 * `cdk synth`       emits the synthesized CloudFormation template
 * `cdk deploy`      deploy this stack to your default AWS account/region
 * `cdk diff`        compare deployed stack with current state
 * `cdk docs`        open CDK documentation

Enjoy!
