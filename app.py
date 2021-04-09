#!/usr/bin/env python3

from aws_cdk import core

from cdk_immutability.cdk_immutability_stack import CdkImmutabilityStack


app = core.App()
CdkImmutabilityStack(app, "cdk-immutability")

app.synth()
