# AreBOT
AreBOT is an automatic and highly configurable tool to monitor your Amazon Web Services (AWS) cloud environments for resource compliance violations. Any detected violation can be reported to the specified set of recipients (e.g., administrators), and, in some cases, automatically corrected. The goal of AreBOT is to simplify the design and enforcement of compliance policies in complex AWS cloud infrastructures - possibly multi-region/account.

AreBOT supports both real-time and scheduled resource compliance checking. The AWS resources currently supported are Elastic Compute Cloud (EC2) Instances, Security Groups, Elastic Block Store Volumes and Snapshots. Support for Simple Storage Service Buckets is also on the way.

Using AreBOT, you can define complex compliance policies using a simple and flexible configuration language. More in details, a compliance policy defines the set of rules imposed on a resource's configuration setting (e.g., tag policies, security policies such as access control and encryption requirements), the set of actions to take in case of compliance violation (e.g., email notification or modification of the resource state), and a set of trigger rules to schedule periodic checks. A future guide will cover the configuration file in depth but, for now, please rely on the commented configuration file `arebot.cfg`.

The AreBOT client is developed in Go, and uses the AWS SDK for Go to interact with the AWS services deployed on the AWS account to monitor.

# Links
- "The Quest for Cloud Compliance - Challenges and Available Tools" [link#1]
- "Cloud Compliance made Simple: Meet AreBOT" [link#2]
- "Cloud Compliance using AreBOT: Designing Complex Compliance Policies"" [link#3]

# Quick Install

### Prerequisites
To enable AreBOT to monitor an AWS cloud environment, you need to perform some setup steps on the environment first. You can use the Amazon CloudFormation templates in the `environment/` folder as a reference for this process. In particular, you will need to configure the AWS auditing service CloudTrail to track resource activities, and to send this information to AreBOT as Amazon CloudWatch Events by using an Amazon SQS message queue.

### Dependencies
GoLang dependencies are managed with `glide`. To install those run the following command:

```
$ glide install
```

This will create a `vendor` folder as part of the source repository.

### Build
Simply run `make clean build` to compile the sources as an OSX binary. There are targets for Linux (`build-linux`) and Windows as well. Consult the `Makefile` for further information.

### Run AreBOT
`$ make run` starts AreBOT using the config file that comes along with the code. Feel free to modify the run command and config to your needs. In particular, be sure to
