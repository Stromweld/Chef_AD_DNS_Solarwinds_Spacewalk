# Automatically Delete Terminated Instances in Chef Server with AWS Lambda
Using CloudWatch Events, when an instance is terminated a Lambda function is triggered that will remove the node from Chef server for you.  For this we'll use Lambda, CloudWatch Events, and AWS KMS.

**WARNING:  This code is meant as reference material only.  Using this code may cost you money.  Please be sure you understand your current usage and the costs associated with this reference code before launching in your AWS account.**

## Details
When an instance terminates, CloudWatch events will pass a JSON object containing the Instance ID to a Lambda function.  The JSON object does not contain any other identifying information of the instance, such as DNS name or Public IP Address.  Additionally, since the instance is now in a terminated state we cannot query any other identifying information about the instance.  This is important to understand because it effects how we must query for the node in Chef Server in order to delete it automatically.

The Lambda function then communicates with the Chef Server using a request hashed with a valid private key of a valid Chef Server user with appropriate permissions.  The Lambda expects an AWS KMS encrypted version of the private key which it will decrypt on the fly to sign all requests to the Chef Server.  The Lambda then makes a request to find a matching node in the Chef Server and finally a request to delete that node.

## USAGE
Please follow instructions found at https://aws.amazon.com/blogs/apn/automatically-delete-terminated-instances-in-chef-server-with-aws-lambda-and-cloudwatch-events/
or the original github repo found at https://github.com/awslabs/lambda-chef-node-cleanup/blob/master/lambda/main.py

I extended the original project to clean up other systems as well. I'm a new programmer learning as I go so the code may be a little dirty.

Chef uses pychef to remove nodes.
AD, DNS, and Solarwinds methods are using winrm and passing in a powershell script with commands to remove nodes.
Spacewalk uses the spacewalk api to remove nodes.
Chef Automate uses SSH to run remote "automate-ctl delete-visibility-node hostname" command.

Update the variables in the top of the main.py file with your environments settings.
Simply update the aws_ssh_key_pem.txt file with an ssh key file contents for a user that can login via ssh to chef automate server.
Using the encryption method explained in the blog you can add encrypted versions of the other credentials in the encrypted_*.txt files.
If you just want to get it to work and don't care about the encryption then modify the main.py variables and remove the decrypt portions.
