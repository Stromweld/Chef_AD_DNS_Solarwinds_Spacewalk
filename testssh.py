import paramiko

hostname = 'chef-automate-zddqq0w8qotvayto.us-west-2.opsworks-cm.io'
sshuser = 'ec2-user'
sshkey = 'aws_ssh_key_pem.txt'

ssh = paramiko.SSHClient()

ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

ssh.connect(hostname, username=sshuser, key_filename=sshkey)

stdin, stdout, stderr = ssh.exec_command('automate-ctl delete-visibility-node somehostname')
print stdout.readlines()
ssh.close()
