import re

class EC2Lib(object):
    def __init__(self, aws_manager):
        self.aws = aws_manager
        self.ec2 = aws_manager.ec2_client()

    def process_ssh_host_arg(self, host):

        # instance ID
        if re.search(r'^i-[a-fA-F0-9]+$', host):
            raise TODO
            self.ec2.describe_instances()

        # IP address
        if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
            return 'ip-address'

        # else Name tag
        return 'name-tag'
