#/usr/bin/python

DEFAULT = "/etc/apache2/apache2.conf"


from apache_parser import ApacheParser
from apache_config_auditor import ApacheConfigAuditor

class ApacheAuditor:
    def __init__(self):
        self.parser = ApacheParser()
        self.config_auditor = None
        self.directive_list = None 
    def audit(self):
        self.directive_list = self.parser.build_directives_list(DEFAULT)
        self.config_auditor = ApacheConfigAuditor(self.directive_list)
        self.config_auditor.audit_config()

if __name__ == '__main__':
    auditor = ApacheAuditor()
    auditor.audit()
