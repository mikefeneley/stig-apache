#/usr/bin/python

DEFAULT = "/etc/apache2/apache2.conf"

from apache_parser import ApacheParser
from apache_config_auditor import ApacheConfigAuditor
from apache_system_auditor import ApacheSystemAuditor

class ApacheAuditor:
    def __init__(self):
        self.parser = ApacheParser()
        self.config_auditor = None
        self.directive_list = None 
    def audit(self):
        self.directive_list = self.parser.build_directives_list(DEFAULT)
        self.config_auditor = ApacheConfigAuditor(self.directive_list)
        self.system_auditor = ApacheSystemAuditor()
        files = []
        filename = self.config_auditor.audit()
        files.append(filename)
        filename = self.config_auditor.audit()
        files.append(filename)


        output = self.build_output(files=files)
        return output

    def build_output(self, files, filename="ApacheLog.txt"):
        out_log = open(filename, 'w')

        for file in files:
            in_log = open(file, 'r')

            for line in in_log:
                out_log.write(line)
            in_log.close()

        out_log.close()
        return filename


if __name__ == '__main__':
    auditor = ApacheAuditor()
    auditor.audit()
