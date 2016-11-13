#/usr/bin/python
from apache_parser import ApacheParser
from apache_config_auditor import ApacheConfigAuditor
from apache_system_auditor import ApacheSystemAuditor


DEFAULT_CONFIG = "/etc/apache2/apache2.conf"


class ApacheAuditor:

    def __init__(self):
        self.parser = ApacheParser()
        self.config_auditor = None
        self.directive_list = None

    def audit(self):
        """
        Entry fucntion to the auditor creates other auditing objects and uses
        them to audit componenets Apache configuration for STIG compliance.

        :returns: string -- filename of the log file
        """
        self.directive_list = self.parser.build_directives_list(DEFAULT_CONFIG)
        self.config_auditor = ApacheConfigAuditor(self.directive_list)
        self.system_auditor = ApacheSystemAuditor()
        files = []

        filename = self.config_auditor.audit()
        if filename != 0:
            files.append(filename)

        filename = self.config_auditor.audit()
        if filename != 0:
            files.append(filename)

        output = self.build_output(files=files)
        return output

    def build_output(self, files, filename="ApacheLog.txt"):
        """
        Concatenates all the log files in files list into single file
        with name filename.

        :returns: string -- filename of the log file
        """
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
