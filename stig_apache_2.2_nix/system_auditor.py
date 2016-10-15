#!/usr/bin/env python
import subprocess
import os


class SystemAuditor:

    """
    System auditor checks all system requirements outside of
    apache config documents to make sure the server is in compliance
    with Apache STIG requirements.
    """

    def __init__(self):
        pass

    def audit_system(self):
        self.clean_production_server()
        self.check_version()

    def clean_production_server(self):
        """
        Check SV-32933r1_rule: All web server documentation, sample code,
        example applications, and tutorials must be removed from a
        production web server.

        Finding ID: V-13621

        Query the SA to determine if all directories that contain samples and
        any scripts used to execute the samples have been removed from
        the server


        - If any sample files are found on the web server, this is a finding
        """
        self.has_documentation()
        self.has_sample_code()
        self.has_tutorials()

    def has_documentation(self):
        """
        Check the default installation location for apache documentation

        Currently just checks for the existance of /usr/share/doc/apache2
        """
        exists = print(os.path.isdir('/usr/share/doc/apache2'))
        exists = os.path.isdir('/usr/share/doc/apache2')
        empty = True
        if(exists):
            empty = not os.listdir('/usr/share/doc/apache2')

        if(exists and not empty):
            documented = True
        else:
            documented = False
        return documented

    def has_sample_code(self):
        pass

    def has_example_applications(self):
        pass

    def has_tutorials(self):
        pass

    def check_version(self):
        """Check SV-36441r2_rule: Web server software must be a vendor-supported
        version.


        Finding ID: V-2246

        - If the version of Apache is not at the following version or higher,
        this is a finding.
        Apache httpd server version 2.2 - Release 2.2.31 (July 2015)
        """
        pass


if __name__ == '__main__':
    auditor = SystemAuditor()
    auditor.audit_system()
