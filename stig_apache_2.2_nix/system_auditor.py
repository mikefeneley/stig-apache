#!/usr/bin/env python
import subprocess
import os
import glob
import sys
from subprocess import call

UBUNTU_SEP_TOKEN = "u"
MISSING_APACHE = "(none)"

REQUIRED_APACHE = "2.2.31"

VERSION_FILENAME = "version.txt"
SYSTEM_INFOFILE = "/proc/version"


class SystemAuditor:

    """
    System auditor checks all system requirements outside of
    apache config documents to make sure the server is in compliance
    with Apache STIG requirements.
    """

    def __init__(self):
        self.os = None
        self.version_sep_token = None

    def audit_system(self):
        self.get_os_info()
        self.is_supported()
        # self.is_clean_production_server()
        # self.is_supported()
        # self.user_access_restricted()

    def get_os_info(self):
        """ Finds which operating system is installed"""

        system_info = open(SYSTEM_INFOFILE, "r")
        line = system_info.readline()   
        os_name = line.split()[7]
        os_name = os_name[1:]
        self.os = os_name

        if(self.os == "Ubuntu"):
            self.version_sep_token = UBUNTU_SEP_TOKEN
        else:
            self.version_sep_token = None # Only using Ubuntu now

    def is_supported(self):
        """Check SV-36441r2_rule: Web server software must be a vendor-supported
        version.


        Finding ID: V-2246

        - If the version of Apache is not at the following version or higher,
        this is a finding.
        Apache httpd server version 2.2 - Release 2.2.31 (July 2015)
        CONCERNS: We know the operating system, apt-cache might not be installed.
                  May need to change approach depending upon the installed OS.
                  Ditto for checking documention, various config files, etc.
                  Also, currently only checking if the latest on apt-cache is 
                  installed, not if a version greater than or equal to required
        """

        if(self.os == "Ubuntu"):
            version_info = open(VERSION_FILENAME, "w")
            call(["apt-cache", "policy", "apache2"], stdout=version_info)
            version_info.close()
            version_info = open(VERSION_FILENAME, "r")

            installed = -2
                    
            is_installed = False
            is_latest = False
            supported = False

            for line in version_info:
                line_tokens = line.split()
                if line_tokens[0] == "Installed:":
                    installed_line = line_tokens[1]


            version_info.close()
            call(["rm", VERSION_FILENAME])

            """ Return error if apache is not installed on the system """
            if(installed_line == MISSING_APACHE):
                return 0
            
            installed = installed_line.split(UBUNTU_SEP_TOKEN)[0]
            meets_requirements = self.version_meets_requirements(installed)

            if(not meets_requirements):
                return 0
            else:
                return 1

        elif(self.os == "RedHatLinux"): # Todo
            pass

    def version_meets_requirements(self, installed_version):
        """ Check that the installed version is greater than or equal
        to 2.2.31.
        """

        components = installed_version.split('.')
        first = components[0]
        second = components[1]
        third = components[2]
        third = third.split('-')
        third = third[0]

        print(first, second, third)

        if(int(first) != 2):
            return 0
        if(int(second) != 2):
            return 0
        if(int(third) < 31):
            return 0
        return 1

    def is_clean_production_server(self):
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



    def user_access_restricted(self):
        """Check SV-36456r2_rule: Administrators must be the only users allowed
        access to the directory tree, the shell, or other operating system
        functions and utilities.


        Finding ID: V-2247

        Verify with the system administrator or the ISSO that all
        privileged accounts are mission essential and documented.

        Verify with the system administrator or the ISSO that all
        non-administrator access to shell scripts and operating system functions are mission essential and documented.


        - If undocumented privileged accounts are found, this is a finding.
        - If undocumented access to shell scripts or operating system functions is found, this is a finding.
        """

        pass




if __name__ == '__main__':
    auditor = SystemAuditor()
    auditor.audit_system()
