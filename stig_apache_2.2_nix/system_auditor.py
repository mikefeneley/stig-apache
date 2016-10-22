#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess
import os
import glob
import sys
from subprocess import call
from stat import *

UBUNTU_SEP_TOKEN = "u"
MISSING_APACHE = "(none)"

REQUIRED_APACHE = "2.2.31"

PASSWORD_FILENAME = "password.txt"
COMPILER_RESULT = "compiler_result.txt"
VERSION_FILENAME = "version.txt"
COMPILER_FILENAME = "compiler.txt"
TELNET_FILENAME = "telnet.txt"
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
        #self.is_supported()
        # self.is_clean_production_server()
        # self.is_supported()
        # self.user_access_restricted()
        self.meets_compiler_restriction()
        # self.inbound_email_restricted()

        self.password_file_permissions_set()


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
            self.version_sep_token = None  # Only using Ubuntu now

###########################################

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
                return False

            installed = installed_line.split(UBUNTU_SEP_TOKEN)[0]
            meets_requirements = self.version_meets_requirements(installed)

            if(meets_requirements):
                return True
            else:
                return False

        elif(self.os == "RedHatLinux"):  # Todo
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
            return False
        if(int(second) != 2):
            return False
        if(int(third) < 31):
            return Falses
        return True


##########################

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
        return True

    def has_example_applications(self):
        return True

    def has_tutorials(self):
        return True

    def user_access_restricted(self):
        """Check SV-36456r2_rule: Administrators must be the only users
        allowed access to the directory tree, the shell, or other
        operating system functions and utilities.


        Finding ID: V-2247

        Verify with the system administrator or the ISSO that all
        privileged accounts are mission essential and documented.

        Verify with the system administrator or the ISSO that all
        non-administrator access to shell scripts and operating system
        functions are mission essential and documented.


        - If undocumented privileged accounts are found, this is a finding.
        - If undocumented access to shell scripts or operating system
          functions is found, this is a finding.
        """

        return False

####################################


    def meets_compiler_restriction(self):
        """Check SV-32956r3_rule: Installation of a compiler on 
        production web server is prohibited.

        

        Finding ID: V-2236  

        Verify that no compilers are installed on the system unless 
        documented and restricted to administrator use.
        """
        exists = self.compiler_exists()
        approved = self.compiler_allowed()

        if(exists and not approved):
            meets_restriction = False
        else:
            meets_restriction = True

        return meets_restriction


    def compiler_exists(self):
        """Checks the package manager to see if any programs 
        with keyword 'compiler' are installed on the system.
        Currently only checks using dpkg. 

        TODO:
            Add support for Red Hat Linux with yum package manager
            Use better technique to check for compilers.

        """

        print(self.os)
        if(self.os == "Ubuntu"):
            compiler_info = open(COMPILER_FILENAME, "w")
            p1 = subprocess.Popen(["dpkg", "--list"], 
                stdout=subprocess.PIPE)
            p2 = subprocess.Popen(["grep", "compiler"], 
                stdin=p1.stdout, stdout=subprocess.PIPE)
            p1.stdout.close()
            output,err = p2.communicate()
            compiler_info.write(output)
            compiler_info.close()

            compiler_info = open(COMPILER_FILENAME, "r")
            for line in compiler_info:
                if line is not None:
                    compiler_info.close()
                    call(["rm", COMPILER_FILENAME])
                    return True 

            compiler_info.close()
            call(["rm", COMPILER_FILENAME])
            return False

        elif(self.os == "RedHatLinux"):  # Todo
            pass

    def compiler_allowed(self):
        """Check if compiiler on production server is DOD approved
        and meets user access restriction requirements.
        """
        return False

############################################
    def minmium_file_permissions_set(self):
        return False


############################################
    def cgi_files_monitored(self):
        """Check SV-32927r2_rule: Monitoring software must include CGI
        or equivalent programs in its scope.

        Finding ID: V-2236

        CGI or equivalent files must be monitored by a 
        security tool that reports unauthorized changes.

        Query the system for a tool that monitors CGI files. 
        Example FileTypes: .cgi, .asp, .aspx, .class, .vb, .php, .pl, and .c
        """

        return False

############################################
    def password_file_permissions_set(self):
        """Check SV-32927r2_rule: The web server’s htpasswd files 
        (if present) must reflect proper ownership and permissions

        Finding ID: V-2255
        """

        password_info = open(PASSWORD_FILENAME, "w")
        call(["find", "/", "-name", "htpasswd"], stdout=password_info)
        password_info.close()

        password_info = open(PASSWORD_FILENAME, "r")

        for line in password_info:
            line = line.strip("\n")
            permissions = oct(os.stat(line).st_mode & 0777)
            first = permissions[1]
            second = permissions[2]
            third = permissions[3]

            if(first != 5 or second != 5 or third != 7):
                password_info.close()
                call(["rm", PASSWORD_FILENAME])
                return False

        password_info.close()
        call(["rm", PASSWORD_FILENAME])
        return True

############################################
    def server_not_proxy(self):
        """Check SV-33220r1_rule: The web server must not be 
        configured as a proxy server.

        Finding ID: V-26299 
        """

        return False

############################################
    def server_segregated(self):
        """Check SV-32950r1_rule: The web server must be 
        segregated from other services.

        Finding ID: V-6577
        """
        return False

############################################
    def server_segregated(self):
        """Check SV-32950r1_rule: The web server must be 
        segregated from other services.

        Finding ID: V-6577
        """
        return False


############################################
    def pid_file_secure(self):
        """Check SV-33222r1_rule: The process ID (PID) 
        file must be properly secured.

        Finding ID: V-26305 
        """
        return False

############################################
    def inbound_email_restricted(self):
        """Check SV-32937r1_rule: A public web server must 
        limit email to outbound only.

        Finding ID: V-2261 UNFINSHED
        """
        telnet_info = open(TELNET_FILENAME, "w")
        code = call(["telnet", "google.com", "25"], stdout=telnet_info)
        telnet_info.close()
        call(["rm", TELNET_FILENAME])


        return False

############################################
    def user_directories_restricted(self):
        """Check SV-33221r1_rule: User specific directories
        must not be globally enabled.

        Finding ID: V-26302
        """
        return False

############################################
    def software_updated(self):
        """Check SV-32969r2_rule: The Web site software used with the 
        web server must have all applicable security patches 
        applied and documented.

        Finding ID: V-13613
        """
        return False

############################################
    def server_isolated(self):
        """Check SV-32932r2_rule: A public web server, if 
        hosted on the NIPRNet, must be isolated in an accredited 
        DoD DMZ Extension.


        Finding ID: V-2242
        """
        return False

############################################
    def mime_types_disabled(self):
        """Check SV-36309r2_rule: MIME types for csh or sh 
        shell programs must be disabled.

        Finding ID: V-2225
        """
        return False

############################################
    def certificates_validated(self):
        """Check SV-32954r2_rule: The private web server must use an
        approved DoD certificate validation process.

        Finding ID: V-13672 
        """
        return False

############################################
    def modules_minimized(self):
        """Check SV-33215r1_rule: Active software modules 
        must be minimized.


        Finding ID: V-26285 
        """
        return False

############################################
    def webdav_disabeld(self):
        """Check SV-33216r1_rule: Web Distributed Authoring 
        and Versioning (WebDAV) must be disabled.


        Finding ID: V-26287
        """
        return False

############################################
    def export_ciphers_remoevd(self):
        """Check SV-75159r1_rule: The web server must remove all 
        export ciphers from the cipher suite.


        Finding ID: V-60707 
        """
        return False

############################################
    def admin_tools_restricted(self):
        """Check SV-32948r2_rule: Web administration tools must be 
        restricted to the web manager and the web manager’s 
        designees.


        Finding ID: V-2248  
        """
        return False

############################################
    def scoreboard_file_secured(self):
        """Check SV-33223r1_rule: The score board file must be 
        properly secured.


        Finding ID: V-26322 
        """
        return False

############################################
    def directory_indexing_disabled(self):
        """Check SV-33219r1_rule: Automatic directory indexing must be 
        disabled.


        Finding ID: V-26368 
        """
        return False

############################################
    def url_pathname_set(self):
        """Check SV-33229r1_rule: The URL-path name must be set to 
        the file path name or the directory path name.

        Finding ID: V-26327
        """
        return False

############################################
    def backup_process_set(self):
        """Check SV-32964r2_rule: Web server content and 
        configuration files must be part of a routine backup program.


        Finding ID: V-6485
        """
        return False

############################################
    def backup_scripts_removed(self):
        """Check SV-6930r1_rule: Backup interactive scripts
         on the production web server are prohibited.



        Finding ID: V-2230
        """
        return False

############################################        
    def utility_programs_removed(self):
        """Check SV-32955r2_rule: All utility programs, not necessary for 
        operations, must be removed or disabled.    



        Finding ID: V-2251
        """
        return False

############################################  
    def utility_programs_removed(self):
        """Check SV-32951r1_rule: Administrative users and groups 
        that have access rights to the web server must be documented.
   
        Finding ID: V-2257
        """
        return False


if __name__ == '__main__':
    auditor = SystemAuditor()
    auditor.audit_system()
