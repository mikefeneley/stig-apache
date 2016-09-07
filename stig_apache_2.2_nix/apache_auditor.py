import os
import glob
import sys
from subprocess import call
from apache_parser import ApacheConfParser

# Notes: 
# Need to add return value checking and update log on 
# a bad return value
# Allow user to secify system specs and design choices that
# can help identify uneeded configuration modules


ROOT = "/"
UBUNTU_CONF_DIR = "/etc/"
UBUNTU_APACHE_CONF = "apache2.conf"
LOG_HEADER = "BEGIN APACHE CONFIG REPORT\n\n\n"
SERVERSIG_DIRECTIVE = "ServerSignature"
SERVERTOKENS_DIRECTIVE = "ServerTokens"
LOADMODULE_DIRECTIVE = "LoadModule"
OPTIONS_DIRECTIVE = "Options"
SERVERSIG_RECOMENDATION = "ServerSignature Off"
SERVERTOKENS_RECOMENDATION = "ServerTokens Prod"
SYMBOLIC_LINK_RECOMENDATION = "Options -FollowSymLinks"
ROOT_ORDER_RECOMENDATION = "Order Deny,Allow"
ROOT_DENY_RECOMENDATION = "Deny from all"
ROOT_OPTIONS_RECOMENDATION = "Options None"
START_DIRECTORY = "<Directory"
END_DIRECTORY = "</Directory>"

UBUNTU_SEP_TOKEN = "u"

LOG_FILENAME = "apache_log.txt"
VERSION_FILENAME = "version.txt"
SYSTEM_INFOFILE = "/proc/version"

class ApacheAuditor:

    def __init__(self):

        self.os = None
        self.conf_dir = None
        self.main_conf = None
        self.version_sep_token = None
        self.serversigniture = False
        self.servertokens = False
        self.symboliclinks = False
        self.disable_options = False
        self.deny_first = False
        self.deny_all = False

    def audit_apache(self):
        self.apache_log = open(LOG_FILENAME, "w")
        self.apache_log.write(LOG_HEADER)
        self.get_system_info()
        self.check_apache_version()
        self.audit_apache_conf()
        self.check_missing()
        self.apache_log.close()
        return 0


    """ Gets information about the operating so that
        the default apache configuration setup can be found """
    def get_system_info(self):
        system_info = open(SYSTEM_INFOFILE, "r")
        
        line = system_info.readline()   
        os_name = line.split()[7]
        os_name = os_name[1:]
        self.os = os_name

        if(self.os == "Ubuntu"):
            self.main_conf = UBUNTU_APACHE_CONF
            self.conf_dir = UBUNTU_CONF_DIR
            self.version_sep_token = UBUNTU_SEP_TOKEN


    def check_apache_version(self):

        version_info = open(VERSION_FILENAME, "w")
        call(["apt-cache", "policy", "apache2"], stdout=version_info)
        version_info.close()

        version_info = open(VERSION_FILENAME, "r")

        candidate = -1
        installed = -2
        
        for line in version_info:
            line_tokens = line.split()
            if line_tokens[0] == "Installed:":
                installed_line = line_tokens[1]
            elif line_tokens[0] == "Candidate:":
                candidate_line = line_tokens[1]

        if(self.os == "Ubuntu"):
            installed = installed_line.split(UBUNTU_SEP_TOKEN)[0]
            candidate = candidate_line.split(UBUNTU_SEP_TOKEN)[0]

        if(installed != candidate):
            self.write_version_error()
        
        version_info.close()
        call(["rm", VERSION_FILENAME])
        return 0


    """ Finds the main apache configuration file and calls helper
        methods to generate report of recomended changes """
    def audit_apache_conf(self):
        self.server_root = self.get_server_root(self.main_conf)
        main_conf_path = os.path.join(self.server_root, self.main_conf)
        print self.server_root
        parser = ApacheConfParser(self.server_root)
        full_directive_list = parser.parse_apache_conf(main_conf_path)
        self.process_directives(full_directive_list)


    """ Looks at every directive in directive and calls subfunctions
        to handle depending on the type of directive """
    def process_directives(self, directive_list):

        i = 0
        while i < len(directive_list):
            directive_info = directive_list[i]
            if self.check_start_directory(directive_info):
                i, directory_list = self.get_directory_list(i, directive_list)
                self.process_directory(directory_list)
            elif self.check_serversignature(directive_info):
                self.serversignature = True
            elif self.check_servertokens(directive_info):
                self.servertokens = True
            elif self.check_options(directive_info):
                self.symbolic_links = True
            elif self.is_load_module(directive_info):
                self.check_load_module(directive_info)
            i += 1


    """ Checks for any recomended configuration feature that was not
        found by the configuration parse """
    # Note - Refactor this section so that you check for existance and then return
    # before possibly calling check
    def check_missing(self):
        if(not self.serversigniture):
            self.advise_add_directive(SERVERSIG_RECOMENDATION)
        if(not self.servertokens):
            self.advise_add_directive(SERVERTOKENS_RECOMENDATION)
        if(not self.symboliclinks):
            self.advise_add_directive(SYMBOLIC_LINK_RECOMENDATION)
        if(not self.disable_options):
            self.advise_add_root_directive(ROOT_OPTIONS_RECOMENDATION)
        if(not self.deny_first):
            self.advise_add_root_directive(ROOT_ORDER_RECOMENDATION)
        if(not self.deny_all):
            self.advise_add_root_directive(ROOT_DENY_RECOMENDATION)


    # This section checks the options for directives that should be
    # applied at the server scope. Includes information leaking
    # directives serversig and servertokens as well as
    # symbolic link permissions

    # Note - Check for existance in the program as well as the option. If
    # not found, still need to advise they be added with specified option.

    def check_serversignature(self, directive_info):

        directive = directive_info.get_directive()
        if directive == SERVERSIG_DIRECTIVE:
            self.check_serversignature_options(directive_info)
            return 1
        else:
            return 0

    def check_serversignature_options(self, directive_info):

        options = directive_info.get_options()
        serversig_option = options[0]

        if serversig_option == "Off":
            return
        else:
            self.advise_directive_change(
                directive_info, SERVERSIG_RECOMENDATION)

    def check_servertokens(self, directive_info):
        directive = directive_info.get_directive()
        if directive == SERVERTOKENS_DIRECTIVE:
            self.check_servertokens_options(directive_info)
            return 1
        else:
            return 0

    def check_servertokens_options(self, directive_info):
        directive_options = directive_info.get_options()
        servertoken_option = directive_options[0]
        if servertoken_option == "Prod":
            return
        else:
            self.advise_directive_change(
                directive_info, SERVERTOKENS_RECOMENDATION)

    def check_options(self, directive_info):
        directive = directive_info.get_directive()
        if directive == OPTIONS_DIRECTIVE:
            self.check_symbolic_link(directive_info)

    def check_symbolic_link(self, directive_info):
        options = directive_info.get_options()
        for option in options:
            if option == "FollowSymLinks" or option == "+FollowSymLinks":
                self.advise_directive_change(
                    directive_info, SYMBOLIC_LINK_RECOMENDATION)
                self.symboliclinks = True

    def is_load_module(self, directive_info):
        directive = directive_info.get_directive()
        if(directive == LOADMODULE_DIRECTIVE):
            return True
        else:
            return False

    def check_load_module(self, directive_info):
        options = directive_info.get_options()
        module = options[0]

        unneeded = ["mod_imap", "mod_include", "mod_info",
                    "mod_userdir", "mod_autoindex"]

        for uneeded_module in unneeded:
            if module == uneeded_module:
                advise_remove_module(directive_info)

    #
    # Setup functions...
    #
    def get_server_root(self, main_conf):
        for root, dirs, files in os.walk(self.conf_dir):
            if main_conf in files:
                return root

    def get_main_conf(self):
        abspath = os.path.join(self.server_root, APACHE_CONFIG)
        main_conf = open(abspath, "r")
        return main_conf

    #
    # This section is responsible for checking directories. Currently
    # only know enough about directories to check that certain directives
    # with certain options have been applied to the root directory.
    # Check that desired option meets required specification as well as exists
    #
    def process_directory(self, directory_list):
        directive_info, directory = directory_list[0]

        if directory == ROOT:
            self.check_root_directory(directory_list)

    def check_root_directory(self, directory_list):

        for directive_info, directory in directory_list:
            directive = directive_info.get_directive()
            options = directive_info.get_directive()

            if directive == "Options":
                self.check_root_options(directive_info)
                self.disable_options = True
                return 1
            elif directive == "Order":
                self.check_root_order(directive_info)
                self.deny_first = True
                return 1
            elif directive == "Deny":
                self.check_root_deny(directive_info)
                self.deny_all = True
                return 1
        return 0

    def check_root_order(self, directive_info):
        options = directive_info.get_options()
        if options[0] != "Deny,Allow":
            self.advise_directive_change(
                directive_info, ROOT_ORDER_RECOMENDATION)

    def check_root_deny(self, directive_info):
        options = directive_info.get_options()
        if options[0] != "from" or options[1] != "all":
            self.advise_directive_change(
                directive_info, ROOT_DENY_RECOMENDATION)

    def check_root_options(self, directive_info):
        options = directive_info.get_options()
        if options[0] != "None":
            self.advise_directive_change(
                directive_info, ROOT_OPTIONS_RECOMENDATION)

    def check_start_directory(self, directive_info):
        directive = directive_info.get_directive()
        directory_length = len(START_DIRECTORY)
        if (len(directive) == directory_length and
                directive[0:directory_length + 1] == START_DIRECTORY):
            return True
        else:
            return False

    def check_end_directory(self, directive_info):
        directive = directive_info.get_directive()
        if directive == END_DIRECTORY:
            return True
        else:
            return False

    def get_directory_list(self, current_index, directive_list):
        directory_options = []

        i = current_index + 1
        directive_info = directive_list[current_index]
        directory = self.get_directory(directive_info)
        while 1:
            directive_info = directive_list[i]
            if self.check_end_directory(directive_info):
                break
            directory_options.append((directive_info, directory))
            i += 1

        return i, directory_options

    def get_directory(self, directive_info):
        options = directive_info.get_options()
        directory = options[0].split(">")
        return directory[0]
    #
    # Log report methods below here
    #
    def advise_directive_change(self, directive_info, recomendation):

        directive_line = directive_info.get_line()
        directive_line = " ".join(directive_line)
        line_num = directive_info.get_line_num()
        filename = directive_info.get_filename()

        report = "In file " + filename + " on line number " + str(line_num)
        report += "\nyou have the following directive: \n" + directive_line
        report += "\n\nIt is recomended that you change this to:\n"
        report += recomendation + "\n\n\n\n"
        self.apache_log.write(report)

    def advise_add_directive(self, recomendation):
        report = "It is recomended that you add " + recomendation
        report += " to your main configuration file\n\n"
        self.apache_log.write(report)

    def advise_add_root_directive(self, recomendation):
        report = "It is recomended that you add " + recomendation
        report += " to the root directory configuration section\n\n"
        self.apache_log.write(report)

    def advise_remove_module(self, directive_info):

        directive_line = directive_info.get_line()
        directive_line = " ".join(directive_line)
        line_num = directive_info.get_line_num()
        filename = directive_info.get_filename()

        report = "In file " + filename + " on line number " + str(line_num)
        report += "\nyou have the following directive: \n" + directive_line
        report += "\n\nIt is recomended that you remove this line from your"
        report += " configuration file\n\n\n\n"
        self.apache_log.write(report)

    def write_version_error(self, installed, candidate):
        report = "You currently have version " + installed + " of \n"
        report += "apache2. It is recomended that you install the "
        report += "Latest avaliable version: " + candidate + "\n\n\n\n"
        self.apache_log.write(report)