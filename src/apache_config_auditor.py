# -*-coding: utf-8 -*-

from apache_config_logger import ApacheConfigLogger
from apache_parser import DirectiveInfo
from apache_parser import DirectiveLine

ROOT = "/"
START_DIRECTORY = "<Directory"
END_DIRECTORY = "</Directory>"


class ApacheConfigAuditor:
    """
    ApacheConfigAuditor checks the directive_list for all STIG requirements
    that involve single or multiline directives from the main Apache
    configuration file on the server.
    """
    def __init__(self, directive_list=None):
        self.directive_list = directive_list

    def audit(self):
        """
        Run checks of the apache configuartion file for compliance and
        report all misconfiguartions using the ApacheConfigLogger.

        :returns: string -- filename of the log file
        """
        if self.directive_list == 0:
            return 0

        logger = ApacheConfigLogger()
        result = self.ssi_disabled()
        logger.ssi_disabled_errmsg(result)
        result = self.http_header_field_limited()
        logger.http_header_field_limited_errmsg(result)
        result = self.http_line_limited()
        logger.http_line_limited_errmsg(result)
        result = self.maxclients_set()
        logger.maxclients_set_errmsg(result)
        result = self.interactive_programs_set()
        logger.interactive_programs_set_errmsg(result)
        result = self.symlinks_disabled()
        logger.symlinks_disabled_errmsg(result)
        result = self.multiviews_disabled()
        logger.multiviews_disabled_errmsg(result)
        result = self.indexing_disabled()
        logger.indexing_disabled_errmsg(result)
        result = self.http_message_limited()
        logger.http_message_limited_errmsg(result)
        result = self.http_header_limited()
        logger.http_header_limited_errmsg(result)
        result = self.request_methods_limited()
        logger.request_methods_limited_errmsg(result)
        result = self.minspareservers_set()
        logger.minspareservers_set_errmsg(result)
        result = self.startservers_set()
        logger.startservers_set_errmsg(result)
        result = self.keepalivetimeout_set()
        logger.keepalivetimeout_set_errmsg(result)
        result = self.keepalive_set()
        logger.keepalive_set_errmsg(result)
        result = self.timeout_set()
        logger.timeout_set_errmsg(result)
        result = self.maxspareservers_set()
        logger.maxspareservers_set_errmsg(result)
        result = self.ports_configured()
        logger.ports_configured_errmsg(result)
        result = self.mime_types_disabled()
        logger.mime_types_disabled_errmsg(result)
        result = self.root_denied()
        logger.root_denied_errmsg(result)
        result = self.url_name_set()
        logger.url_name_set_errmsg(result)
        result = self.trace_disabled()
        logger.trace_disabled_errmsg(result)
        result = self.override_denied()
        logger.override_denied_errmsg(result)
        result = self.pid_file_secure()
        logger.pid_file_secure_errmsg(result)
        filename = logger.get_filename()
        del logger

        return filename

    def ssi_disabled(self):
        """
        Check SV-32753r1_rule: Server side includes (SSIs) must run
        with execution capability disabled.

        Finding ID: V-13733

        Review all uncommented Options statements for the following values:

        +IncludesNoExec
        -IncludesNoExec
        -Includes


        -If these values don’t exist this is a finding.
        -If the value does NOT exist, this is a finding.
        -If all enabled Options statement are set to None this is
         not a finding.

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        option_exists = False
        ssi_option_disabled = False
        options_set_none = True
        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "Options":
                option_exists = True
                options = directive.get_options()
                for option in options:
                    if option != "None":
                        options_set_none = False
                    if option == "+IncludesNoExec":
                        ssi_option_disabled = True
                    elif option == "-IncludesNoExec":
                        ssi_option_disabled = True
                    elif option == "-Includes":
                        ssi_option_disabled = True

        if options_set_none and option_exists:
            disabled = True
        elif ssi_option_disabled:
            disabled = True
        else:
            disabled = False
        return disabled

    def http_header_field_limited(self):
        """
        Check SV-32766r2_rule: The HTTP request header field size
        must be limited.

        Finding ID: V-13738

        Check active configuation file for directive:

        LimitRequestFiledSize

        -If no LimitRequestFieldSize directives exist, this is a Finding.
        -If the value of LimitRequestFieldSize is not set to 8190,
         this is a finding.

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        directive_exists = False
        correct_value = False

        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "LimitRequestFieldSize":
                directive_exists = True
                options = directive.get_options()
                for option in options:
                    if option == "8190":
                        correct_value = True

        if(directive_exists and correct_value):
            limited = True
        else:
            limited = False
        return limited

    def http_line_limited(self):
        """
        Check SV-32768r2_rule: The HTTP request line must be limited.

        Finding ID: V-13739

        Check active configuation file for directive:

        LimitRequestLine

        -If no LimitRequestLine directives exist, this is a Finding.
        -If the value of LimitRequestLine is not set to 8190,
         this is a finding.

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        directive_exists = False
        correct_value = False

        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "LimitRequestLine":
                directive_exists = True
                options = directive.get_options()
                for option in options:
                    if option == "8190":
                        correct_value = True
        if(directive_exists and correct_value):
            limited = True
        else:
            limited = False
        return limited

    def maxclients_set(self):
        """
        Check SV-36649r2_rule: The MaxClients directive
        must be set properly.

        Finding ID: V-13730

        Check active configuation file for directive:

        MaxClients

        - If the value of MaxClients is not less than or equal to 256,
          this is a finding.
        - If the directive does not exist, this is NOT a finding
          because it will default to 256.

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        directive_exists = False
        correct_value = False

        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "MaxClients":
                directive_exists = True
                options = directive.get_options()
                for option in options:
                    if(int(option) < 256):
                        correct_value = True
        if(correct_value or not directive_exists):
            correct = True
        else:
            correct = False
        return correct

    def interactive_programs_set(self):
        """
        Check SV-32763r1_rule: All interactive programs must be placed
        in a designated directory with appropriate permissions.

        Finding ID: V-13731

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        pass

    def symlinks_disabled(self):
        """
        Check SV-40129r1_rule: The "–FollowSymLinks” setting must be disabled.

        Finding ID: V-13732

        Review all uncommented Options statements for the following values:

        -FollowSymLinks

        - If the value does NOT exist, this is a finding.
        - If all enabled Options statement are set to None
          this is not a finding.

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        option_exists = False
        symlinks_option_disabled = False
        options_set_none = True
        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "Options":
                option_exists = True
                options = directive.get_options()
                for option in options:
                    if option != "None":
                        options_set_none = False
                    if option == "-FollowSymLinks":
                        symlinks_option_disabled = True

        if options_set_none and option_exists:
            disabled = True
        elif symlinks_option_disabled:
            disabled = True
        else:
            disabled = False
        return disabled

    def multiviews_disabled(self):
        """
        Check SV-32754r1_rule: The MultiViews directive must be disabled.

        Finding ID: V-13734

        Review all uncommented Options statements for the following value:

        -MultiViews

        - If the value is found on the Options statement, and it does not
          have a preceding ‘-‘, this is a finding.
        - If the value does NOT exist, this is a finding.
        - If all enabled Options statement are set to None
          this is not a finding.

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        option_exists = False
        multiviews_option_disabled = False
        options_set_none = True
        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "Options":
                option_exists = True
                options = directive.get_options()
                for option in options:
                    if option != "None":
                        options_set_none = False
                    if option == "-Multiview":
                        multiviews_option_disabled = True

        if option_exists and options_set_none:
            disabled = True
        elif multiviews_option_disabled:
            disabled = True
        else:
            disabled = False
        return disabled

    def indexing_disabled(self):
        """
        Check SV-32755r1_rule: Directory indexing must be disabled on
        directories not containing index files.

        Finding ID: V-13735

        Review all uncommented Options statements for the following value:

        -Indexes

        - The value is found on the Options statement, and it does not have a
          preceding ‘-‘, this is a finding.
        - If the value does NOT exist, this is a finding.
        - If all enabled Options statement are set to None
          this is not a finding.

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        option_exists = False
        indexing_option_disabled = False
        options_set_none = True
        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "Options":
                option_exists = True
                options = directive.get_options()
                for option in options:
                    if option != "None":
                        options_set_none = False
                    if option == "-Indexes":
                        indexing_option_disabled = True

        if option_exists and options_set_none:
            disabled = True
        elif indexing_option_disabled:
            disabled = True
        else:
            disabled = False
        return disabled

    def http_message_limited(self):
        """
        Check SV-32756r1_rule: The HTTP request message body size must be limited.

        Finding ID: V-13736

        Check active configuation file for directive:

        LimitRequestBody

        - If the value of LimitRequestBody is not set to 1 or greater or
          does not exist, this is a finding.

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        correct_value = False
        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "LimitRequestBody":
                options = directive.get_options()
                for option in options:
                    if(int(option) >= 1):
                        correct_value = True
        if(correct_value):
            limited = True
        else:
            limited = False
        return limited

    def http_header_limited(self):
        """
        Check SV-32757r1_rule: The HTTP request header fields must be limited.

        Finding ID: V-13737

        Check active configuation file for directive:

        LimitRequestFields

        - If the value of LimitRequestFields is not set to a value
          greater than 0, this is a finding.

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        correct_value = False
        for directive in self.directive_list:
                directive_start = directive.get_directive()
                if directive_start == "LimitRequestFields":
                    options = directive.get_options()
                    for option in options:
                        if(int(option) >= 1):
                            correct_value = True
        if(correct_value):
            limited = True
        else:
            limited = False
        return limited

    def request_methods_limited(self):
        """
        Check SV-33236r1_rule: HTTP request methods must be limited.

        Finding ID: V-26396

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        pass

    def minspareservers_set(self):
        """
        Check SV-36646r2_rule: The httpd.conf MinSpareServers
        directive must be set properly.

        Finding ID: V-13728

        Check active configuation file for directive:

        MinSpareServers

        The value needs to be between 5 and 10

        - If the directive is set improperly, this is a finding.
        - If the directive does not exist, this is NOT a finding
          because it will default to 5.

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        directive_exists = False
        correct_value = False
        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "MinSpareServers":
                directive_exists = True
                options = directive.get_options()
                for option in options:
                    if(int(option) >= 5 and int(option) <= 10):
                        correct_value = True
        if(correct_value or not directive_exists):
            correct = True
        else:
            correct = False
        return correct

    def startservers_set(self):
        """
        Check SV-36645r2_rule: The httpd.conf StartServers
        directive must be set properly.

        Finding ID: V-13727

        Check active configuation file for directive:

        StartServers

        The value needs to be between 5 and 10

        - If the directive is set improperly, this is a finding.
        - If the directive does not exist, this is NOT a finding
          because it will default to 5.

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        directive_exists = False
        correct_value = False
        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "StartServers":
                directive_exists = True
                options = directive.get_options()

                for option in options:
                    if(int(option) >= 5 and int(option) <= 10):
                        correct_value = True
        if(correct_value or not directive_exists):
            correct = True
        else:
            correct = False
        return correct

    def keepalivetimeout_set(self):
        """
        Check SV-32877r1_rule: The KeepAliveTimeout directive must be defined.

        Finding ID: V-13726

        Check active configuation file for directive:

        KeepAliveTimeout

        The value needs to be less than or equal to 15

        - If the directive is set improperly, this is a finding.
        - If the directive does not exist, this is NOT a finding
          because it will default to 5.

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        directive_exists = False
        correct_value = False
        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "KeepAliveTimeout":
                directive_exists = True
                options = directive.get_options()
                for option in options:
                    if(int(option) <= 15):
                        correct_value = True
        if(correct_value or not directive_exists):
            correct = True
        else:
            correct = False
        return correct

    def keepalive_set(self):
        """
        Check SV-32844r2_rule: The KeepAlive directive must be enabled.

        Finding ID: V-13725

        Check active configuation file for directive:

        KeepAlive

        - Verify the Value of KeepAlive is set to On, If not, it is a finding

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        correct_value = False
        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "KeepAlive":
                options = directive.get_options()
                for option in options:
                    if(option == "On"):
                        correct_value = True
        if(correct_value):
            correct = True
        else:
            correct = False
        return correct

    def timeout_set(self):
        """
        Check SV-32977r1_rule: The Timeout directive must be properly set.

        Finding ID: V-13724

        Check active configuation file for directive:

        Timeout

        - Verify the value is 300 or less if not, this is a finding.
        - If the directive does not exist, this is not a finding
          because it will default to 300

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        directive_exists = False
        correct_value = False
        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "Timeout":
                directive_exists = True
                options = directive.get_options()
                for option in options:
                    if(int(option) <= 300):
                        correct_value = True
        if(correct_value or not directive_exists):
            correct = True
        else:
            correct = False
        return correct

    def maxspareservers_set(self):
        """
        Check SV-36648r2_rule: The MaxSpareServers directive must be set properly.

        Finding ID: V-13729

        Check active configuation file for directive:

        MaxSpareServers

        - The value needs to be 10 or less
        - If the directive is set improperly, this is a finding.

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        directive_exists = False
        correct_value = False
        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "MaxSpareServers":
                directive_exists = True
                options = directive.get_options()
                for option in options:
                    if(int(option) <= 10):
                        correct_value = True
        if(correct_value or not directive_exists):
            correct = True
        else:
            correct = False
        return correct

    def ports_configured(self):
        """
        Check SV-33228r1_rule: The web server must be configured to
        listen on a specific IP address and port.

        Finding ID: V-26326

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        directive_exists = False

        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "Listen":
                directive_exists = True
                options = directive.get_options()
                for option in options:
                    valid_address = self.is_valid_address(option)
                    if(not valid_address):
                        return False

        if(not directive_exists):
            return False
        else:
            return True

    def is_valid_address(self, address):
        """
        A valid apache address is one that has both an ip address that is
        not all zeros and a port number. Function checks if both of these
        criteria are met.

        :param address: The address to check for criteria
        :type address: string
        :returns: bool -- True if criteria is met, False otherwise
        """
        if "[" in address:  # Ipv6

            if "]:" not in address:  # Check for port
                return False
            start = address.find("[")
            end = address.find("]")
            ipv6_address = address[start + 1: end]

            address_nonzero = False
            for character in ipv6_address:
                if(character.isdigit() and character != "0"):
                    address_nonzero = True
            return address_nonzero
        else:  # ipv4
            if "0.0.0.0" in address:    # Check all zero ipv4 address
                return False
            if ":" not in address:
                return False
            return True

    def mime_types_disabled(self):
        """
        Check SV-36309r2_rule: MIME types for csh or sh shell
        programs must be disabled.


        Finding ID: V-2225

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        pass

    def root_denied(self):
        """
        Check SV-33226r1_rule: The web server must be configured to
        explicitly deny access to the OS root.

        Finding ID: V-26323

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        pass

    def url_name_set(self):
        """
        Check SV-33229r1_rule: The web server must be configured to
        explicitly deny access to the OS root.

        Finding ID: V-26327

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        pass

    def trace_disabled(self):
        """
        Check SV-33227r1_rule: The TRACE method must be disabled.

        Finding ID: V-26325

        Currently not checking the scope

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        directive_exists = False
        correct_value = False

        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "TraceEnable":
                directive_exists = True
                options = directive.get_options()
                for option in options:
                    if option == "Off":
                        correct_value = True
        if(directive_exists and correct_value):
            limited = True
        else:
            limited = False
        return limited

    def override_denied(self):
        """
        Check SV-33232r1_rule: The ability to override the access
        configuration for the OS root directory must be disabled.

        Finding ID: V-26393

        For every root directory entry ensure the following entry exists:

        AllowOverride None

        - If the statement above is not found in the root directory
          statement, this is a finding.
        - If Allow directives are included in the root directory
          statement, this is a finding.

        :returns: bool -- True if rule is satisfied, False otherwise
        """
        root_exists = False
        option_exists = False
        option_correct = False

        i = 0
        while i < len(self.directive_list):
            directive = self.directive_list[i]
            directive_start = directive.get_directive()

            if(directive_start == START_DIRECTORY):
                tmp = i
                directory_list = self.get_directory_list(tmp)

                first_directive = directory_list[0]
                directive_info = first_directive[0]
                directory = first_directive[1]
                if(directory == '/'):
                    root_exists = True
                    for line in directory_list:
                        directive_info = line[0]
                        directive = directive_info.get_directive()
                        options = directive_info.get_options()
                        print(directive)
                        if(directive == 'AllowOverride'):
                            option_exists = True
                            print("In here??")
                            if(options[0] == "None"):
                                option_correct = True
            i += 1
        return option_exists and option_correct and root_exists

    def get_directory_list(self, current_index):
        """
        Currently does not work if directive list
        is empty.
        """

        directory_options = []

        i = current_index + 1
        directive_info = self.directive_list[current_index]
        directory = self.get_directory(directive_info)
        while True:
            directive_info = self.directive_list[i]
            if self.check_end_directory(directive_info):
                break
            directory_options.append((directive_info, directory))
            i += 1
        return directory_options

    def get_directory(self, directive_info):
        options = directive_info.get_options()
        directory = options[0].split(">")
        return directory[0]

    def check_end_directory(self, directive_info):
        directive = directive_info.get_directive()
        if directive == END_DIRECTORY:
            return True
        else:
            return False

    def pid_file_secure(self):
        """
        Check SV-33222r1_rule: The process ID (PID)
        file must be properly secured.

        Finding ID: V-26305
        """
        return False


if __name__ == "__main__":
    test_list = []
    line = DirectiveInfo(DirectiveLine("<Directory", ["/>"]), 0, 'file.txt')
    test_list.append(line)
    line = DirectiveInfo(
        DirectiveLine("AllowOverride", ["None"]), 0, 'file.txt')
    test_list.append(line)
    line = DirectiveInfo(DirectiveLine("</Directory>", [""]), 0, 'file.txt')
    test_list.append(line)

    auditor = ApacheConfigAuditor(test_list)

    print(auditor.override_denied())
