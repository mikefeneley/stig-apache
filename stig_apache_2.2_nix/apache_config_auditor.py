# -*- coding: utf-8 -*-

from apache_logger import ApacheLogger


""" ApacheConfigAuditor checks the directive_list for all STIG requirements
that involve single or multiline directives from the main apache configuration
file on the server.
"""
class ApacheConfigAuditor:
    def __init__(self, directive_list = None):
        self.directive_list = directive_list
        self.logger = ApacheLogger() 

    def audit_config(self):
        self.ssi_disabled()            
        self.http_header_limited()
        self.http_line_limited()
        self.symlinks_disabled()
        self.multiviews_disabled()
        self.indexing_disabled()
        self.http_message_limited()
        self.http_header_limited()
        self.minspareservers_set()
        self.startservers_set()
        self.keepalivetimeout_set()
        self.keepalive_set()
        self.timeout_set()
        self.root_denied()
        self.ports_configured()
        self.maxspareservers_set()


    """Check SV-32753r1_rule: Requires server side includes be disabled to 
    prevent external scripts from being execued.

    Review all uncommented Options statements for the following values:
         
    +IncludesNoExec
    -IncludesNoExec
    -Includes
    
    
    -If these values don’t exist this is a finding.
    -If the value does NOT exist, this is a finding.
    -If all enabled Options statement are set to None this is not a finding.""" 
    def ssi_disabled(self):
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
        if option_exists and not ssi_option_disabled and not options_set_none:
            self.logger.ssi_disabled_errmsg()
            finding = True
        else:
            finding = False
        return finding 

    def http_header_limited(self):
        directive_exists = False
        correct_value = False

        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "LimitRequestFieldSize":
                directive_exists = True
                for option in options:
                    if option == "8190":
                        correct_value = True
        
        if(not directive_exists or not correct_value):
            self.logger.http_header_limited_errmsg()
            finding = True
        else:
            finding = False
        return finding

    def http_line_limited(self):
        directive_exists = False
        correct_value = False

        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "LimitRequestLine":
                directive_exists = True
                for option in options:
                    if option == "8190":
                        correct_value = True
        if(not directive_exists or not correct_value):
            self.logger.http_line_limited_errmsg()
            finding = True
        else:
            finding = False
        return 0


    def maxclients_set(self):
        directive_exists = False
        correct_value = False

        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "MaxClients":
                directive_exists = True
                for option in options:
                    if(int(option) < 256):
                        correct_value = True
        if(directive_exists and not correct_value):
            self.logger.maxclients_set_errmsg() 
            finding = True
        else:
            finding = False
        return finding

    def symlinks_disabled(self):
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

        if(option_exists and not options_set_none
                and not symlinks_option_disabled):
            self.logger.symlinks_disabled_errmsg() 
            finding = True
        else:
            finding = False
        return finding

    def multiviews_disabled(self):
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
                        multiview_option_disabled = True

        if(option_exists and not options_set_none
                and not multiviews_option_disabled):
            self.logger.multiviews_disabled_errmsg() 
            finding = True
        else:
            finding = False
        return finding

  
    def indexing_disabled(self):
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

        if(option_exists and not options_set_none
                and not indexing_option_disabled):
            self.logger.indexing_disabled_errmsg() 
            finding = True
        else:
            finding = False
        return finding

    def http_message_limited(self):
        directive_exists = False
        correct_value = False
        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "LimitRequestBody":
                directive_exists = True
                options = directive.get_options()
                for option in options:
                    if(int(option) >= 1):
                        correct_value = True
        if(directive_exists and not correct_value):
            self.logger.http_message_limited_errmsg() 
            finding = True
        else:
            finding = False
        return finding


    def http_header_limited(self):
        directive_exists = False
        correct_value = False
        for directive in self.directive_list:
                directive_start = directive.get_directive()
                if directive_start == "LimitRequestFields":
                    directive_exists = True
                    options = directive.get_options()
                    for option in options:
                        if(int(option) >= 1):
                            correct_value = True
        if(directive_exists and not correct_value):
            self.logger.http_header_limited_errmsg() 
            finding = True
        else:
            finding = False
        return finding
    
    def minspareservers_set(self):
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
        if(not directive_exists or not correct_value):
            self.logger.minspareservers_set_errmsg() 
            finding = True
        else:
            finding = False
        return finding


    def startservers_set(self):
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
        if(not directive_exists or not correct_value):
            self.logger.startservers_set_errmsg() 
            finding = True
        else:
            finding = False
        return finding


    def keepalivetimeout_set(self):
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
        if(not directive_exists or not correct_value):
            self.logger.startservers_set_errmsg() 
            finding = True
        else:
            finding = False
        return finding


    def keepalive_set(self):
        directive_exists = False
        correct_value = False
        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "KeepAlive":
                directive_exists = True
                options = directive.get_options()
                for option in options:
                    if(option == "On"):
                        correct_value = True
        if(not directive_exists or not correct_value):
            self.logger.startservers_set_errmsg() 
            finding = True
        else:
            finding = False
        return finding


    def timeout_set(self):
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
        if(not directive_exists or not correct_value):
            self.logger.timeout_set_errmsg() 
            finding = True
        else:
            finding = False
        return finding


    """ Requires directory processing """
    def root_denied(self):
        return 0

    """ Requires directory processing """
    def ports_configured(self):
        return 0
    
    def maxspareservers_set(self):
        directive_exists = False
        correct_value = False
        for directive in self.directive_list:
            directive_start = directive.get_directive()
            if directive_start == "MaxSpareServers":
                directive_exists = True
                options = directive.get_options()
                for option in options:
                    if(int(option) <= 15):
                        correct_value = True
        if(not directive_exists or not correct_value):
            self.logger.maxspareservers_set_errmsg() 
            finding = True
        else:
            finding = False
        return finding

