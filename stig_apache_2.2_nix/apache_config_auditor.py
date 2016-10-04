# -*- coding: utf-8 -*-

from apache_logger import ApacheLogger


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
                    for option in options:
                        if(int(option) >= 5 and int(option) <= 10):
                            correct_value = True
        if(not directive_exists or not correct_value):
            self.logger.http_header_limited_errmsg() 
            finding = True
        else:
            finding = False
        return finding



def designated_dir_set():
    return 0




def access_override_disabled():
    return 0

def certificated_authorized():
    return 0

def server_segragated():
    return 0

def compiler_free():
    return 0

def sa_enabeld():
    return 0

def status_mod_disabled():
    return 0

def server_separated():
    return 0

def min_perm_set():
    return 0

def cgi_set():
    return 0

def htpassd_valid():
    return 0

def no_proxy():
    return 0



def startservers_set():
    return 0

def keepalivetimeout_set():
    return 0

def keepalive_set():
    return 0

def timeout_set():
    return 0

def pid_secured():
    return 0

def email_limited():
    return 0

def global_dir_disabled():
    return 0

def software_patched():
    return 0

def server_isolated():
    return 0

def mime_disabled():
    return 0

def ca_process_approved():
    return 0

def modules_minimized():
    return 0

def webdav_disabled():
    return 0

def ciphers_removed():
    return 0

def tools_restriced():
    return 0

def root_denied():
    return 0

def scoreboard_secured():
    return 0

def dir_index_disabled():
    return 0

def pathname_set():
    return 0

def ports_configured():
    return 0

def trace_disabled():
    return 0

def root_options_disabled():
    return 0

def regular_backups_enabled():
    return 0

def backup_scripts_disabled():
    return 0

def utility_disabled():
    return 0

def maxspareservers_set():
    return 0

def server_info_protected():
    return 0

def users_documented():
    return 0

