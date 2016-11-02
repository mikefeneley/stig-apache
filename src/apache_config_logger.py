# -*-coding: utf-8 -*-

class ApacheConfigLogger:
    
    def __init__(self, filename="ApacheConfigLog.txt"):
        self.filename = filename
        self.log = open(filename, 'w')
        self.log.write("#########################\n\n")
        self.log.write("Apache Config Audit Findings\n\n")

    def __del__(self):
        self.log.write("#########################\n\n")
        self.log.close()

    def get_filename(self):
        return self.filename

    def ssi_disabled_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-43621r1_rule: ")
            self.log.write("Server side includes (SSIs) must run with execution capability disabled.\n\n")
            self.log.write("To fix: ")
            self.log.write("Add one of the following directives to the apache config file: +IncludesNoExec, -IncludesNoExec, or -Includes.\n\n\n")
    
    def http_header_field_limited_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-32766r2_rule: ")
            self.log.write("The HTTP request header field size must be limited.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the apache config file and ensure the LimitRequestFieldSize is explicitly configured and set to 8190 or other approved value.\n\n\n")
    
    def http_line_limited_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-32768r2_rule: ")
            self.log.write("The HTTP request header field size must be limited.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the apache config file and set the LimitRequestLine to 8190 or other approved value. If no LimitRequestLine directives exist, explicitly add the directive and set to 8190.\n\n\n")

    def maxclients_set_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-36649r2_rule: ")
            self.log.write("The MaxClients directive must be set properly.\n\n")
            self.log.write("To fix: ")
            self.log.write("Set the MaxClients directive to a value of 256 or less, add the directive if it does not exist.\n\n\n")

    def interactive_programs_set_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-36649r2_rule: ")
            self.log.write("All interactive programs must be placed in a designated directory with appropriate permissions.\n\n")
            self.log.write("To fix: ")
            self.log.write("EXPLAIN IT HERE\n\n\n")

    def symlinks_disabled_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-40129r1_rule: ")
            self.log.write("The –FollowSymLinks setting must be disabled.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the apache config file and set the value of FollowSymLinks to -FollowSymLinks.\n\n\n")
    
    def multiviews_disabled_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-32754r1_rule: ")
            self.log.write("The MultiViews directive must be disabled.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the apache config file file and add the - to the MultiViews setting, or set the options directive to None.\n\n\n")

    def indexing_disabled_errmsg(self, result):
       if result == 0:
            self.log.write("Check SV-32755r1_rule: ")
            self.log.write("Directory indexing must be disabled on directories not containing index files.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the apache config file file and add an - to the Indexes setting, or set the options directive to None.\n\n\n")

    def http_message_limited_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-32756r1_rule: ")
            self.log.write("The HTTP request message body size must be limited.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the apache config file and specify a size for the LimitRequestBody directive.\n\n\n")

    def http_header_limited_errmsg(self, result):
        if result == 0:
            self.log.write("SV-32757r1_rule: ")
            self.log.write("The HTTP request header fields must be limited.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the httpd.conf file and set LimitRequestFields Directive to a value greater than 0.\n\n\n")

    def request_methods_limited_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-33236r1_rule: ")
            self.log.write("HTTP request methods must be limited.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the https.conf file and add the following entries for every enabled directory except root: 'Order allow,deny' and 'Deny from all'.\n\n\n")

    def minspareservers_set_errmsg(self, result):
        if result == 0:
            self.log.write("SV-36646r2_rule: ")
            self.log.write("The httpd.conf MinSpareServers directive must be set properly.\n\n")
            self.log.write("To fix: ")
            self.log.write("Set the directive MinSpareServers to a value of between 5 and 10, add the directive if it does not exist.\n\n\n")

    def startservers_set_errmsg(self, result):
        if result == 0:
            self.log.write("SV-36645r2_rule: ")
            self.log.write("The httpd.conf StartServers directive must be set properly.\n\n")
            self.log.write("To fix: ")
            self.log.write("Set the directive StartServers to a value of between 5 and 10, add the directive if it does not exist.\n\n\n")

    def keepalivetimeout_set_errmsg(self, result):
        if result == 0:
            self.log.write("SV-32877r1_rule: ")
            self.log.write("The KeepAliveTimeout directive must be defined.\n\n")
            self.log.write("To fix: ")
            self.log.write("Set the directive KeepAliveTimeout to a value of less than or equal to 15. Add the directive if it does not exist.\n\n\n")

    def keepalive_set_errmsg(self, result):
        if result == 0:
            self.log.write("SV-32844r2_rule: ")
            self.log.write("The KeepAliveTimeout directive must be enabled.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the httpd.conf file and set the value of KeepAlive to On\n\n\n")

    def timeout_set_errmsg(self, result):
        if result == 0:
            self.log.write("SV-32977r1_rule: ")
            self.log.write("Timeout directive not set properly\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the httpd.conf file and set the value of Timeout to 300 seconds or less.\n\n\n")

    def maxspareservers_set_errmsg(self, result):
        if result == 0:
            self.log.write("SV-36648r2_rule: ")
            self.log.write("The MaxSpareServers directive must be set properly.\n\n")
            self.log.write("To fix: ")
            self.log.write("Set the directive to a value of 10 or less, add the directive if it does not exist.\n\n\n")

    def ports_configured_errmsg(self, result):
        if result == 0:
            self.log.write("SV-33228r1_rule: ")
            self.log.write("The web server must be configured to listen on a specific IP address and port.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the httpd.conf file and set the Listen directive to listen on a specific IP address and port.\n\n\n")

    def mime_types_disabled_errmsg(self, result):
        if result == 0:
            self.log.write("SV-36309r2_rule: ")
            self.log.write("MIME types for csh or sh shell programs must be disabled.\n\n")
            self.log.write("To fix: ")
            self.log.write("Disable MIME types for csh or sh shell programs.\n\n\n")       

    def root_denied_errmsg(self, result):
        if result == 0:
            self.log.write("SV-33226r1_rule: ")
            self.log.write("The web server must be configured to explicitly deny access to the OS root.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the httpd.conf file and set the root directory directive as follows: Directory Order deny,allow Deny from all\n\n\n")   

    def url_name_set_errmsg(self, result):
        if result == 0:

            self.log.write("SV-33229r1_rule: ")
            self.log.write("The web server must be configured to explicitly deny access to the OS root.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the httpd.conf file and set the ScriptAlias URL-path and file-path or directory-path entries.\n\n\n")   

    def trace_disabled_errmsg(self, result):
        if result == 0:
            self.log.write("SV-33227r1_rule: ")
            self.log.write("The TRACE method must be disabled.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the httpd.conf file and add or set the value of EnableTrace to Off.\n\n")   

    def override_denied_errmsg(self, result):
        if result == 0:
            self.log.write("SV-33232r1_rule: ")
            self.log.write("The ability to override the access configuration for the OS root directory must be disabled.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the httpd.conf file and add or set the value of AllowOverride to None.\n\n")

    def pid_file_secure_errmsg(self, result):
        if result == 0:
            self.log.write("SV-33222r1_rule: ")
            self.log.write("The process ID (PID) file must be properly secured.\n\n")
            self.log.write("To fix: ")
            self.log.write("Modify the location, permissions, and/or ownership for the PID file folder.\n\n")
