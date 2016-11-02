# -*-coding: utf-8 -*-

DEFAULT_CONFIG = "ApacheSystemLog.txt"

class ApacheSystemLogger:
    """
    ApacheSystemLogger writes error messages to the JRE log file
    for apache system rule in the Apache STIG that is violated
    """
    def __init__(self, filename=DEFAULT_CONFIG):
        self.filename = filename
        self.log = open(filename, 'w')
        self.log.write("#########################\n\n")
        self.log.write("Apache System Audit Findings\n\n")

    def __del__(self):
        self.log.write("#########################\n\n")
        self.log.close()

    def get_filename(self):
        return self.filename

    def is_supported_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-36441r2_rule: ")
            self.log.write("Web server software must be a vendor-supported version.\n\n")
            self.log.write("To fix: ")
            self.log.write("Install the current version of the web server software and maintain appropriate service packs and patches.\n\n\n")

    def is_clean_production_server_errmsg(self, result):
        if result == 0:
            self.log.write("SV-32933r1_rule: ")
            self.log.write("All web server documentation, sample code, example applications, and tutorials must be removed from a production web server.\n\n")
            self.log.write("To fix: ")
            self.log.write("Ensure sample code and documentation have been removed from the web server.\n\n\n")

    def user_access_restricted_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-36456r2_rule: ")
            self.log.write("Administrators must be the only users allowed access to the directory tree, the shell, or other operating system functions and utilities.\n\n")
            self.log.write("To fix: ")
            self.log.write("Ensure non-administrators are not allowed access to the directory tree, the shell, or other operating system functions and utilities.\n\n\n")

    def meets_compiler_restriction(self, result):
        if result == 0:
            self.log.write("Check SV-32956r3_rule: ")
            self.log.write("Installation of a compiler on production web server is prohibited.\n\n")
            self.log.write("To fix: ")
            self.log.write("Remove any compiler found on the production web server.\n\n\n")

    def cgi_files_monitored_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-32927r2_rule: ")
            self.log.write("Monitoring software must include CGI or equivalent programs in its scope.\n\n")
            self.log.write("To fix: ")
            self.log.write("Use a monitoring tool to monitor changes to the CGI or equivalent directory. This can be done with something as simple as a script or batch file that would identify a change in the file.\n\n\n")
   
    def webserver_mod_disabled_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-33218r1_rule: ")
            self.log.write("Web server status module must be disabled.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the httpd.conf file and disable info_module and status_module.\n\n\n")

    def password_file_permissions_set_errmsg(self, result):
       if result == 0:
            self.log.write("Check SV-32927r2_rule: ")
            self.log.write("The web server’s htpasswd files (if present) must reflect proper ownership and permissions.\n\n")
            self.log.write("To fix: ")
            self.log.write("The SA or Web Manager account should own the htpasswd file and permissions should be set to 550.\n\n\n")

    def server_not_proxy_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-33220r1_rule: ")
            self.log.write("The web server must not be configured as a proxy server.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the httpd.conf file and remove the following modules: proxy_module, proxy_ajp_module, proxy_balancer_module proxy_ftp_module, proxy_http_module, proxy_connect_module.\n\n\n")

    def server_segregated_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-32950r1_rule: ")
            self.log.write("The web server must be segregated from other services.\n\n")
            self.log.write("To fix: ")
            self.log.write("Move or install additional services and applications to partitions that are not the operating system root or the web document root.\n\n\n")

    def inbound_email_restricted_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-32937r1_rule: ")
            self.log.write("A public web server must limit email to outbound only.\n\n")
            self.log.write("To fix: ")
            self.log.write("Configure the email application to not allow incoming connections.\n\n\n")

    def user_directories_restricted_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-33221r1_rule: ")
            self.log.write("User specific directories must not be globally enabled.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the httpd.conf file and remove userdir_module.\n\n\n")

    def software_updated_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-32969r2_rule: ")
            self.log.write("The Web site software used with the web server must have all applicable security patches applied and documented.\n\n")
            self.log.write("To fix: ")
            self.log.write("Establish a detailed process as part of the configuration management plan to stay compliant with all web server security-related patches.\n\n\n")

    def server_isolated_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-32932r2_rule: ")
            self.log.write("A public web server, if hosted on the NIPRNet, must be isolated in an accredited DoD DMZ Extension.\n\n")
            self.log.write("To fix: ")
            self.log.write("Logically relocate the public web server to be isolated from internal systems.\n\n\n")


    def certificates_validated_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-32954r2_rule: ")
            self.log.write("The private web server must use an approved DoD certificate validation process.\n\n")
            self.log.write("To fix: ")
            self.log.write("Configure DoD Private Web Servers to conduct certificate revocation checking utilizing certificate revocation lists (CRLs) or Online Certificate Status Protocol (OCSP).\n\n\n")

    def modules_minimized_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-33215r1_rule: ")
            self.log.write("Active software modules must be minimized.\n\n")
            self.log.write("To fix: ")
            self.log.write("Disable any modules that are not needed.\n\n\n")

    def webdav_disabeld_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-33216r1_rule: ")
            self.log.write("Web Distributed Authoring and Versioning (WebDAV) must be disabled.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the httpd.conf file and remove the following modules: dav_module, dav_fs_module, dav_lock_module\n\n\n")

    def export_ciphers_removed_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-75159r1_rule: ")
            self.log.write("The web server must remove all export ciphers from the cipher suite.\n\n")
            self.log.write("To fix: ")
            self.log.write("Update the cipher specification string for all enabled SSLCipherSuite directives to include !EXPORT.\n\n\n")

    def admin_tools_restricted_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-32948r2_rule: ")
            self.log.write("Web administration tools must be restricted to the web manager and the web manager’s designees.\n\n")
            self.log.write("To fix: ")
            self.log.write("Restrict access to the web administration tool to only the web manager and the web manager’s designees.\n\n\n")       

    def scoreboard_file_secured_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-33223r1_rule: ")
            self.log.write("The score board file must be properly secured.\n\n")
            self.log.write("To fix: ")
            self.log.write("The scoreboard file is created when the server starts, and is deleted when it shuts down, set the permissions during the creation of the file.\n\n\n")   

    def directory_indexing_disabled_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-33219r1_rule: ")
            self.log.write("Automatic directory indexing must be disabled.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the httpd.conf file and remove autoindex_module.\n\n\n")   

    def url_pathname_set_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-33229r1_rule: ")
            self.log.write("The URL-path name must be set to the file path name or the directory path name.\n\n")
            self.log.write("To fix: ")
            self.log.write("Edit the httpd.conf file and set the ScriptAlias URL-path and file-path or directory-path entries.\n\n")   

    def backup_process_set_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-32964r2_rule: ")
            self.log.write("Web server content and configuration files must be part of a routine backup program.\n\n")
            self.log.write("To fix: ")
            self.log.write("Document the backup procedures.\n\n")

    def backup_scripts_removed_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-32964r2_rule: ")
            self.log.write("Backup interactive scripts on the production web server are prohibited.\n\n")
            self.log.write("To fix: ")
            self.log.write("Ensure that CGI backup scripts are not left on the production web server.\n\n")

    def utility_programs_removed_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-32955r2_rule: ")
            self.log.write("All utility programs, not necessary for operations, must be removed or disabled. \n\n")
            self.log.write("To fix: ")
            self.log.write("Remove any unnecessary applications.\n\n")

    def users_documented_errmsg(self, result):
        if result == 0:
            self.log.write("Check SV-32951r1_rule: ")
            self.log.write("Administrative users and groups that have access rights to the web server must be documented.\n\n")
            self.log.write("To fix: ")
            self.log.write("Document the administrative users and groups which have access rights to the web server in the web site SOP or in an equivalent document.\n\n")

