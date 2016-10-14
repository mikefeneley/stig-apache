
class ApacheLogger:
    def __init__(self, filename="ConfigLog.txt"):
        self.filename = filename
        self.log = open(filename, 'w')

    def ssi_disabled_errmsg(self):
        pass
        self.log.write("Server side includes not disabled. ")
        self.log.write("Check SV-32752r1_rule\n") 
        
    def http_header_limited_errmsg(self):
        self.log.write("HTTP headers not size limited. ")
        self.log.write("Check SV-32766r2_rule. \n")
        
    def http_line_limited_errmsg(self):
        self.log.write("HTTP Line LImited not set. ")
        self.log.write("\n")

    def maxclients_set_errmsg(self):
        self.log.write("Maxclients directive not set correctly. ")
        self.log.write("\n")

    def symlinks_disabled_errmsg(self):
        self.log.write("Symlinks not disabled. ")
        self.log.write("Check SV-40129r1_rule. \n")

    def multiviews_disabled_errmsg(self):
        self.log.write("Multiview not disabled. ")
        self.log.write("\n")
    
    def indexing_disabled_errmsg(self):
        self.log.write("Indexing not disabled. ")
        self.log.write("\n")

    def http_message_limited_errmsg(self):
        self.log.write("Http message not limited")
        self.log.write("\n")

    def http_header_limited_errmsg(self):
        self.log.write("Http header not limited")
        self.log.write("\n")

    def minspareservers_set_errmsg(self):        
        self.log.write("Space servers directive not set properly")
        self.log.write("\n")

    def startservers_set_errmsg(self):        
        self.log.write("StartServers directive not set properly")
        self.log.write("\n")

    def keepalive_set_errmsg(self):        
        self.log.write("KeepAlive directive not set properly")
        self.log.write("\n")

    def keepalivetimeout_set_errmsg(self):        
        self.log.write("KeepAliveTimeout directive not set properly")
        self.log.write("\n")

    def timeout_set_errmsg(self):        
        self.log.write("Timeout directive not set properly")
        self.log.write("\n")

    def maxspareservers_set_errmsg(self):
        self.log.write("MaxSpareServers directive not set properly")
        self.log.write("\n")
