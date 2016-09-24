
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
        

