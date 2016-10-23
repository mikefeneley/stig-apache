import unittest
import sys

sys.path.append('../')

from apache_config_auditor import ApacheConfigAuditor
from apache_parser import DirectiveInfo
from apache_parser import DirectiveLine


class TestApacheConfigAuditor(unittest.TestCase):
    def test_ssi_disabled1(self):

        test_list = []
        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.ssi_disabled())

    def test_ssi_disabled2(self):
        """
        Check case where all Options have value "None"
        """
        test_list = []
        line = DirectiveInfo(DirectiveLine("Options", ["None"]), 0, 'file.txt')
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.ssi_disabled())

    def test_ssi_disabled3(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("Options", ["+IncludesNoExec"]), 0, 'file.txt')
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.ssi_disabled())

    def test_ssi_disabled4(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("Options", ["-IncludesNoExec"]), 0, 'file.txt')
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.ssi_disabled())

    def test_ssi_disabled5(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("Options", ["-Includes"]), 0, 'file.txt')
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.ssi_disabled())

    def test_ssi_disabled6(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("Options", ["+Includes"]), 0, 'file.txt')
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.ssi_disabled())

    def test_ssi_disabled7(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("Options", ["None"]), 0, 'file.txt')
        test_list.append(line)
        line = DirectiveInfo(DirectiveLine("Options", ["+Includes"]), 0, 'file.txt')
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.ssi_disabled())

    def test_http_header_field_limited1(self):
        test_list = []

        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.http_header_field_limited())

    def test_http_header_field_limited2(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("LimitRequestFieldSize", ["-1"]), 0, 'file.txt')
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.http_header_field_limited())

    def test_http_header_field_limited3(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("LimitRequestFieldSize", ["8190"]), 0, 'file.txt')
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.http_header_field_limited())

    def test_http_line_limited1(self):
        test_list = []

        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.http_line_limited())

    def test_http_line_limited2(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("LimitRequestLine", ["-1"]), 0, 'file.txt')
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.http_header_field_limited())

    def test_http_line_limited3(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("LimitRequestLine", ["8190"]), 0, 'file.txt')
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.http_line_limited())

    def test_maxclients_set1(self):
        test_list = []

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.maxclients_set())

    def test_maxclients_set2(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("MaxClients", ["300"]), 0, 'file.txt')
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.maxclients_set())

    def test_maxclients_set3(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("MaxClients", ["22"]), 0, 'file.txt')
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.maxclients_set())

    def test_symlinks_disabled1(self):
        test_list = []

        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.symlinks_disabled())

    def test_symlinks_disabled2(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("Options", ["None"]), 0, 'file.txt')
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.symlinks_disabled())

    def test_symlinks_disabled3(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("Options", ["-FollowSymLinks"]), 0, 'file.txt')
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.symlinks_disabled())

    def test_symlinks_disabled4(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("Options", ["+FollowSymLinks"]), 0, 'file.txt')
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.symlinks_disabled())

    
    def test_multiviews_disabled1(self):
        test_list = []
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.multiviews_disabled())

    def test_multiviews_disabled2(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("Options", ["None"]), 0, 'file.txt')         
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.multiviews_disabled())


    def test_multiviews_disabled3(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("Options", ["+Multiview"]), 0, 'file.txt')           
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.multiviews_disabled())
    

    def test_multiviews_disabled4(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("Options", ["-Multiview"]), 0, 'file.txt')           
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.multiviews_disabled())

    def test_indexing_disabled1(self):
        test_list = []
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.indexing_disabled())

    def test_indexing_disabled2(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("Options", ["None"]), 0, 'file.txt')         
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.indexing_disabled())


    def test_indexing_disabled3(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("Options", ["+Indexes"]), 0, 'file.txt')           
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.indexing_disabled())
    

    def test_indexing_disabled4(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("Options", ["-Indexes"]), 0, 'file.txt')           
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.indexing_disabled())

    def test_http_message_limited1(self):
        test_list = []
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.http_message_limited())
    
    def test_http_message_limited2(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("LimitRequestBody", ["0"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.http_message_limited())
    
    def test_http_message_limited3(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("LimitRequestBody", ["1"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.http_message_limited())

    def test_http_message_limited4(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("LimitRequestBody", ["2"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.http_message_limited())

    def test_http_header_limited1(self):
        test_list = []
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.http_header_limited())
    
    def test_http_header_limited2(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("LimitRequestFields", ["0"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.http_header_limited())
    
    def test_http_header_limited3(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("LimitRequestFields", ["1"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.http_header_limited())

    def test_http_header_limited4(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("LimitRequestFields", ["2"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.http_header_limited())


    def test_minspareservers_set1(self):
        test_list = []

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.minspareservers_set())

    def test_minspareservers_set2(self):
        test_list = []
        
        line = DirectiveInfo(DirectiveLine("MinSpareServers", ["4"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.minspareservers_set())

    def test_minspareservers_set3(self):
        test_list = []
        
        line = DirectiveInfo(DirectiveLine("MinSpareServers", ["5"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.minspareservers_set())

    def test_minspareservers_set4(self):
        test_list = []
        
        line = DirectiveInfo(DirectiveLine("MinSpareServers", ["6"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.minspareservers_set())


    def test_minspareservers_set5(self):
        test_list = []
        
        line = DirectiveInfo(DirectiveLine("MinSpareServers", ["10"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.minspareservers_set())

    def test_minspareservers_set6(self):
        test_list = []
        
        line = DirectiveInfo(DirectiveLine("MinSpareServers", ["11"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.minspareservers_set())



    def test_startservers_set_set1(self):
        test_list = []

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.startservers_set())

    def test_startservers_set_set2(self):
        test_list = []
        
        line = DirectiveInfo(DirectiveLine("StartServers", ["4"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.startservers_set())

    def test_startservers_set_set3(self):
        test_list = []
        
        line = DirectiveInfo(DirectiveLine("StartServers", ["5"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.startservers_set())

    def test_startservers_set_set4(self):
        test_list = []
        
        line = DirectiveInfo(DirectiveLine("StartServers", ["6"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.startservers_set())

    def test_startservers_set_set5(self):
        test_list = []
        
        line = DirectiveInfo(DirectiveLine("StartServers", ["10"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.startservers_set())

    def test_startservers_set_set6(self):
        test_list = []
        
        line = DirectiveInfo(DirectiveLine("StartServers", ["11"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.startservers_set())

    def test_keepalivetimeout_set1(self):
        test_list = []
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.keepalivetimeout_set())

    def test_keepalivetimeout_set2(self):
        test_list = []

        line = DirectiveInfo(DirectiveLine("KeepAliveTimeout", ["15"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.keepalivetimeout_set())

    def test_keepalivetimeout_set3(self):
        test_list = []

        line = DirectiveInfo(DirectiveLine("KeepAliveTimeout", ["14"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.keepalivetimeout_set())\

    def test_keepalivetimeout_set4(self):
        test_list = []

        line = DirectiveInfo(DirectiveLine("KeepAliveTimeout", ["16"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.keepalivetimeout_set())


    def test_keepalive_set1(self):
        test_list = []

        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.keepalive_set())
    
    def test_keepalive_set1(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("KeepAlive", ["On"]), 0, 'file.txt')           
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.keepalive_set())

    def test_keepalive_set2(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("KeepAlive", ["Off"]), 0, 'file.txt')           
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.keepalive_set())

    def test_timeout_set1(self):
        test_list = []
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.timeout_set())

    def test_timeout_set2(self):
        test_list = []

        line = DirectiveInfo(DirectiveLine("Timeout", ["300"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.timeout_set())


    def test_timeout_set3(self):
        test_list = []

        line = DirectiveInfo(DirectiveLine("Timeout", ["299"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.timeout_set())

    def test_timeout_set4(self):
        test_list = []

        line = DirectiveInfo(DirectiveLine("Timeout", ["301"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.timeout_set())


    def test_maxspareservers_set1(self):
        test_list = []

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.maxspareservers_set())

    def test_maxspareservers_set2(self):
        test_list = []
        
        line = DirectiveInfo(DirectiveLine("MaxSpareServers", ["10"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.maxspareservers_set())

    def test_maxspareservers_set3(self):
        test_list = []
        
        line = DirectiveInfo(DirectiveLine("MaxSpareServers", ["11"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.maxspareservers_set())

    def test_maxspareservers_set4(self):
        test_list = []
        
        line = DirectiveInfo(DirectiveLine("MaxSpareServers", ["9"]), 0, 'file.txt')           
        test_list.append(line)
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.maxspareservers_set())


    def test_ports_configured1(self):
        test_list = []
        
        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.ports_configured())

    def test_ports_configured2(self):
        test_list = []
        

        line = DirectiveInfo(DirectiveLine("Listen", ["[0:0:0:0:0:0:1]:1"]), 0, 'file.txt')           
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertTrue(auditor.ports_configured())


    def test_ports_configured3(self):
        test_list = []
        
        line = DirectiveInfo(DirectiveLine("Listen", ["0.0.0.0"]), 0, 'file.txt')           
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.ports_configured())


    def test_is_valid_address(self):
        auditor = ApacheConfigAuditor()

        address1 = "0.0.0.0"
        address2 = "0.0.0.0:0"
        address3 = "0.0.0.1:0"
        address4 = "1.1.1.1"

        address5 = "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]"
        address6 = "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:3"

        address8 = "[0:0:0:0:0:0:0]:1" # How to check.
        address9 = "[::1]"
        address10 = "[::]"
        address11 = "[::]:20"
        address12 = "[::1]:20"

        self.assertFalse(auditor.is_valid_address(address1))
        self.assertFalse(auditor.is_valid_address(address2))
        self.assertTrue(auditor.is_valid_address(address3))
        self.assertFalse(auditor.is_valid_address(address4))

        self.assertFalse(auditor.is_valid_address(address5))
        self.assertTrue(auditor.is_valid_address(address6))
        self.assertFalse(auditor.is_valid_address(address8))

        self.assertFalse(auditor.is_valid_address(address9))
        self.assertFalse(auditor.is_valid_address(address10))
        self.assertFalse(auditor.is_valid_address(address11))
        self.assertTrue(auditor.is_valid_address(address12))

    
    def test_override_denied1(self):
        test_list = []

        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.override_denied())


    def test_override_denied2(self):
        test_list = []
        line = DirectiveInfo(DirectiveLine("<Directory", ["/>"]), 0, 'file.txt')           
        test_list.append(line)
        line = DirectiveInfo(DirectiveLine("AllowOverride", ["All"]), 0, 'file.txt')           
        test_list.append(line)
        line = DirectiveInfo(DirectiveLine("</Directory>", [""]), 0, 'file.txt')           
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)
        self.assertFalse(auditor.override_denied())
    
    
    def test_override_denied3(self):

        test_list = []
        auditor = ApacheConfigAuditor(test_list)

        line = DirectiveInfo(DirectiveLine("<Directory", ["/>"]), 0, 'file.txt')           
        test_list.append(line)
        line = DirectiveInfo(DirectiveLine("AllowOverride", ["None"]), 0, 'file.txt')           
        test_list.append(line)
        line = DirectiveInfo(DirectiveLine("</Directory>", [""]), 0, 'file.txt')           
        test_list.append(line)

        auditor = ApacheConfigAuditor(test_list)

        self.assertTrue(auditor.override_denied())
    


if __name__ == '__main__':
    unittest.main()
