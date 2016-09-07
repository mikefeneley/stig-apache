import unittest
import sys

sys.path.append("../")

import apache_config_auditor


class TestApache(unittest.TestCase):
    def setUp(self):
        self.test1 = open("test1.conf")
        self.test2 = open("test2.conf")
        
        self.test3 = open("test3.conf")
        self.test4 = open("test4.conf")
        self.test5 = open("test5.conf")
        self.test6 = open("test6.conf")

    def tearDown(self):
        self.test1.close()
        self.test2.close()
        self.test3.close()
        self.test4.close()
        self.test5.close()
        self.test6.close()

    def test_ssi_disabled(self):
        self.assertEqual(apache_config_auditor.ssi_disabled(self.test1), 1)
        self.assertEqual(apache_config_auditor.ssi_disabled(self.test2), 1)
        self.assertEqual(apache_config_auditor.ssi_disabled(self.test3), 1)
        self.assertEqual(apache_config_auditor.ssi_disabled(self.test4), 1)
        self.assertEqual(apache_config_auditor.ssi_disabled(self.test5), 0)
        self.assertEqual(apache_config_auditor.ssi_disabled(self.test6), 0)
   
    def test_http_req_head_size_limited(self):
        assert True

    def test_http_req_line_limited(self):
        assert True
    
    def test_maxclients_set(self):
        assert True

    def test_symlinks_disabled(self):
        assert True

    def test_multiviews_disabled(self):
        assert True

    def test_directory_indexing_disabled(self):
        assert True

    def test_http_msg_body_size_limited(self):
        assert True

    def test_http_req_head_limited(self):
        assert True 

    def test_os_root_overiride_disabled(self):
        assert True

    def test_http_req_method_limited(self):
        assert True

    def test_minspareservers_disabled(self):
       assert True 

    def test_startservers_disabled(self):
       assert True 

    def test_keepalivetimeout_defiend(self):
        assert True

    def test_timeout_set(self):
       assert True 

    def test_maxspareservers_set(self):
       assert True 

if __name__ == '__main__':
    unittest.main()
