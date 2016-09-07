import unittest
import sys

sys.path.append('../')

from apache_parser import ApacheParser

class TestConfigParser(unittest.TestCase):

    def setUp(self):
        self.parser = ApacheParser()
    def tearDown(self):
        pass
    def test_load_config1(self):
        pass 
    def test_parse_configuartion1(self):
        pass
    def test_remove_white(self):
        pass
    def test_remove_comments(self):
        pass
    
    

if __name__ == '__main__':
    unittest.main()
