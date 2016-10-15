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


	
if __name__ == '__main__':
    unittest.main()