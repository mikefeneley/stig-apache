import unittest
import sys

sys.path.append('../')

from apache_config_auditor import ApacheConfigAuditor
from apache_parser import DirectiveInfo
from apache_parser import DirectiveLine

class TestApacheConfigAuditor(unittest.TestCase):


	def test_ssi_disabled1(self):

		empty_list = []
		auditor = ApacheConfigAuditor(empty_list)
		self.assertFalse(auditor.ssi_disabled())

	def test_ssi_disabled2(self):
		"""
		Check case where all Options have value "None"
		"""
		all_none_list = []
		line = DirectiveInfo(DirectiveLine("Options", ["None"]), 0, 'file.txt')		
		all_none_list.append(line)

		auditor = ApacheConfigAuditor(all_none_list)
		self.assertTrue(auditor.ssi_disabled())

	def test_ssi_disabled3(self):
		disabled_list = []
		line = DirectiveInfo(DirectiveLine("Options", ["+IncludesNoExec"]), 0, 'file.txt')		
		disabled_list.append(line)
		
		auditor = ApacheConfigAuditor(disabled_list)
		self.assertTrue(auditor.ssi_disabled())

	def test_ssi_disabled4(self):
		disabled_list = []
		line = DirectiveInfo(DirectiveLine("Options", ["-IncludesNoExec"]), 0, 'file.txt')		
		disabled_list.append(line)
		
		auditor = ApacheConfigAuditor(disabled_list)
		self.assertTrue(auditor.ssi_disabled())

	def test_ssi_disabled5(self):
		disabled_list = []
		line = DirectiveInfo(DirectiveLine("Options", ["-Includes"]), 0, 'file.txt')		
		disabled_list.append(line)
		
		auditor = ApacheConfigAuditor(disabled_list)
		self.assertTrue(auditor.ssi_disabled())

	def test_ssi_disabled6(self):
		disabled_list = []
		line = DirectiveInfo(DirectiveLine("Options", ["+Includes"]), 0, 'file.txt')		
		disabled_list.append(line)
		
		auditor = ApacheConfigAuditor(disabled_list)
		self.assertFalse(auditor.ssi_disabled())

	def test_ssi_disabled7(self):
		disabled_list = []
		line = DirectiveInfo(DirectiveLine("Options", ["None"]), 0, 'file.txt')		
		disabled_list.append(line)
		line = DirectiveInfo(DirectiveLine("Options", ["+Includes"]), 0, 'file.txt')		
		disabled_list.append(line)

		auditor = ApacheConfigAuditor(disabled_list)
		self.assertFalse(auditor.ssi_disabled())

if __name__ == '__main__':
    unittest.main()