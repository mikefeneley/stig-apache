#!/usr/bin/python


DEFAULT = "/etc/apache2/apache2.conf"

#from apache_auditor import ApacheAuditor
from apache_parser import ApacheParser

def main():
    parser = ApacheParser()

    the_list = parser.build_directives_list(DEFAULT)

    for directive in the_list:
    	print directive.get_directive()

	
    #apache_auditor = ApacheAuditor()
    #apache_auditor.audit_apache()
	
    return 0

if __name__ == '__main__':
    main()
