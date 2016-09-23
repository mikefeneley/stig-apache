#/usr/bin/python


DEFAULT = "/etc/apache2/apache2.conf"


from apache_parser import ApacheParser
from apache_config_auditor import ApacheConfigAuditor

def main():
    parser = ApacheParser()

    directive_list = parser.build_directives_list(DEFAULT)

    auditor = ApacheConfigAuditor(directive_list)

    auditor.audit_config()
    
    
	
    return 0

if __name__ == '__main__':
    main()
