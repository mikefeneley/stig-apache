The idea behind this project is to create a tool which checks if a
server with Apache v 2.2 is configured to meet the requirements of the 
DISA STIG guide for Apache. 

The offical STIG can be found at the DISA website here:
https://web.nvd.nist.gov/view/ncp/repository/checklistDetail?id=351

The list of requirements this tool will be checking can be found here:
https://www.stigviewer.com/stig/apache_server_2.2unix/2015-06-01/MAC-1_Classified/

This is a personal project, but if anyone else is interested in working with me for fun,
send me an email here: mfeneley@vt.edu

This programed was developed on Ubuntu and will not work on Windows or other Nix OS.

This program checks a subset of the configuration requirements of the DISA Apache STIG. If any of the rules are violated, information about the violated rule is written to a log file for user review.

The subset of rules checked with their corresponding finding id in case of a violation is listed below.

Rule, Finding_ID

SV-32753r1_rule, V-13733
SV-32766r2_rule, V-13738
SV-32768r2_rule, V-13739
SV-36649r2_rule, V-13730
SV-40129r1_rule, V-13732
SV-32754r1_rule, V-13734
SV-32755r1_rule, V-13735
SV-32756r1_rule, V-13736
SV-32757r1_rule, V-13737
SV-36646r2_rule, V-13728
SV-36645r2_rule, V-13727
SV-32877r1_rule, V-13726
SV-32844r2_rule, V-13725
SV-32977r1_rule, V-13724
SV-36648r2_rule, V-13729
SV-33228r1_rule, V-26326
SV-33227r1_rule, V-26325
SV-33232r1_rule, V-26393
