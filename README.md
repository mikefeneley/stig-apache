<b>Update 11/13/2016:</b>

STIG-Apache was originally intended to be a vulnerability checker that checked apache configuration against the recommendations of the STIG guides provided by the DISA. The STIG-Apache used Python implementations of each individual STIG guide to check against the STIG requirements.

According to the NISA, the best way to implement a SCAP, (Security Content Automation Protocol), like STIG-Apache is to use OVAL, (Open Vulnerability and Assessment Language) repository to check the vulnerabilities provided by an XCCDF, (Extensible Configuration Checklist Description Format) and report the misconfigurations back the user.

Because the approach used to start this project is outdated and the correct approach is already impelemented here: https://github.com/OpenSCAP, I am no longer going to continue regular work on this project. I may continue to write new methods in my free time in order to learn about STIG requirements, but it is no longer a personal priority.

If you are interested in working on this project with me, I may be interested if you can provide a good reason to do. If so, please contact me here: mfeneley@vt.edu.

<b>Update 11/26/2016:</b>

Initially this tool was originally intended to just check and report misconfiguations back to the user. However, adding the option to change or add configurations to make the system STIG compliant might help this tool stand out from many of the other STIG tools avaliable.

I am still going to work on extending the number of findings that are supported by the STIG Kit, but I also intend to add configuration change functitonality to the program.

<b>#################################################################</b>

<b>Introduction</b>

The idea behind this project is to create a tool which checks if a
server with Apachev2.2 is configured to meet the requirements of the 
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

<b>Using the Program</b>

The program can be run using the command line. Navigate to the src folder after downloading and execute program with the following command:

<i>python apache_auditor.py</i>

<br>
<br>
<b>Contact:</b>

Michael Feneley: mfeneley(at)vt.edu

