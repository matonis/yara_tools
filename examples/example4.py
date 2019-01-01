#!/usr/bin/python

'''
Example 4: Introducing Condition Groups
Note: Demonstrating how a condition group might be used.

wtf
rule suspicious_doc_file
{

	strings:
		$k0 = "_VBA_PROJECT" wide ascii //Suspicious Document Streams & Inidicators
		$k1 = "_xmlsignatures" wide ascii //Suspicious Document Streams & Inidicators
		$k2 = "Macros" wide ascii //Suspicious Document Streams & Inidicators
		$SUSPICIOUS_STR0 = "TVqQAAMAAAAEAAAA" wide ascii nocase //Obvious EXE strings
		$SUSPICIOUS_STR1 = "This program cannot be run in DOS mode" wide ascii nocase //Obvious EXE strings
		$f0 = "WordDocument" wide //Directory Entries
		$f1 = "SummaryInformation" wide //Directory Entries
		$f2 = "CompObj" wide //Directory Entries

	condition:
		(uint32(0x00) == 0xe011cfd0) and 
		(uint32(0x00) == 0xe011cfd0 and any of ($f*))

}


'''
import yara_tools
import yara
import base64
import os
import sys

#::Using calc.exe (MD5: b6b9aca1ac1e3d17877801e1ddcb856e as input)
suspicious_doc_strings = ['_VBA_PROJECT', '_xmlsignatures', 'Macros']
suspicious_exe_strings = [base64.b64encode(bytearray(open(sys.argv[1], 'rb').read()))[:16],
						'This program cannot be run in DOS mode']

rule = yara_tools.create_rule(name="suspicious_doc_file")
rule.create_condition_group(name="is_a_doc", default_boolean="and")
rule.add_condition(condition="uint32(0x00) == 0xe011cfd0",
				   condition_group="is_a_doc")

rule.add_strings(strings=['WordDocument', 'SummaryInformation', 'CompObj'],
				modifiers='wide',
				comment="Directory Entries",
				condition="any of ($IDENTIFIER*)",
				condition_group="is_a_doc")


for s in suspicious_exe_strings:
	rule.add_strings(strings=s,
					modifiers=['wide', 'ascii', 'nocase'],
					comment='Obvious EXE strings',
					identifier="SUSPICIOUS_STR",
					condition="1 of ($IDENTIFIER*)",
					condition_group="susp_exe",
					default_boolean="or"
					)

rule.add_strings(strings=suspicious_doc_strings,
				modifiers=['wide', 'ascii'],
				comment='Suspicious Document Streams & Inidicators',
				condition_group="susp_streams",
				default_boolean="or",
				condition="any of ($IDENTIFIER*)")


# rule.create_condition_group(name="all_malicious_strings")
rule.add_condition(condition=rule.get_condition_group("is_a_doc"))

generated_rule = rule.build_rule(str_condition_groups=True)

try:
	compiled_rule = yara.compile(source=generated_rule)
	print generated_rule
	print "SUCCESS: IT WORKED!"
except Exception as e:
	print "Failed... oh noes! %s" % e
	print generated_rule
