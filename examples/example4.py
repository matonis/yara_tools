#!/usr/bin/python

'''
Example 4: Introducing Condition Groups
Note: Creating a rule to hunt for documents

rule doc_exe_with_macros
{

	strings:
		$EXE0 = "TVqQAAMAAAAEAAAA" wide ascii nocase
		$EXE1 = "4d5a90000300000004000000ffff0000" wide ascii nocase
		$EXE2 = "This program cannot be run in DOS mode" wide ascii nocase
		$SOCIAL_ENGINEER0 = "enable macro" wide ascii nocase
		$SOCIAL_ENGINEER1 = "please" wide ascii nocase
		$SOCIAL_ENGINEER2 = "kindly" wide ascii nocase
		$DIRECTORY_ENTRY0 = "WordDocument" wide
		$DIRECTORY_ENTRY1 = "SummaryInformation" wide
		$DIRECTORY_ENTRY2 = "CompObj" wide

	condition:
		(uint32(0x00) == 0xe011cfd0 or 2 of ($DIRECTORY_ENTRY*)) and 
		(any of ($SOCIAL_ENGINEER*) and (any of ($EXE*)))

}

'''
import yara_tools
import yara
import base64
import os
import sys
import binascii

#::Using calc.exe (MD5: b6b9aca1ac1e3d17877801e1ddcb856e as input)
EXE=bytearray(open(sys.argv[1], 'rb').read())
BASE64_EXE=base64.b64encode(EXE)

suspicious_doc_strings = ['_VBA_PROJECT', '_xmlsignatures', 'Macros']
common_directory_entries = ['WordDocument','SummaryInformation','CompObj']
suspicious_exe_strings = [BASE64_EXE[:16],binascii.hexlify(EXE[:16]),'This program cannot be run in DOS mode']

#::Create our rule
rule=yara_tools.create_rule(name="doc_exe_with_macros")
rule.set_default_boolean(value="and")

#::Condition Group 1 - Things that tell us this is a doc
rule.create_condition_group(name="is_doc",default_boolean="or")
rule.add_condition(condition="uint32(0x00) == 0xe011cfd0",condition_group="is_doc")

#::Loop through directory entries and add to group
for entry in common_directory_entries:
	rule.add_strings(strings=entry,
					modifiers='wide',
					identifier="DIRECTORY_ENTRY",
					condition="2 of ($IDENTIFIER*)",
					condition_group="is_doc")

#::Condition Group 2 - Checking for suspicious strings
rule.create_condition_group(name="doc_iocs",default_boolean='and')
rule.add_strings(strings=['enable macro','please','kindly'],
				modifiers=['wide','ascii','nocase'],
				identifier="SOCIAL_ENGINEER",
				condition="any of ($IDENTIFIER*)",
				condition_group="doc_iocs"
				)

#::Condition Group 3 - Nested under Condition Group 2, checking for executable strings
for exe_str in suspicious_exe_strings:
	rule.add_strings(strings=exe_str,
					modifiers=['wide','ascii','nocase'],
					condition="any of ($IDENTIFIER*)",
					identifier="EXE",
					condition_group="exe_iocs",
					default_boolean="or",
					parent_group="doc_iocs")

generated_rule = rule.build_rule(condition_groups=True)

try:
	compiled_rule = yara.compile(source=generated_rule)
	print generated_rule
	print "SUCCESS: IT WORKED!"
except Exception as e:
	print "Failed... oh noes! %s" % e
	print generated_rule
