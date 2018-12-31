#!/usr/bin/python

'''
Example 4: Introducing Condition Groups
Note: Demonstrating how a condition group might be used.

'''
import yara_tools
import yara
import base64

suspicious_strings=[]

exe_as_base64=base64.b64encode(bytearray(open(sys.argv[1],'rb')[:16]))
suspicious_strings.append(exe_as_base64)
suspicious_strings.append("This program cannot be run in DOS mode")

rule=yara_tools.create_rule(name="suspicios_doc_file")
rule.create_condition_group(name="is_a_doc",default_boolean="and")
rule.add_condition(condition="uint32(0x00) == 0xe011cfd0",condition_group="is_a_doc")
rule.add_strings(strings=['WordDocument','SummaryInformation','CompObj'],
					modifiers='wide',
					comment="Directory Entries",
					condition="any of ($IDENTIFIER*)",
					condition_group="is_a_doc")


for s in suspicious_strings:
	rule.add_strings(strings=["This program cannot be run in DOS mode",exe_as_base64],
					modifiers=['wide','ascii','nocase'],
					comment='Obvious EXE strings',
					condition_group="susp_strings",
					default_boolean="or")




generated_rule=rule.build_rule()

try:
	compiled_rule=yara.compile(source=generated_rule)
	print generated_rule
	print "SUCCESS: IT WORKED!"
except Exception as e:
	print "Failed... oh noes! %s" % e
	print generated_rule

