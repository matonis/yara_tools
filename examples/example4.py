#!/usr/bin/python

'''
Example 4: Introducing Condition Groups
Note: Demonstrating how a condition group might be used.

'''
import yara_tools
import yara
import base64
import os
import sys

#::Using calc.exe (MD5: b6b9aca1ac1e3d17877801e1ddcb856e as input)
suspicious_doc_strings = ['_VBA_PROJECT', '_xmlsignatures', 'Macros']
suspicious_exe_strings = [base64.b64encode(bytearray(open(sys.argv[1], 'rb').read()[:16])),
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
                     condition_group="susp_strings",
                     default_boolean="or")

rule.add_strings(strings=suspicious_doc_strings,
                 modifiers=['wide', 'ascii'],
                 comment='Suspicious Document Streams & Indicators',
                 condition_group="malicious_strings",
                 default_boolean="or",
                 condition="1 of ($IDENTIFIER*)")

# rule.create_condition_group(name="all_malicious_strings")
# rule.add_condition(condition=[rule.get_condition_group("susp_strings")])

generated_rule = rule.build_rule(str_condition_groups=True)

try:
    compiled_rule = yara.compile(source=generated_rule)
    print generated_rule
    print "SUCCESS: IT WORKED!"
except Exception as e:
    print "Failed... oh noes! %s" % e
    print generated_rule
