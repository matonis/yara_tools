#!/usr/bin/python

'''
Example 1: Simple Hello World Program
Note: 
Output:

rule hello_world
{
	meta:
		author="@matonis"
		purpose="Demonstrating a simple yara_tools rule and how to validate in yara-python"

	strings:
		$x0 = "Yello, World?" wide ascii
		$x1 = "Yello, World!" wide ascii
		$HWORLD = "HelloWorld"
		$r = "Hello World"

	condition:
		any of ($x*) and 
		#HWORLD > 3 and 
		all of ($r*)

}
'''

import yara_tools
import yara

rule=yara_tools.create_rule(name="hello_world")
rule.add_meta(key="author",value="@matonis")
rule.add_meta(key="purpose",value="Demonstrating a simple yara_tools rule and how to validate in yara-python")
rule.add_strings(strings="Hello World")
rule.add_strings(strings=['Yello, World?','Yello, World!'],
				condition="any of ($IDENTIFIER*)",
				modifiers=['wide','ascii'])
rule.add_strings(strings="HelloWorld",
				identifier="HWORLD",
				condition="#IDENTIFIER > 3")

generated_rule=rule.build_rule()

try:
	compiled_rule=yara.compile(source=generated_rule)
	print generated_rule
	print "SUCCESS: IT WORKED!"
except Exception as e:
	print "Failed... oh noes! %s" % e
	print generated_rule