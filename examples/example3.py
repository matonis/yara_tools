#!/usr/bin/python

'''
Example 3: Working With Modules & Condition Groups
Reference Sample: 
b41f586fc9c95c66f0967f1592641a85
887c614608e7cd9a691858caf468c28f
de07c4ac94a50663851e5dabe6e50d1f

import "pe"

rule simple_shamoon
{

	strings:
		$RICH0 = {adbf182de9de767ee9de767ee9de767e86a8e87effde767e86a8dd7ea9de767e86a8dc7e7ade767ece18187ee8de767ece181b7eeade767ee0a6e57ef8de767ee9de777e39de767e86a8d97ee1de767e86a8ec7ee8de767e86a8eb7ee8de767e} //File MD5: 887c614608e7cd9a691858caf468c28f 
		$RICH1 = {f49fb188b0fedfdbb0fedfdbb0fedfdbdf8841dba4fedfdbdf8874db8ffedfdbdf8875db3efedfdbb9864cdba3fedfdbb0fededb38fedfdbdf8870dbb4fedfdbdf8845dbb1fedfdbdf8842dbb1fedfdb} //File MD5: b41f586fc9c95c66f0967f1592641a85 
		$RICH2 = {aa728172ee13ef21ee13ef21ee13ef2181657121fd13ef2181654421d813ef21816545219013ef21e76b7c21ff13ef21ee13ee214013ef2181654021e913ef2181657521ef13ef2181657221ef13ef21} //File MD5: de07c4ac94a50663851e5dabe6e50d1f 

	condition:
		pe.imphash() == '4767fbf3ade8812b0583b2b20cb6dd46' or 
		any of ($RICH*) or 
		pe.imphash() == 'bc0eba48e65cc3ae72091c76f068f3e5' or 
		pe.imphash() == '53e316887bac4e36b2dfef0e711a3d8e'

}

'''
import yara_tools
import yara
import pefile
import os,sys

#::yara_tools
rule=yara_tools.create_rule(name="simple_shamoon")
rule.add_import(name="pe")
rule.set_default_boolean(value='or')

#::loop through folder
WORKING_FOLDER=os.path.expanduser(sys.argv[1])
for filename in os.listdir(WORKING_FOLDER):
	FILE=os.path.join(WORKING_FOLDER,filename)
	PE_OBJ=pefile.PE(FILE)

	#::imphash
	rule.add_condition(condition="pe.imphash() == '%s'" % PE_OBJ.get_imphash())
	
	#::rich header
	rule.add_binary_strings(data=PE_OBJ.RICH_HEADER.raw_data,
							identifier="RICH",
							condition="any of ($IDENTIFIER*)",
							comment="File MD5: %s " % filename) #::files stored as MD5

generated_rule=rule.build_rule()

try:
	compiled_rule=yara.compile(source=generated_rule)
	print generated_rule
	print "SUCCESS: IT WORKED!"
except Exception as e:
	print "Failed... oh noes! %s" % e
	print generated_rule
