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
		$RICH0 = {adbf182de9de767ee9de767ee9de767e86a8e87effde767e86a8dd7ea9de767e86a8dc7e7ade767ece18187ee8de767ece181b7eeade767ee0a6e57ef8de767ee9de777e39de767e86a8d97ee1de767e86a8ec7ee8de767e86a8eb7ee8de767e} //887c614608e7cd9a691858caf468c28f
		$RICH1 = {f49fb188b0fedfdbb0fedfdbb0fedfdbdf8841dba4fedfdbdf8874db8ffedfdbdf8875db3efedfdbb9864cdba3fedfdbb0fededb38fedfdbdf8870dbb4fedfdbdf8845dbb1fedfdbdf8842dbb1fedfdb} //b41f586fc9c95c66f0967f1592641a85
		$RICH2 = {aa728172ee13ef21ee13ef21ee13ef2181657121fd13ef2181654421d813ef21816545219013ef21e76b7c21ff13ef21ee13ee214013ef2181654021e913ef2181657521ef13ef2181657221ef13ef21} //de07c4ac94a50663851e5dabe6e50d1f

	condition:
		(pe.imphash() == '4767fbf3ade8812b0583b2b20cb6dd46' or pe.imphash() == 'bc0eba48e65cc3ae72091c76f068f3e5' or pe.imphash() == '53e316887bac4e36b2dfef0e711a3d8e') or 
		(any of ($RICH*))

}


'''
import yara_tools
import yara
import pefile
import os,sys

#::yara_tools
rule=yara_tools.create_rule(name="simple_shamoon")

rule.add_import(import_name="pe")
rule.create_condition_group(name="imphashes",default_boolean='or')
rule.create_condition_group(name="rich_headers")
rule.set_default_boolean(value='or')

#::Resource names placeholder
RESOURCE_NAMES=set()
RESOURCE_COUNT=set()


#::loop through folder
WORKING_FOLDER=os.path.expanduser(sys.argv[1])
for filename in os.listdir(WORKING_FOLDER):
	FILE=os.path.join(WORKING_FOLDER,filename)
	PE_OBJ=pefile.PE(FILE)

	#::imphash
	rule.add_condition(condition="pe.imphash() == '%s'" % PE_OBJ.get_imphash(),
						condition_group="imphashes")
	
	#::rich header
	rule.add_binary_strings(data=PE_OBJ.RICH_HEADER.raw_data,
							condition_group="rich_headers",
							identifier="RICH",
							condition="any of ($IDENTIFIER*)",
							comment=filename) #::files stored as MD5

	#::loop through resources
	if hasattr(PE_OBJ, 'DIRECTORY_ENTRY_RESOURCE'):
		for resource in PE_OBJ.DIRECTORY_ENTRY_RESOURCE.entries:
			if hasattr(resource, 'directory'):
				RESOURCE_COUNT.add(len(resource.directory.entries))
				for e in resource.directory.entries:
					if e.name:
						RESOURCE_NAMES.add(str(e.name))
'''
rule.add_strings(strings=list(RESOURCE_NAMES),
				condition_group='low_confidence_iocs',
				modifiers='wide',
				condition="all of ($IDENTIFIER*)"
				)
'''
rule.add_condition(condition=rule.get_condition_group(name="imphashes"))
rule.add_condition(condition=rule.get_condition_group(name="RICH"))

generated_rule=rule.build_rule(str_condition_groups=True)

try:
	compiled_rule=yara.compile(source=generated_rule)
	print generated_rule
	print "SUCCESS: IT WORKED!"
except Exception as e:
	print "Failed... oh noes! %s" % e
	print generated_rule
