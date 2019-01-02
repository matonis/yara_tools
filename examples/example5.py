#!/usr/bin/python

'''
Example 5: Advanced Condition Groups & Community Rules
Note: How to create templates for complex rule types

import "pe"
import "math"

rule susp_file_enumerator_with_encrypted_resource_101 {
		meta:
			copyright = "Kaspersky Lab"
			description = "Generic detection for samples that enumerate files with encrypted resource
			called 101"
			hash = "2cd0a5f1e9bcce6807e57ec8477d222a"
			hash = "c843046e54b755ec63ccb09d0a689674"
			version = "1.4"
		strings:
			$mz = "This program cannot be run in DOS mode."
			$a1 = "FindFirstFile" ascii wide nocase
			$a2 = "FindNextFile" ascii wide nocase
			$a3 = "FindResource" ascii wide nocase
			$a4 = "LoadResource" ascii wide nocase
		condition:
			uint16(0) == 0x5A4D and
			all of them and
			filesize < 700000 and
			pe.number_of_sections > 4 and
			pe.number_of_signatures == 0 and
			pe.number_of_resources > 1 and pe.number_of_resources < 15 and
			for any i in (0..pe.number_of_resources - 1):
			( 	(math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.8) and
				pe.resources[i].id == 101 and
				pe.resources[i].length > 20000 and
				pe.resources[i].language == 0 and
				not ($mz in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length))
			)
}

produces

import "math"
import "pe"

rule kaspersky_stonedrill
{

	strings:
		$a0 = "FindFirstFile"
		$a1 = "FindNextFile"
		$a2 = "FindResource"
		$a3 = "LoadResource"
		$mz = "This program cannot be run in DOS mode."

	condition:
		uint16(0) == 0x5A4D and 
		all of ($a*) and 
		all of ($mz*) and 
		filesize < 700000 and 
		pe.number_of_sections > 4 and 
		pe.number_of_signatures == 0 and 
		pe.number_of_resources > 1 and 
		pe.number_of_resources < 15 and 
		
			for any i in (0..pe.number_of_resources - 1):
			( 	
				((math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.8) and (pe.resources[i].id == 101 and pe.resources[i].length > 20000 and pe.resources[i].language == 0 and not ($mz in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length)))
			)


}


'''
import yara_tools
import yara

resource_strings=['FindFirstFile','FindNextFile','FindResource','LoadResource']
mz="This program cannot be run in DOS mode."

rule=yara_tools.create_rule(name="kaspersky_stonedrill")
rule.add_import(import_name="pe")
rule.add_import(import_name="math")
rule.add_condition(condition="uint16(0) == 0x5A4D")
rule.add_strings(strings=resource_strings,identifier="a",condition="all of ($IDENTIFIER*)")
rule.add_strings(strings=mz,identifier="mz")
rule.add_condition(condition="filesize < 700000")
rule.add_condition(condition="pe.number_of_sections > 4")
rule.add_condition(condition="pe.number_of_signatures == 0")
rule.add_condition(condition="pe.number_of_resources > 1")
rule.add_condition(condition="pe.number_of_resources < 15")

rule.create_condition_group(name="master_for")
rule.create_condition_group(name="entropy_for",parent_group="master_for")
rule.create_condition_group(name="resource_for",parent_group="master_for")
rule.create_condition_group(name="not_mz",parent_group="resource_for",condition_modifier='not')

rule.add_condition(condition="math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.8",condition_group="entropy_for")
rule.add_condition(condition=['pe.resources[i].id == 101',
							'pe.resources[i].length > 20000',
							'pe.resources[i].language == 0'],
							condition_group="resource_for"
							)
rule.add_condition(condition="$mz in (pe.resources[i].offset..pe.resources[i].offset + pe.resources[i].length",
							condition_group="not_mz"
							)

for_loop_format_str="""
			for any i in (0..pe.number_of_resources - 1):
			( 	
				%s
			)
"""

rule.add_condition(condition=for_loop_format_str % rule.get_condition_group(name='master_for'))

generated_rule = rule.build_rule()

try:
	compiled_rule = yara.compile(source=generated_rule)
	print generated_rule
	print "SUCCESS: IT WORKED!"
except Exception as e:
	print "Failed... oh noes! %s" % e
	print generated_rule
