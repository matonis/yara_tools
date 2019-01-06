#!/usr/bin/python

'''
Example 6: Demonstrating Very Complex Nested Condition Groups
Note: This is a POC, mostly used for troubleshooting

REMEMBER: WHEN DEFINING CONDITION GROUPS - ORDER MATTERS.

(and it makes your code easier to read/interpret)

Creates:
rule nested_masters
{


	condition:
		(m1 and (pc1 and (bc1) and (c1)) and (pc2 and (bc1) and (c2 and (c4)))) or 
		(m2 and (pc2 and (bc1) and (c2 and (c4)))) or 
		(m3 and (c2 and (c4)))

}
'''

import yara_tools

rule=yara_tools.create_rule(name="nested_masters",default_boolean='or')
rule.create_condition_group(name="m1") 
rule.create_condition_group(name="m2")
rule.create_condition_group(name="m3")
rule.create_condition_group(name="m4",virtual=False) 
rule.create_condition_group(name="pc1",parent_group="m1")
rule.create_condition_group(name="pc2",parent_group=['m1','m2'])
rule.create_condition_group(name="c1",parent_group="pc1")
rule.create_condition_group(name="bc1",parent_group=["pc1",'pc2'])
rule.create_condition_group(name="c2",parent_group=["pc2",'m3'])
rule.create_condition_group(name="c3",parent_group='c2')

rule.add_condition('m1',condition_group='m1')
rule.add_condition('m2',condition_group='m2')
rule.add_condition('m3',condition_group='m3')
rule.add_condition('m4',condition_group='m4')
rule.add_condition("pc1",condition_group="pc1")
rule.add_condition("pc2",condition_group="pc2")
rule.add_condition("c1",condition_group='c1')
rule.add_condition("bc1",condition_group=['bc1','m4'])
rule.add_condition("c2",condition_group='c2')
rule.add_condition("c3",condition_group='c3')


print rule.build_rule(condition_groups=True)