#!/usr/bin/python

'''
Example 2: Demonstrating Analysis Workflows
Notes: Demonstrates binary strings, comments, order of conditions
Output:
rule more_xor
{

	strings:
		$xorstring0 = {546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f6465} //XOR Key 0x0
		$xorstring1 = {556968722171736e6673606c2162606f6f6e752163642173746f21686f21454e52216c6e6564} //XOR Key 0x1
		$xorstring2 = {566a6b712272706d6570636f2261636c6c6d762260672270776c226b6c22464d51226f6d6667} //XOR Key 0x2
		$xorstring3 = {576b6a702373716c6471626e2360626d6d6c772361662371766d236a6d23474c50236e6c6766} //XOR Key 0x3
		$xorstring4 = {506c6d772474766b637665692467656a6a6b702466612476716a246d6a24404b5724696b6061} //XOR Key 0x4
		$xorstring5 = {516d6c762575776a627764682566646b6b6a712567602577706b256c6b25414a5625686a6160} //XOR Key 0x5
		$xorstring6 = {526e6f75267674696174676b2665676868697226646326747368266f6826424955266b696263} //XOR Key 0x6
	...
		$xorstring254 = {aa96978dde8e8c91998c9f93de9d9f9090918ade9c9bde8c8b90de9790debab1adde93919a9b} //XOR Key 0xfe
		$xorstring255 = {ab97968cdf8f8d90988d9e92df9c9e9191908bdf9d9adf8d8a91df9691dfbbb0acdf92909b9a} //XOR Key 0xff

	condition:
		uint32(0x00) == 0xe011cfd0 and 
		any of ($xorstring*)

'''
import yara_tools
import yara

EXECUTABLE_STRING="This program cannot be run in DOS mode"
rule=yara_tools.create_rule(name="more_xor")
rule.add_condition(condition="uint32(0x00) == 0xe011cfd0")

for xor_key in range(256):
	xored_string=""
	for c in EXECUTABLE_STRING:
		xored_string+=chr(ord(c)^xor_key)
	
	rule.add_binary_strings(data=xored_string,
							comment="XOR Key %s" % hex(xor_key),
							identifier="xorstring",
							condition="any of ($IDENTIFIER*)")

generated_rule=rule.build_rule()

try:
	compiled_rule=yara.compile(source=generated_rule)
	print generated_rule
	print "SUCCESS: IT WORKED!"
except Exception as e:
	print "Failed... oh noes! %s" % e
	print generated_rule

