yara_tools
===========

Python bindings to author YARA rules using natural Python conventions instead of format strings. Additional features to automate and appropriately describe YARA rules programatically.  If YARA is the *"pattern matching swiss [Army] knife"* of the binary world, then *yara_tools* is the **butter knife** of signature generation! 

*"But hold on, @matonis... isn't a butter knife just a utensil used to cut a sliver of cold butter and then aggressively wipe it on a crusty piece of bread?"* 

**WRONG!** 
Did you know that a household butter knife can be used as:
* A wedge
* A flat-head screwdriver
* A Phillips screwdriver *(if held at an angle)*
* A repair tool for a screen door
* A knife?

**yara_tools**, as its name implies, is a tool. This format string (the one many of you use in your scripts)  is not a tool:

```python
	print "rule %s\n{\n\tstrings:\n\t%s\n\tcondition:\n\t%s\n\n}" % (name,strings,condition)
```
There has to be a better way.

### Installation
```bash
python setup.py build && sudo python setup.py install
```
### Be Advised
*yara_tools* has no concept of enforcing YARA rules or conventions. It simply creates a properly-formatted YARA rule for you using standard nomenclature. Legal terms & definitions are responsibility of the user. 

For more information on authoring YARA rules, please [read the docs.](https://yara.readthedocs.io/en/v3.8.1/gettingstarted.html)

*yara-python* is highly advised to be used in parallel with *yara_tools*.

### Usage
*yara_tools* has facilities for four primary aspects of a YARA rule:

* Imports
* Includes
* Strings
* Conditions

Example:
```python
import yara_tools
import yara

rule=yara_tools.create_rule(name="x86_pe")
rule.add_import(import_name="pe")
rule.add_meta(key="author",value="matonis")
rule.add_condition(condition="uint16(0x00) == 0x5a4d")
rule.set_default_boolean(value="and")
rule.add_strings(strings="This program cannot",modifiers=['wide','ascii','nocase'])
my_rule=rule.build_rule()
try:
	compiled_rule=yara.compile(source=my_rule)
	print my_rule
	print "SUCCESS: IT WORKED!"
except Exception as e:
	print "Failed... oh noes! %s" % e
	print my_rule
```

**Getting Started**

Begin by importing yara_tools:
```python
import yara_tools
```

A parent "rule object" is created using the following method. All aspects of a rule are controlled via this object.

```python
rule=yara_tools.create_rule(name="my_rule")
```

**Imports**

```python
rule.add_import(import_name="pe")
rule.add_import(import_name="cuckoo")
rule.add_import(import_name="my_custom_package")
```
**Includes**

```python
rule.add_include(include_name="other_rule.yar")
```

**Meta**

Meta fields in YARA are completely arbitrary. Add as many as you would like.
```python
rule.add_meta(key="author",value="matonis")
rule.add_meta(key="purpose",value="Testing my first yara_tools YARA rule!")
```

**Strings**

yara_tools allows for creation of traditional string constants and is controlled through the ***add_strings*** function. 

Simple usage of *add_strings*
```python
rule.add_strings(strings="MyStringToFind")
```
* In this example, this string will be issued a random variable name later used in a condition. *add_strings* can be overloaded with the following parameters which provide additional control and labeling of the rule.

A more complex example:
```python
rule.add_strings(strings=['MyStringToFind2','ATimeToFindAString','ThirdTimes A Charm'],modifiers=['wide','ascii','nocase'],comment="Testing Inline Comments",condition="2 of ($IDENTIFIER*)")
```
* The *strings* parameter can be overloaded with a list. In this case, all strings are treated as one group.
* The *modifiers* parameter can be a list or string and is used to modify strings in the rule.
* The *comment* parameter is used to provide a comment to the string in-line.
* The *condition* parameter is used to establish an arbitrary condition. A reserved word "IDENTIFIER" is used to give the author flexibility for the condition they wish to assign to a group of strings.

Since strings are issued at random, more control over the identifier can be controlled inline:

```python
rule.add_strings(strings=['MyStringToFind2','ATimeToFindAString','ThirdTimes A Charm'],modifiers=['wide','ascii','nocase'],comment="Testing Inline Comments",identifier="TESTING",condition="2 of ($IDENTIFIER*)")
```
* In this example, all strings will be identified with the $TESTING prefix.

**Binary Strings**

*yara_tools* has support for binary data blobs which are translated into hex-strings. Parameters used in add_strings also apply to those used in *add_binary_strings*.

```python
rule.add_binary_strings(data=open(sys.argv[1],'rb').read())
```

Size limits can also be applied via the *add_binary_strings* method.

```python
rule.add_binary_strings(data=open(sys.argv[1],'rb').read(),comment="Applying size limits",size_limit=5)
```

**Conditions**

Conditions created via *add_condition* are order-based when compiled. It is recommended to apply file-based constraints/conditions prior to strings.
* If a condition was provided inline to a string via *add_strings* or *add_binary_strings* then no control is needed as these carry priority.

```python
rule.add_condition(condition="uint16(0x00) == 0x5a4d")
```


Programatic logic may dictate a default boolean condition for a rule if multiple string identifiers are utilized. These can be controlled via the following function:

```python
rule.set_default_boolean(value="or") #::Default value is 'and'
```

A default condition exists within *yara_tools*, it is 'all of them.' Programmatic logic may trump all of your work. In this case, an authoritative condition can be set which trumps all prior procedures:

```python
rule.add_authoritative_condition(condition="any of them")
```

**Building A Rule**

Rules are built in *yara_tools* only if strings or a condition is present. A string-based rule is returned via:

```python
rule.build_rule()
```

## Fun Facts
Here are some fun facts about yara_tools.
 * As of this writing, yara_tools is almost four years old! It was first created as a sub-project to version 2 of github.com/matonis/ripPE. ripPEv2 is an entire rewrite which was never released... and probably never will be! Wanna parse authenticode certs and automatically create YARA rules on them and so much more? Bribe me.
 * yara_tools was once referred to as *"too meta"* by one of the key developers behind YARA!
 * The author of yara_tools has no idea why they even wasted their time on this project. *See method "ret_complete_rule"*
