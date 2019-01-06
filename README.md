yara_tools
===========

Python bindings to author YARA rules using natural Python conventions instead of format strings. Additional features to automate and appropriately describe YARA rules programatically.  If YARA is the *"pattern matching swiss [Army] knife"* of the binary world, then *yara_tools* is the **butter knife** of signature generation! 

*"But hold on, @matonis... isn't a butter knife only a utensil used to cut a sliver of cold butter which is then aggressively wiped on a crusty piece of bread?"* 

**WRONG!** 
Did you know that a household butter knife can be used as:
* A wedge
* A flat-head screwdriver
* A Phillips screwdriver *(if held at an angle)*
* A repair tool for a screen door
* A knife?

Like a butter knife, yara_tools has multiple features to help streamline signature generation. It can't do everything, but it can do _most_ things.


### Be Advised
*yara_tools* has no concept of enforcing YARA rules or conventions. It simply creates a properly-formatted YARA rule for you using standard nomenclature. Legal terms & definitions are responsibility of the user. 

For more information on authoring YARA rules, please [read the docs.](https://yara.readthedocs.io/en/v3.8.1/gettingstarted.html)

*yara-python* is highly advised to be used in parallel with *yara_tools*.

### Installation
```bash
python setup.py build && sudo python setup.py install
```

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
rule.add_import(name="pe")
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
**Visual Tutorial**
![Visual Guide](https://github.com/matonis/yara_tools/blob/alpha_release/yara_tools_visual_guide.png)

**Getting Started**

Begin by importing yara_tools:
```python
import yara_tools
```

A parent "rule object" is created using the following method. All aspects of a rule are controlled via this object.

```python
rule=yara_tools.create_rule(name="my_rule")
```

*create_rule()* takes a number of parameters which assist in aspects of a rule.
* _default_boolean_ - Default global condition operator
* _default_condition_ - Default condition if no condition present. Default "all of them"
* _default_identifier_ - Default string identifier.
* _default_str_condition_ - Default condition prefix with strings. Default "all of"
* _global_rule_ - Boolean if global rule
* _identifier_template_ - String reference for condition templates in strings. Default "IDENTIFIER"
* _imports_ - String or List to import reference.
* _includes_ - String or List to include reference.
* _private_rule_ -  Boolean if private rule
* _tags_ - String or List to include tags.


**Imports**

```python
rule.add_import(name="pe")
rule.add_import(name="cuckoo")
rule.add_import(name="my_custom_package")
```
**Includes**

```python
rule.add_include(value="other_rule.yar")
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
rule.add_strings(strings=['MyStringToFind2','ATimeToFindAString','ThirdTimes A Charm'],
				modifiers=['wide','ascii','nocase'],
				comment="Testing Inline Comments",
				condition="2 of ($IDENTIFIER*)")
```
* The *strings* parameter can be overloaded with a list. In this case, all strings are treated as one group.
* The *modifiers* parameter can be a list or string and is used to modify strings in the rule.
* The *comment* parameter is used to provide a comment to the string in-line.
* The *condition* parameter is used to establish an arbitrary condition. A reserved word "IDENTIFIER" is used to give the author flexibility for the condition they wish to assign to a group of strings.

Since strings are issued at random, more control over the identifier can be controlled inline:

```python
rule.add_strings(strings=['MyStringToFind2','ATimeToFindAString','ThirdTimes A Charm'],
				modifiers=['wide','ascii','nocase'],
				comment="Testing Inline Comments",
				identifier="TESTING",
				condition="2 of ($IDENTIFIER*)")
```
* In this example, all strings will be identified with the $TESTING prefix.

**Binary Strings**

*yara_tools* has support for binary data blobs which are translated into hex-strings. Parameters used in add_strings also apply to those used in *add_binary_strings*.

```python
rule.add_binary_strings(data=open(sys.argv[1],'rb').read())
```

Size limits can also be applied via the *add_binary_strings* method.

```python
rule.add_binary_strings(data=open(sys.argv[1],'rb').read(),
						comment="Applying size limits",size_limit=5)
```

**Wildcard Binary Strings**

*yara_tools* also lets you add binary strings which have been wildcarded, most applicable to analyzed assembly. This is possible using the *add_binary_as_string* method.

```python
rule.add_binary_as_string(data="4d5a9000??000000??000000ffff0000")

```
**Conditions**

Conditions created via *add_condition* are order-based when compiled. It is recommended to apply file-based constraints/conditions prior to strings.
* If a condition was provided inline to a string via *add_strings* or *add_binary_strings* then no control is needed as these carry priority.

```python
rule.add_condition(condition="uint16(0x00) == 0x5a4d")
```


*yara_tools* has a concept of a "global condition group." Any condition you add will be thrown into the global condition group. The default boolean can be updated for this group using the *set_default_boolean* method. Its default value is 'and.' Every expression added to a condition via *add_condition* will be joined using this master operator.

```python
rule.set_default_boolean(value="or") #::Default value is 'and'
```

You can also set an authoritative condition. No matter what conditions/expressions have been added via *add_condition*, only the condition used in *add_authoritative_condition* will appear in your rule.

```python
rule.add_authoritative_condition(condition="any of them")
```

**Conditions And Strings**

All functions adding strings to a YARA rule accept the following parameters which enable developers to add conditions to the following methods:
* *add_strings*
* *add_binary_strings*
* *add_regex*
* *add_binary_as_string*

```python
add_strings(...condition="my condition")
```

**Complex Conditions & Condition Groups**

*yara_tools* introduces a concept known as *Condition Groups.*

Condition Groups are containers for conditions. 
* A condition group may have one or many expressions within them. 
* A condition group has a single configurable boolean assigned to all expressions within it. 
* A condition group can be negated/inverted (not modifier)
* An expression can be used within many condition groups. 
* Condition groups can be related to one another and nested.

A condition group is a construct that only exists in memory. A condition group is not committed to a rule until compile time (build_rule()) and will only appear as a condition if build rule is invoked with the *condition_groups* parameter.

```python
rule.build_rule(condition_groups=True)
```

_**Simple Condition Groups**_

Condition groups are created via _create_condition_group()_ method.

```python
rule.create_condition_group(name="my_condition_group")
```

The following parameters can be provided to *create_condition_group* to modify it:
* *condition_modifier*  - A boolean value, most often used to negate a group using 'not'
* *default_boolean* - A condition group's expressions can only contain a single boolean.
* *parent_group* - A reference to another condition group used in building complex relationships. Can be a list() or str()
* *virtual* - Boolean. A virtual condition group is never committed to a rule. It is used to prototype condition groups, commonly used to retrieve compiled condition_group strings.

_**Inline Assignment of Strings & Conditions To Condition Groups**_

All strings and conditions can be assigned to one or many condition groups via the *condition_group* parameter to each respective function.

```python
rule.create_condition_group(name="m1",default_boolean='or') 
rule.add_strings(strings="MyStringToFind",condition_group='m1')
rule.add_condition('uint16(0x00) == 0x5a4d',condition_group='m1')
```
_**Complex Condition Groups: Nesting Condition Groups**_

Conditions groups can have a one to many relationship with other condition groups and nested within each other. Nested condition groups are created by referencing a related condition group known as its "parents" by using the parameter *parent_group*

```python
rule.create_condition_group(name="bc1",parent_group=["pc1",'pc2'])
```
In this example, a condition group is created and is related to parent groups "pc1" and "pc2." This will only work successfully if these parent groups have been created prior to this call. 

Upon compile, conditions and expressions contained within "bc1" will be nested within condition groups "pc1" and "pc2."

_**Virtual Condition Groups**_

Virtual Condition Groups are a memory-only concept. It allows you to create a complex condition that is never committed to a rule. 

There may be cases, conditions, or features that do not yet exist in YARA or yara_tools where you still may be able to apply a condition group construct. An easy example of this is the *for loop* in YARA. To achieve a *for loop*, you'll need to build a format string. 
* See Example 5

A virtual condition group is created using the parameter *virtual*

```python
rule.create_condition_group(name="master_for",virtual=True)
```

All conditions nested under a virtual condition group will reside in memory, unless they also exist in a non-virtual condition group. To access a compiled virtual condition_group strings, the follow method will invoke aspects of build_rule() but in *prototype* mode. The rule's global conditions will not be compiled or modified.

```python
rule.get_condition_group(name='master_for')
```

**Building A Rule**

Rules are built in *yara_tools* only if strings or a condition is present. A string-based rule is returned via:

```python
rule.build_rule()
```

If condition groups are used in a rule, conditions groups will not appear unless *build_rule()* is executed with *condition_groups* parameter.

```python
rule.build_rule(condition_groups=True)
```