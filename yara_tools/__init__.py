"""A library to interact with YARA rules.
"""

import binascii
import random
from copy import deepcopy


class yara_tools(object):

	"""."""

	def __init__(self, rule_name):
		"""."""
		self.__name = str(rule_name)
		self.__default_identifier = False
		self.__identifier_template = "IDENTIFIER"
		self.__strings = False  # ::list obj
		self.__conditions = False  # ::list obj
		self.__condition_groups = False  # ::dict obj
		self.__imports = False  # ::set obj
		self.__includes = False  # ::set obj
		self.__rule_meta = False  # ::list obj
		self.__reserved_identifiers = [self.__identifier_template]
		self.__default_condition = "all of them"
		self.__default_str_condition = "all of"
		self.__authoritative_condition = False
		self.__default_boolean = "and"
		self.__string_struct = {'type': '', 'identifier': '',
								'strings': '', 'modifiers': '',
								'condition': '', 'comment': '',
								'condition_group': '',
								'default_boolean': ''}

		self.__legal_booleans = ('and', 'or')

	def raw_to_hex(self, raw_data):
		"""."""
		return str(binascii.hexlify(raw_data))

	def add_import(self, import_name):
		"""."""
		if not self.__imports:
			self.__imports = set()

		self.__imports.add(str(import_name))

	def add_include(self, include_name):
		"""."""
		if not self.__includes:
			self.__includes = set()

		self.__includes.add(str(include_name))

	def add_meta(self, key, value):
		"""."""
		if not self.__rule_meta:
			self.__rule_meta = list()

		self.__rule_meta.append({str(key): str(value)})

	def create_condition_group(self, name, default_boolean=False, parent_group=False):
		"""."""
		def init_condition_group(name, default_boolean, parent=False):
			group_struct = {
				'default_boolean': default_boolean,
				 'conditions': list(),
				 'parent': parent}
			self.__condition_groups[name] = deepcopy(group_struct)

		if default_boolean:
			if not default_boolean in self.__legal_booleans:
				return False
		else:
			default_boolean = 'and'

		if not self.__condition_groups:
			self.__condition_groups = dict()
			init_condition_group(name, default_boolean, parent_group)
		else:
			if not name in self.__condition_groups:
				init_condition_group(name, default_boolean, parent_group)

	def get_condition_group(self, name, new_boolean=False):
		"""."""
		if name in self.__condition_groups:
			boolean = self.__condition_groups[name]['default_boolean']
			if new_boolean:
				if new_boolean in self.__legal_booleans:
					boolean = new_boolean
			return "(%s)" % (" %s " % boolean).join(self.__condition_groups[name]['conditions'])
		else:
			return False

	def process_as_condition_group(self, condition, boolean):
		"""."""

		if boolean in self.__legal_booleans:
			if type(condition) == list:
				return "(%s)" % (" %s " % boolean).join(condition)
			elif type(condition) == str:
				return "(%s)" % condition
			else:
				return False
		else:
			return False

	def add_condition(self, condition, condition_group=False, default_boolean=False, parent_group=False):
		"""."""
		if not self.__conditions:
			self.__conditions = list()

		if condition_group:
			self.create_condition_group(
				name=condition_group, default_boolean=default_boolean, parent_group=parent_group)
			if type(condition) == list:
				for c in condition:
					if not c in self.__condition_groups[condition_group][
							'conditions']: #::dev, unsure if we're breaking things
						self.__condition_groups[condition_group][
							'conditions'].append(c)
			else:
				if condition:
					if not condition in self.__condition_groups[condition_group][
							'conditions']: #::dev, unsure if we're breaking things
						self.__condition_groups[condition_group][
							'conditions'].append(condition)
		else:
			if condition:
				if not condition in self.__conditions: #::dev, unsure if we're breaking things
					self.__conditions.append(str(condition))

	def add_authoritative_condition(self, condition):
		"""."""
		self.__authoritative_condition = str(condition)

	def set_default_boolean(self, value):
		"""."""
		if value in self.__legal_booleans:
			self.__default_boolean = (str(value))

	def set_default_condition(self, value):

		self.__default_condition = str(value)

	def set_default_str_condition(self,value):

		self.__default_str_condition = str(value)

	def set_default_identifier(self, value):
		"""."""
		self.__default_identifier = str(value)
		self.add_reserved_identifiers(value=value)

	def add_reserved_identifiers(self, value):
		"""."""
		if not self.__reserved_identifiers:
			self.__reserved_identifiers = list()

		self.__reserved_identifiers.append(str(value))

	def add_strings(self, strings, modifiers=False, identifier=False,
					condition=False, condition_group=False, default_boolean=False,
					string_type=False, comment=False, parent_group=False):
		"""."""

		def process_string_condition(condition,identifier,condition_group,default_boolean,parent_group):
			
			if type(condition) == list:
				for i in range(len(condition)):
					condition[i]=condition[i].replace(self.__identifier_template,identifier)
			else:
				condition=condition.replace(self.__identifier_template,identifier)

			self.add_condition(condition=condition,
								condition_group=condition_group,
								default_boolean=default_boolean,
								parent_group=parent_group)

		if not self.__strings:
			self.__strings = list()

		string_template = deepcopy(self.__string_struct)
		reserved_identifiers = deepcopy(self.__reserved_identifiers)

		if not identifier and not self.__default_identifier:
			#::keep'n it traditional yara style
			#:: If you're troubleshooting and arrived here, choose an identifier of your own. This won't scale.
			for char in [115,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,97,116,117,118,119,120,121,122]:
				char=chr(char)
				if not self.__reserved_identifiers:
					identifier = char
					self.add_reserved_identifiers(value=identifier)
					string_template['identifier'] = identifier
					break
				else:
					if char not in self.__reserved_identifiers:
						identifier = char
						self.add_reserved_identifiers(value=identifier)
						string_template['identifier'] = identifier
						break
					else:
						continue
				continue

		elif self.__default_identifier and not identifier:
			string_template['identifier'] = self.__default_identifier

		else:
			string_template['identifier'] = str(identifier)

		string_template['strings'] = strings
		string_template['condition_group'] = condition_group
		string_template['default_boolean'] = default_boolean

		if condition:
			string_template['condition'] = condition
			process_string_condition(condition=string_template['condition'],
									identifier=identifier,
									condition_group=condition_group,
									default_boolean=default_boolean,
									parent_group=parent_group)
		else:
			string_template['condition'] = "%s ($%s*)" % (self.__default_str_condition,identifier)
			process_string_condition(condition=string_template['condition'],
									identifier=identifier,
									condition_group=condition_group,
									default_boolean=default_boolean,
									parent_group=parent_group)

		if modifiers:
			string_template['modifiers'] = modifiers

		if comment:
			string_template['comment'] = comment

		if string_type:
			
			string_template['type'] = str(string_type)
		else:

			string_template['type'] = 'str'

		self.__strings.append(string_template)

	def add_regex(self, regex, modifiers=False, identifier=False,
				  condition=False, condition_group=False, default_boolean=False,
				  comment=False, parent_group=False):
		"""."""
		regex_template = "/%s/"

		if regex == list:
			for idx, _ in enumerate(regex):
				self.add_strings(strings=regex_template % regex[idx], modifiers=modifiers,
								 identifier=identifier, condition=condition,
								 string_type='regex', comment=comment,
								 condition_group=condition_group, default_boolean=default_boolean,
								 parent_group=parent_group)
		else:
			self.add_strings(strings=regex_template % regex, modifiers=modifiers,
							 identifier=identifier, condition=condition,
							 string_type='regex', comment=comment,
							 condition_group=condition_group, default_boolean=default_boolean,
							 parent_group=parent_group)

	def add_binary_strings(self, data, size_limit=False, modifiers=False,
						   identifier=False, condition=False,
						   condition_group=False, default_boolean=False, comment=False,
						   parent_group=False):
		"""."""
		binary_template = "{%s}"

		if data == list:
			for idx, _ in enumerate(data):
				if size_limit:
					data[idx] = binary_template % (
						self.raw_to_hex(data[idx][0:int(size_limit)]))
				else:
					data[idx] = binary_template % (self.raw_to_hex(data))

		else:
			if size_limit:
				data = "{%s}" % self.raw_to_hex(data[0:int(size_limit)])
			else:
				data = "{%s}" % self.raw_to_hex(data)

		self.add_strings(strings=data, modifiers=modifiers,
						 identifier=identifier, condition=condition,
						 string_type='binary', comment=comment,
						 condition_group=condition_group, default_boolean=default_boolean,
						 parent_group=parent_group)

	def add_binary_as_string(self, data, modifiers=False,
							 identifier=False, condition=False,
							 condition_group=False, default_boolean=False, comment=False,
							 parent_group=False):
		"""."""
		binary_template = "{%s}"

		if data == list:
			for bin_str in data:
				self.add_strings(strings=binary_template % bin_str, modifiers=modifiers,
								 identifier=identifier, condition=condition,
								 string_type='binary_str', comment=comment,
								 condition_group=condition_group, default_boolean=default_boolean,
								 parent_group=parent_group)

		else:
			self.add_strings(strings=binary_template % data, modifiers=modifiers,
							 identifier=identifier, condition=condition,
							 string_type='binary_str', comment=comment,
							 condition_group=condition_group, default_boolean=default_boolean,
							 parent_group=parent_group)

	def process_strings(self, with_condition_groups=False):
		"""."""
		def process_collections(str_obj):
			identifier_collections[identifier]['strings'].append(str_obj)

		def eval_string(t_ident, t_index, t_string, t_modifier=False, t_type=False, t_comment=False, ignore_index=False):
			ret_string = ""
			format_string = ""

			if ignore_index:
				t_index = ""

			if t_modifier:
				mtype = type(t_modifier)
				if mtype == list:
					t_modifier = " ".join(t_modifier)

				if t_comment:
					format_string = "$%s%s = %s %s //%s"
					if type(t_comment) == list:
						t_comment = " - ".join(t_comment)
					return format_string % (str(t_ident), str(t_index), t_string, t_modifier, t_comment)
				else:
					format_string = "$%s%s = %s %s"
					return format_string % (str(t_ident), str(t_index), t_string, t_modifier)
			else:
				if t_comment:
					if type(t_comment) == list:
						t_comment = " - ".join(t_comment)

					format_string = "$%s%s = %s //%s"
					return format_string % (str(t_ident), str(t_index), t_string, t_comment)
				else:
					format_string = "$%s%s = %s"
					return format_string % (str(t_ident), str(t_index), t_string)

		identifier_collections = dict()
		final_strings = []
		# rule_name = str(rule_name) #::deprecated

		string_structs = self.__strings

		#::prime::#
		for struct in string_structs:
			identifier = str(struct['identifier'])
			identifier_collections[identifier] = {
				'strings': [], 'conditions': [],
				'condition_group': struct['condition_group'],
				'default_boolean': struct['default_boolean']
			}

		#::process::#
		for struct in string_structs:
			identifier = str(struct['identifier'])
			modifiers = struct['modifiers']
			strings = struct['strings']
			condition = struct['condition']
			str_type = struct['type']
			comment = struct['comment']

			stype = type(strings)
			contype = type(condition)

			if stype == str:
				if str_type == 'binary' or str_type == 'regex' or str_type == 'binary_str':
					process_collections(
						(strings, modifiers, str_type, comment))
				else:
					process_collections(
						("\"" + strings + "\"", modifiers, str_type, comment))

			elif stype == list:
				for string in strings:
					if str_type == 'binary' or str_type == 'regex' or str_type == 'binary_str':
						process_collections(
							(string, modifiers, str_type, comment))
					else:
						process_collections(
							("\"" + string + "\"", modifiers, str_type, comment))
					#::history lesson: I typo'd and left 'strings' in the appended clause and troubleshooted for about an hour. D'oh.
			else:
				process_collections(
					("\"" + str(strings) + "\"", modifiers, str_type, comment))

			if condition != "":

				if contype == str:
					identifier_collections[identifier][
						'conditions'].append(condition)

				if contype == list:
					for cd in condition:
						identifier_collections[identifier][
							'conditions'].append(cd)

		#::uniq it::#
		for identifier, id_dict in identifier_collections.items():
			identifier_collections[identifier][
				'strings'] = id_dict['strings']
			identifier_collections[identifier][
				'conditions'] = list(set(id_dict['conditions']))

			#::get it on::#
			if len(id_dict['strings']) > 1:
				for index in range(len(id_dict['strings'])):

					pstring = id_dict['strings'][index][0]
					modifier = id_dict['strings'][index][1]
					stype = id_dict['strings'][index][2]
					comment = id_dict['strings'][index][3]

					pstype = type(pstring)

					if pstype == str:
						final_strings.append(eval_string(
							t_ident=identifier, t_index=index, t_string=pstring, t_modifier=modifier, t_type=stype, t_comment=comment))

					if pstype == list:
						for tmp_string in pstring:
							final_strings.append(eval_string(
								t_ident=identifier, t_index=index, t_string=tmp_string, t_modifier=modifier, t_type=stype, t_comment=comment))

			elif len(id_dict['strings']) == 1:

				pstring = id_dict['strings'][0][0]
				modifier = id_dict['strings'][0][1]
				stype = id_dict['strings'][0][2]
				comment = id_dict['strings'][0][3]

				final_strings.append(eval_string(
					t_ident=identifier, t_index=False, t_string=pstring,
					t_modifier=modifier, t_type=stype, t_comment=comment,
					ignore_index=True))

		if len(final_strings) > 0:

			return ("\tstrings:\n\t\t%s\n" % ("\n\t\t".join(final_strings)))

		else:

			return False

	def process_conditions(self,condition_groups=False):
		"""."""

		conditions = self.__conditions

		condition_format_str = "\tcondition:\n\t\t%s\n"

		if self.__authoritative_condition:
			auth_type = type(self.__authoritative_condition)
			if auth_type == str:
				return (condition_format_str % self.__authoritative_condition)
			if auth_type == list:
				return (condition_format_str % str(" " + self.__default_boolean + " ").join(self.__authoritative_condition))

		if condition_groups and self.__condition_groups:
			group_format_str="(%s)"
			#::process groups with parents, initialize parents
			for name,c in self.__condition_groups.items():
				if c['parent']:
					condition_add=group_format_str % ((" %s " % c['default_boolean']).join(c['conditions']))
					if type(c['parent']) == list:
						for p in c['parent']:
							condition_add=group_format_str % ((" %s " % c['default_boolean']).join(c['conditions']))
							self.add_condition(condition=condition_add,condition_group=c['parent'])
					else:
						condition_add=group_format_str % ((" %s " % c['default_boolean']).join(c['conditions']))
						self.add_condition(condition=condition_add,condition_group=c['parent'])

			for name,c in self.__condition_groups.items():
				#::if having no parent
				for cond in c['conditions']:
					if not c['parent']: 
						condition_add=group_format_str % ((" %s " % c['default_boolean']).join(c['conditions']))
						self.add_condition(condition=condition_add)

		if self.__conditions:
			if len(self.__conditions) >= 1:
				tmp_conditions = []
				for cond in self.__conditions:
					tmp_conditions.append(cond)
				return (condition_format_str % str(" " + self.__default_boolean + " \n\t\t").join(tmp_conditions))
		else:
			return(condition_format_str % self.__default_condition)

	def process_meta(self):
		"""."""
		if not self.__rule_meta:
			return False

		tmp_meta = list()
		for meta in self.__rule_meta:
			for key, value in meta.items():
				tmp_meta.append("%s=\"%s\"" % (key, value))

		return "\tmeta:\n\t\t%s\n" % "\n\t\t".join(tmp_meta)

	def ret_complete_rule(self, rule_name, condition, meta=False,
						  strings=False, imports=False, includes=False):
		"""."""
		final_rule = ""
		tmp_imports = ""
		tmp_includes = ""

		if imports:
			for imp in imports:
				tmp_imports += "import \"%s\"\n" % str(imp)

		if includes:
			for inc in includes:
				tmp_includes += "include \"%s\"\n" % str(inc)

		if not meta:
			meta = ""

		if not strings:
			strings = ""

		return("%s%s\nrule %s\n{\n%s\n%s\n%s\n}" % (tmp_imports, tmp_includes, rule_name, meta, strings, condition))

	def build_rule(self,condition_groups=False):
		"""."""

		tmp_imports = []
		tmp_meta = False
		tmp_strings = False
		tmp_condition = False

		if len(self.__strings) == 0 and len(self.__conditions) == 0:
			return False

		tmp_strings = self.process_strings()
		tmp_condition = self.process_conditions(condition_groups=condition_groups)
		tmp_meta = self.process_meta()

		if tmp_condition or tmp_strings:
			kwargs = {'rule_name': self.__name, 'condition': tmp_condition,
					  'meta': tmp_meta, 'strings': tmp_strings,
					  'imports': self.__imports, 'includes': self.__includes}
			rule = self.ret_complete_rule(**kwargs)
			return rule

		else:
			return False


def create_rule(name):
	"""."""
	if name:
		return yara_tools(rule_name=str(name))
	else:
		return False
