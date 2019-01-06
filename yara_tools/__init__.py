"""A library to create YARA rules.
"""

import binascii
from copy import deepcopy
import collections


class yara_tools(object):

	"""."""

	def __init__(self, name, default_identifier=False, tags=False, default_condition=False, default_boolean=False, identifier_template=False, global_rule=False, private_rule=False, default_str_condition=False, imports=False, includes=False, **kwargs):
		"""."""
		self.__name = str(name)
		self.__global = False
		self.__private = False
		self.__default_identifier = False
		self.__identifier_template = "IDENTIFIER"
		self.__strings = False  # ::list obj
		self.__tags = False  # ::list obj
		self.__conditions = False  # ::list obj
		self.__proto_conditions = False  # ::list obj
		self.__proto_condition_groups = False  # :: dict obj
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

		self.__legal_booleans = ('and', 'or', 'not')

		if global_rule:
			self.__global = True

		if private_rule:
			self.__private = True

		if default_identifier:
			self.set_default_identifier(value=default_identifier)

		if tags:
			self.add_tags(tags=tags)

		if default_condition:
			self.set_default_condition(condition=default_condition)

		if default_boolean:
			self.set_default_boolean(value=default_boolean)

		if identifier_template:
			self.set_identifier_template(value=identifier_template)

		if default_str_condition:
			self.set_default_str_condition(value=default_str_condition)

		if imports:
			self.add_import(name=imports)

		if includes:
			self.add_include(value=includes)

	def raw_to_hex(self, raw_data):
		"""."""
		return str(binascii.hexlify(raw_data))

	def add_import(self, name):
		"""."""
		if not self.__imports:
			self.__imports = set()

		if type(name) == list:
			for i in name:
				self.__imports.add(i)
		else:
			self.__imports.add(str(name))

	def add_include(self, value):
		"""."""
		if not self.__includes:
			self.__includes = set()

		if type(value) == list:
			for i in value:
				self.__includes.add(i)
		else:
			self.__includes.add(str(value))

	def add_meta(self, key, value):
		"""."""
		if not self.__rule_meta:
			self.__rule_meta = list()

		self.__rule_meta.append({str(key): str(value)})

	def create_condition_group(self, name, default_boolean=False, parent_group=False, condition_modifier=False, virtual=False):
		"""."""

		def proc_child(parent, child_name):

			if parent in dict(self.__condition_groups).keys():
				if self.__condition_groups[parent]['children']:
					self.__condition_groups[parent][
						'children'].append(child_name)
				else:
					self.__condition_groups[parent]['children'] = [child_name]

		def init_condition_group(name, default_boolean, parent=False, condition_modifier=condition_modifier, virtual=False):

			group_struct = {
				'default_boolean': default_boolean,
				'conditions': list(),
				'parent': parent,
				'modifier': condition_modifier,
				'virtual': virtual,
				'children': False
			}

			self.__condition_groups[name] = deepcopy(group_struct)

			if type(parent) == list:
				for p in parent:
					proc_child(parent=p, child_name=name)
			else:
				proc_child(parent=parent, child_name=name)

		if default_boolean:
			if not default_boolean in self.__legal_booleans:
				return False
		else:
			default_boolean = 'and'

		if not self.__condition_groups:
			self.__condition_groups = collections.OrderedDict()

		if type(name) == list:
			for n in name:
				if not n in self.__condition_groups:
					init_condition_group(
						n, default_boolean, parent_group, condition_modifier, virtual)
		else:
			if not name in self.__condition_groups:
				init_condition_group(name, default_boolean,
									 parent_group, condition_modifier, virtual)

	def get_condition_group(self, name):
		"""."""

		#::This function creates a concept of 'prototyping' of the group

		self.__proto_conditions = []
		self.__proto_condition_groups = self.__condition_groups

		if name in self.__proto_condition_groups:

			self.process_conditions(condition_groups=True, prototype=True)

			tmp_conditions = self.proc_cond_str(
				self.__proto_condition_groups[name])

			self.__proto_conditions = []
			self.__proto_condition_groups = dict()

			return tmp_conditions

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

	def add_condition(self, condition, condition_group=False, default_boolean=False, parent_group=False, condition_modifier=False, prototype=False):
		"""."""

		def add_condition_to_group(condition, group):

			self.create_condition_group(
				name=group,
				default_boolean=default_boolean,
				parent_group=parent_group,
				condition_modifier=condition_modifier
			)

			if type(condition) == list:
				for c in condition:
					if not c in global_condition_groups[group][
							'conditions']:  # ::dev, unsure if we're breaking things
						global_condition_groups[group][
							'conditions'].append(c)
			else:
				if condition:
					if not condition in global_condition_groups[group][
							'conditions']:  # ::dev, unsure if we're breaking things
						global_condition_groups[group][
							'conditions'].append(condition)

		def add_global_condition(condition):
			if not condition in global_conditions:
				global_conditions.append(str(condition))

		if not self.__conditions:
			self.__conditions = list()

		if not condition:
			return False

		#::Prototype support for get_condition_group
		global_condition_groups = None
		global_conditions = None

		if prototype:
			global_condition_groups = self.__proto_condition_groups
			global_conditions = self.__proto_conditions
		else:
			global_condition_groups = self.__condition_groups
			global_conditions = self.__conditions

		if condition_group:
			if type(condition_group) == list:
				for cg in condition_group:
					add_condition_to_group(condition=condition, group=cg)
			else:
				add_condition_to_group(
					condition=condition, group=condition_group)
		else:
			if condition:
				if type(condition) == list:
					for c in condition:
						add_global_condition(c)
				else:
					add_global_condition(condition)

	def add_authoritative_condition(self, condition):
		"""."""
		self.__authoritative_condition = str(condition)

	def add_tags(self, tags):
		"""."""
		if not self.__tags:
			self.__tags = []

		if type(tags) == list:
			for tag in tags:
				self.__tags.append(tag)
		elif type(tags) == str:
			self.__tags.append(tags)

	def set_default_boolean(self, value):
		"""."""
		if value in self.__legal_booleans:
			self.__default_boolean = (str(value))

	def set_default_condition(self, condition):

		self.__default_condition = str(condition)

	def set_default_str_condition(self, value):

		self.__default_str_condition = str(value)

	def set_identifier_template(self, value):

		self.__identifier_template = str(value)
		self.__reserved_identifiers[0] = str(value)

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
					string_type=False, comment=False, parent_group=False, condition_modifier=False):
		"""."""

		def process_string_condition(condition, identifier, condition_group, default_boolean, parent_group, condition_modifier):

			if type(condition) == list:
				for i in range(len(condition)):
					condition[i] = condition[i].replace(
						self.__identifier_template, identifier)
			else:
				condition = condition.replace(
					self.__identifier_template, identifier)

			self.add_condition(condition=condition,
							   condition_group=condition_group,
							   default_boolean=default_boolean,
							   parent_group=parent_group,
							   condition_modifier=condition_modifier)

		if not self.__strings:
			self.__strings = list()

		string_template = deepcopy(self.__string_struct)
		reserved_identifiers = deepcopy(self.__reserved_identifiers)

		if self.__default_identifier:
			identifier = self.__default_identifier

		if not identifier and not self.__default_identifier:
			#::keep'n it traditional yara style w/ chr(115), honey
			#:: If you're troubleshooting and arrived here, choose an identifier of your own. This won't scale.
			for char in [115, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 97, 116, 117, 118, 119, 120, 121, 122]:
				char = chr(char)
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
									 parent_group=parent_group,
									 condition_modifier=condition_modifier)
		else:
			string_template[
				'condition'] = "%s ($%s*)" % (self.__default_str_condition, identifier)
			process_string_condition(condition=string_template['condition'],
									 identifier=identifier,
									 condition_group=condition_group,
									 default_boolean=default_boolean,
									 parent_group=parent_group,
									 condition_modifier=condition_modifier)

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
				  comment=False, parent_group=False, condition_modifier=False):
		"""."""
		regex_template = "/%s/"

		if regex == list:
			for idx, _ in enumerate(regex):
				self.add_strings(strings=regex_template % regex[idx], modifiers=modifiers,
								 identifier=identifier, condition=condition,
								 string_type='regex', comment=comment,
								 condition_group=condition_group, default_boolean=default_boolean,
								 parent_group=parent_group,
								 condition_modifier=condition_modifier)
		else:
			self.add_strings(strings=regex_template % regex, modifiers=modifiers,
							 identifier=identifier, condition=condition,
							 string_type='regex', comment=comment,
							 condition_group=condition_group, default_boolean=default_boolean,
							 parent_group=parent_group,
							 condition_modifier=condition_modifier)

	def add_binary_strings(self, data, size_limit=False, modifiers=False,
						   identifier=False, condition=False,
						   condition_group=False, default_boolean=False, comment=False,
						   parent_group=False,
						   condition_modifier=False):
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
						 parent_group=parent_group,
						 condition_modifier=condition_modifier)

	def add_binary_as_string(self, data, modifiers=False,
							 identifier=False, condition=False,
							 condition_group=False, default_boolean=False, comment=False,
							 parent_group=False, condition_modifier=False):
		"""."""
		binary_template = "{%s}"

		if data == list:
			for bin_str in data:
				self.add_strings(strings=binary_template % bin_str, modifiers=modifiers,
								 identifier=identifier, condition=condition,
								 string_type='binary_str', comment=comment,
								 condition_group=condition_group, default_boolean=default_boolean,
								 parent_group=parent_group,
								 condition_modifier=condition_modifier)

		else:
			self.add_strings(strings=binary_template % data, modifiers=modifiers,
							 identifier=identifier, condition=condition,
							 string_type='binary_str', comment=comment,
							 condition_group=condition_group, default_boolean=default_boolean,
							 parent_group=parent_group,
							 condition_modifier=condition_modifier)

	def process_strings(self):
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

		if not self.__strings:
			return ""

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

	def proc_cond_str(self, cond_struct):

		if len(cond_struct['conditions']) > 0:
			if cond_struct['modifier']:
				group_format_str = "%s (%s)"
				return group_format_str % (cond_struct['modifier'], ((" %s " % cond_struct['default_boolean']).join(cond_struct['conditions'])))
			else:
				group_format_str = "(%s)"
				return group_format_str % ((" %s " % cond_struct['default_boolean']).join(cond_struct['conditions']))
		else:
			return False

	def process_conditions(self, condition_groups=False, prototype=False):
		"""."""

		#::Added to prototype condition groups. Hacky.
		int_condition_groups = None
		int_conditions = None

		if prototype:
			int_condition_groups = self.__proto_condition_groups
			int_conditions = self.__proto_conditions
		else:
			int_condition_groups = self.__condition_groups
			int_conditions = self.__conditions

		condition_format_str = "\tcondition:\n\t\t%s\n"

		#::Skip return from authoritity condition if we are prototyping
		if self.__authoritative_condition and not prototype:
			auth_type = type(self.__authoritative_condition)
			if auth_type == str:
				return (condition_format_str % self.__authoritative_condition)
			if auth_type == list:
				return (condition_format_str % str(" " + self.__default_boolean + " ").join(self.__authoritative_condition))

		if condition_groups and int_condition_groups:
			#::This section warrants a re-write of complex condition groups...
			#::Probably as B+ tree (and totally OBO)
			#::Stylistically, maintaining order of conditions appears paramount,
			#::the code was already too deep to change the game.
			#::
			#::...Springfield Rules! Down with Shelbyville!
			#::
			#::process groups with parents, initialize parents, read in reverse order
			#::since conditions groups are in an ordered structure, process in reverse
			#::to ensure all parents are initalized, excluding root node
			#::Leaf
			for name in reversed(int_condition_groups.keys()):
				group_struct = int_condition_groups[name]
				if group_struct['parent'] and not group_struct['children']:
					if type(group_struct['parent']) == list:
						for parent in group_struct['parent']:
							#::If our parent is a child (key 'parent' == True), then we add our condition to them
							if int_condition_groups[parent]['parent']:
								self.add_condition(condition=self.proc_cond_str(
									group_struct), condition_group=parent, prototype=prototype)
					else:
						if int_condition_groups[group_struct['parent']]['parent']:
							self.add_condition(condition=self.proc_cond_str(
								group_struct), condition_group=group_struct['parent'], prototype=prototype)

			#::Internal
			for name in reversed(int_condition_groups.keys()):
				group_struct = int_condition_groups[name]
				if group_struct['parent'] and group_struct['children']:
					if type(group_struct['parent']) == list:
						for parent in group_struct['parent']:
							#::If our parent is a child (key 'parent' == True), then we add our condition to them
							if int_condition_groups[parent]['parent']:
								self.add_condition(condition=self.proc_cond_str(
									group_struct), condition_group=parent, prototype=prototype)
					else:
						if int_condition_groups[group_struct['parent']]['parent']:
							self.add_condition(condition=self.proc_cond_str(
								group_struct), condition_group=group_struct['parent'], prototype=prototype)

			#::Root
			for name, group_struct in int_condition_groups.items():
				#::iterate through our children
				if group_struct['children']:
					for child in group_struct['children']:
						#::if we have no parent, add children conditions to ourselves
						if not group_struct['parent']:
							self.add_condition(condition=self.proc_cond_str(int_condition_groups[
											   child]), condition_group=name, prototype=prototype)

			#::If we are root node (no parents) and not a virtual group, add us as condition
			if int_condition_groups:
				for name, group_struct in int_condition_groups.items():
					if not group_struct['virtual'] and not group_struct['parent']:
						self.add_condition(condition=self.proc_cond_str(
							group_struct), prototype=prototype)

		#::If we are in prototype mode, no need to continue
		if prototype:
			return

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

	def process_tags(self):

		if self.__tags:
			return " : %s" % " ".join(self.__tags)
		else:
			return ""

	def process_scope(self):

		scope = []

		if self.__private:
			scope.append('private')

		if self.__global:

			scope.append('global')

		if len(scope) > 0:
			return "%s " % " ".join(scope)
		else:
			return ""

	def ret_complete_rule(self, rule_name, condition, tags, scope, meta=False,
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

		return("%s%s\n%srule %s%s\n{\n%s\n%s\n%s\n}" % (tmp_imports, tmp_includes, scope, rule_name, tags, meta, strings, condition))

	def build_rule(self, condition_groups=False):
		"""."""

		tmp_imports = []
		tmp_meta = False
		tmp_strings = False
		tmp_condition = False

		tmp_condition = self.process_conditions(
			condition_groups=condition_groups)

		if self.__conditions:
			if len(self.__conditions) == 0:
				raise Exception("No Conditions In Rule")
		else:
			raise Exception("No Conditions In Rule")

		tmp_strings = self.process_strings()
		tmp_meta = self.process_meta()
		tmp_tags = self.process_tags()
		tmp_scope = self.process_scope()

		if tmp_condition or tmp_strings:
			kwargs = {'rule_name': self.__name, 'condition': tmp_condition,
					  'meta': tmp_meta, 'strings': tmp_strings,
					  'imports': self.__imports, 'includes': self.__includes,
					  'tags': tmp_tags, 'scope': tmp_scope}
			rule = self.ret_complete_rule(**kwargs)
			return rule

		else:
			raise Exception("No Strings Or Conditions In Rule, Check Rule")


def create_rule(**kwargs):
	"""."""
	return yara_tools(**kwargs)