"""A library to interact with YARA rules.

A detailed explanation here. :)
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
        self.__strings = False #::list obj
        self.__conditions = False #::list obj
        self.__condition_groups = False #::dict obj
        self.__imports = False #::set obj
        self.__includes = False #::set obj
        self.__rule_meta = False #::list obj
        self.__reserved_identifiers = False
        self.__default_condition = "all of"
        self.__authoritative_condition = False
        self.__default_boolean = "and"
        self.__string_struct = {'type': '', 'identifier': '',
                                'strings': '', 'modifiers': '',
                                'condition': '', 'comment': ''}

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

        self.__rule_meta.append({str(key):str(value)})

    def create_condition_group(self, name, default_boolean='and'):
        """."""
        #::TODO - still in design
        group_struct = {'default_boolean' : 'and', 'conditions' : list()}
        if not self.__condition_groups:
            self.__condition_groups = dict()
            self.__condition_groups['default'] = deepcopy(group_struct)
        else:
            if not name in self.__condition_groups.items():
                self.__condition_groups[name] = deepcopy(group_struct)
                self.__condition_groups[name]['default_boolean'] = default_boolean

    def add_condition(self, condition, condition_group='default'):
        """."""
        if not self.__conditions:
            self.__conditions = list()

        self.__conditions.append(str(condition))

    def add_authoritative_condition(self, condition):
        """."""
        self.__authoritative_condition = str(condition)

    def set_default_boolean(self,value):
        """."""
        if value in ('and', 'or'):
            self.__default_boolean = (str(value))

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
                    condition=False, condition_group='default',
                    string_type=False, comment=False):
        """."""
        if not self.__strings:
            self.__strings = list()

        string_template = deepcopy(self.__string_struct)
        reserved_identifiers = deepcopy(self.__reserved_identifiers)

        if not identifier and not self.__default_identifier:
            for char in chr(random.randint(97, 122)):
                if not self.__reserved_identifiers:
                    identifier = char
                    self.add_reserved_identifiers(value=identifier)
                    string_template['identifier'] = identifier
                else:
                    if char not in self.__reserved_identifiers:
                        identifier = char
                        self.add_reserved_identifiers(value=identifier)
                        string_template['identifier'] = identifier
                continue

        elif self.__default_identifier and not identifier:
            string_template['identifier'] = self.__default_identifier

        else:
            string_template['identifier'] = str(identifier)

        if condition:
            string_template['condition'] = condition

        if modifiers:
            string_template['modifiers'] = modifiers

        if comment:
            string_template['comment'] = comment

        string_template['strings'] = strings

        if string_type:
            string_template['type'] = str(string_type)
        else:
            string_template['type'] = 'str'

        self.__strings.append(string_template)

    def add_binary_strings(self, data, size_limit=False, modifiers=False,
                           identifier=False, condition=False,
                           condition_group=False, comment=False):
        """."""
        binary_template = "{%s}"

        if data == list:
            for idx, _ in enumerate(data):
                if size_limit:
                    data[idx] = binary_template % (self.raw_to_hex(data[idx][0:int(size_limit)]))
                else:
                    data[idx] = binary_template % (self.raw_to_hex(data))
        else:
            if size_limit:
                data = "{%s}" % self.raw_to_hex(data[0:int(size_limit)])
            else:
                data = "{%s}" % self.raw_to_hex(data)

        self.add_strings(strings=data, modifiers=modifiers,
                         identifier=identifier, condition=condition,
                         string_type='binary', comment=comment)

    def process_strings(self):
        """."""
        identifier_collections = dict()
        final_strings = []
        #rule_name = str(rule_name) #::deprecated

        string_structs = self.__strings

        #::prime::#
        for struct in string_structs:
            identifier = str(struct['identifier'])
            identifier_collections[identifier] = {
                'strings': [], 'conditions': []}

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
                if str_type == 'binary':
                    identifier_collections[identifier]['strings'].append(
                        (strings, modifiers, str_type, comment))
                else:
                    identifier_collections[identifier]['strings'].append(
                        ("\"" + strings + "\"", modifiers, str_type, comment))

            elif stype == list:
                for string in strings:
                    if str_type == 'binary':
                        identifier_collections[identifier]['strings'].append(
                            (string, modifiers, str_type, comment))
                    else:
                        identifier_collections[identifier]['strings'].append(
                            ("\"" + string + "\"", modifiers, str_type, comment))
                    #::history lesson: I typo'd and left 'strings' in the appended clause and troubleshooted for about an hour. D'oh.
            else:

                identifier_collections[identifier]['strings'].append(
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
            if len(id_dict['strings']) > 0:
                for index in range(len(id_dict['strings'])):

                    def eval_string(t_ident, t_index, t_string, t_modifier=False, t_type=False, t_comment=False):
                        ret_string = ""
                        format_string = ""

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

            #::TODO, revisit, re-engineer and possibly add a modifier option to add_condition
            if len(id_dict['conditions']) > 0:
                for cond in id_dict['conditions']:

                    if "IDENTIFIER" in cond:
                        cond = cond.replace(
                            "IDENTIFIER", "%s" % str(identifier))

                    self.add_condition(condition=str(cond))
            else:
                self.add_condition(condition="all of ($%s*)" % identifier)

        if len(final_strings) > 0:

            return ("\tstrings:\n\t\t%s\n" % ("\n\t\t".join(final_strings)))

        else:

            return False

    def process_conditions(self):
        """."""
        #::rule_name = str(rule_name) deprecated

        conditions = self.__conditions
        def_conditions = self.__default_condition
        authoritative_condition = self.__authoritative_condition
        condition_joiners = self.__default_boolean

        if authoritative_condition:
            auth_type = type(authoritative_condition)
            if auth_type == str:
                return ("\tcondition:\n\t\t%s\n" % authoritative_condition)
            if auth_type == list:
                return ("\tcondition:\n\t\t%s\n" % str(" " + condition_joiners + " ").join(authoritative_condition))

        if not conditions:
            return("\tcondition:\n\t\t%s them\n" % def_conditions)

        if conditions:
            if len(conditions) >= 1:
                tmp_conditions = []
                for cond in conditions:
                    tmp_conditions.append(cond)
                return ("\tcondition:\n\t\t%s\n" % str(" " + condition_joiners + " \n\t\t").join(tmp_conditions))
        else:
            return False

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

        return("%s%s\nrule %s\n{\n%s\n%s\n%s\n}" % (tmp_imports,tmp_includes,rule_name, meta, strings, condition))

    def build_rule(self):
        """."""
        tmp_imports = []
        tmp_meta = False
        tmp_strings = False
        tmp_condition = False

        if len(self.__strings) == 0 and len(self.__conditions) == 0:
            return False

        tmp_strings = self.process_strings()
        tmp_condition = self.process_conditions()
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
