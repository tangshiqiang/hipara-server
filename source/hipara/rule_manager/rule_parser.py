import re
from django import forms


def split_rules(rule_file_data):
    try:
        rule_file_data = remove_comments(rule_file_data.decode())
        rule_file_data = rule_file_data.encode()
        rule_list = re.findall(b'rule.*?condition:.*?}', rule_file_data, re.DOTALL)
        rule_list_result = []
        for rule in rule_list:
            rule_list_result = rule_list_result + [parse_rule(rule)]
        return rule_list_result
    except forms.ValidationError as error:
        raise forms.ValidationError(error)
    except:
        raise forms.ValidationError("Unable to import file")


def parse_rule(rule):
    name = rule.split(b'{')[0].replace(b'rule ', b'').strip().decode()
    if len(name) == 0:
        raise forms.ValidationError("Name is required for the rules")
    else:
        from django.core.exceptions import MultipleObjectsReturned
        from .models import Rule
        try:
            rule = Rule.objects.get(name__iexact=name)
            raise forms.ValidationError("Name for rule is already been taken : "+name)
        except MultipleObjectsReturned:
            raise forms.ValidationError("Name for rule is already been taken : "+name)
        except Rule.DoesNotExist:
            pass

    meta_result = []
    meta_list = re.findall(b'meta:(.*)strings:', rule, re.DOTALL)
    if len(meta_list) > 0:
        for line in meta_list[0].split(b'\n'):
            if b'=' in line:
                meta_lines = line.split(b'=')
                key = meta_lines[0]
                try:
                    value = re.findall(b'"(.*)"', line)[0]
                except:
                    value = meta_lines[1]
                meta_result = meta_result + [{'key': key.strip().decode(), 'value': value.strip().decode()}]

    string_list_result = []
    string_list = re.findall(b'strings:(.*)condition:', rule, re.DOTALL)
    if len(string_list) > 0:
        lines = string_list[0].split(b'\n')
        for line in lines:
            if b'=' in line:
                string_type = False
                # get the string ID
                line_split = line.split(b'=')
                key = line_split[0].strip().decode()
                string_data = line_split[1]
                string_value = ''
                string_nocase = string_wide = string_full = string_ascii = False
                if string_data.strip().startswith(b'"'):
                    standard_string = re.findall(b'"(.*)"', line)
                    if len(standard_string) != 0:
                        string_type = 'String'
                        string_ascii = True
                        string_value = standard_string[0].decode()
                        if b'nocase' in line.split(b'"')[-1]:
                            string_nocase = True
                        if b'wide' in line.split(b'"')[-1]:
                            string_wide = True
                            string_ascii = False
                        if b'fullword' in line.split(b'"')[-1]:
                            string_full = True
                        if b'ascii' in line.split(b'"')[-1]:
                            string_ascii = True
                if not string_type and string_data.strip().startswith(b'{'):
                    hex_string = re.findall(b'{(.*)}', line)
                    if len(hex_string) != 0:
                        string_type = 'Hex'
                        string_value = hex_string[0].decode()

                if not string_type and string_data.strip().startswith(b'/'):
                    reg_string = re.findall(b'/(.*)/', line)
                    if len(reg_string) != 0:
                        if reg_string[0] not in [b'', b'/']:
                            string_type = 'RegEx'
                            string_ascii = True
                            string_value = reg_string[0].decode()
                            if b'nocase' in line.split(b'"')[-1]:
                                string_nocase = True
                            if b'wide' in line.split(b'"')[-1]:
                                string_wide = True
                                string_ascii = False
                            if b'fullword' in line.split(b'"')[-1]:
                                string_full = True
                            if b'ascii' in line.split(b'"')[-1]:
                                string_ascii = True

                if string_type:
                    string_result = {
                        'type': string_type,
                        'name': key,
                        'value': string_value,
                        'is_nocase': string_nocase,
                        'is_wide': string_wide,
                        'is_full': string_full,
                        'is_ascii': string_ascii
                    }
                    string_list_result = string_list_result + [string_result]

    condition = re.findall(b'condition:(.*)}', rule, re.DOTALL)
    condition_result = condition[0].strip().decode()
    if len(condition_result) == 0:
        raise forms.ValidationError("Condition is required for rule : " + name)

    return {
        'name': name,
        'value': {
            'meta': meta_result,
            'strings': string_list_result,
            'condition': condition_result
        }
    }


def remove_comments(text):
    pattern = r"""
                            ##  --------- COMMENT ---------
           /\*              ##  Start of /* ... */ comment
           [^*]*\*+         ##  Non-* followed by 1-or-more *'s
           (                ##
             [^/*][^*]*\*+  ##
           )*               ##  0-or-more things which don't start with /
                            ##    but do end with '*'
           /                ##  End of /* ... */ comment
         |                  ##  -OR-  various things which aren't comments:
           (                ##
                            ##  ------ " ... " STRING ------
             "              ##  Start of " ... " string
             (              ##
               \\.          ##  Escaped char
             |              ##  -OR-
               [^"\\]       ##  Non "\ characters
             )*             ##
             "              ##  End of " ... " string
           |                ##  -OR-
                            ##
                            ##  ------ ' ... ' STRING ------
             '              ##  Start of ' ... ' string
             (              ##
               \\.          ##  Escaped char
             |              ##  -OR-
               [^'\\]       ##  Non '\ characters
             )*             ##
             '              ##  End of ' ... ' string
           |                ##  -OR-
                            ##
                            ##  ------ ANYTHING ELSE -------
             .              ##  Anything other char
             [^/"'\\]*      ##  Chars which doesn't start a comment, string
           )                ##    or escape
    """
    regex = re.compile(pattern, re.VERBOSE | re.MULTILINE | re.DOTALL)
    noncomments = [m.group(2) for m in regex.finditer(text) if m.group(2)]
    return "".join(noncomments)

# Create Rules from Database
blank_rule = '''rule [[name]]
{
    meta:
[[meta]]
    strings:
[[strings]]
    condition:
        [[condition]]
}
'''


def export_single_rule(rule):
    meta_list = rule.meta_rule.all()
    meta_string = ''
    for meta in meta_list:
        meta_string += '\t\t{0} = "{1}"\n'.format(meta.key, meta.value)

    # get strings
    string_list = rule.string_rule.all()
    strings_string = ''
    for strings in string_list:
        if strings.type == 'String':
            strings_string += '\t\t{0} = "{1}"'.format(strings.name, strings.value)
            if strings.is_nocase:
                strings_string += ' nocase'
            if strings.is_wide:
                strings_string += ' wide'
            if strings.is_full:
                strings_string += ' fullword'
            if strings.is_wide and strings.is_ascii:
                strings_string += ' ascii'
            strings_string += '\n'
        if strings.type == 'Hex':
            strings_string += '\t\t{0} = {{{1}}}\n'.format(strings.name, strings.value)
        if strings.type == 'RegEx':
            strings_string += '\t\t{0} = /{1}/'.format(strings.name, strings.value)
            if strings.is_nocase:
                strings_string += ' nocase'
            if strings.is_wide:
                strings_string += ' wide'
            if strings.is_full:
                strings_string += ' fullword'
            if strings.is_wide and strings.is_ascii:
                strings_string += ' ascii'
            strings_string += '\n'

    # get condition
    condition = rule.condition_rule.all()[0]

    # Compile Rule
    final_rule = blank_rule.replace('[[name]]', rule.name)
    final_rule = final_rule.replace('[[meta]]', meta_string)
    final_rule = final_rule.replace('[[strings]]', strings_string)
    final_rule = final_rule.replace('[[condition]]', condition.condition)

    # Return The rule
    return final_rule


def export_category_rule(category):
    final_rule = ''
    rules = category.rule_category.all()
    for rule in rules:
        raw = export_single_rule(rule)
        final_rule += '{0}'.format(raw)
    return final_rule


def export_all_rule():
    final_rule = ''
    from .models import Rule
    rules = Rule.objects.all()
    for rule in rules:
        raw = export_single_rule(rule)
        final_rule += '{0}'.format(raw)
    return final_rule
