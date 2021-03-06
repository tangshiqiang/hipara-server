from django import forms
from .models import Category


class ImportFile(forms.Form):
    source = forms.CharField(max_length=100, required=True)
    category = forms.ModelChoiceField(queryset=Category.objects.all(), required=True, to_field_name="category_id")
    rule_file = forms.FileField(allow_empty_file=False, required=True)

    def clean_rule_file(self):
        rule_file = self.cleaned_data['rule_file']
        if not rule_file.name.endswith('.yar') and not rule_file.name.endswith('.yara'):
            raise forms.ValidationError("Invalid file type")
        import yara
        try:
	        file_data = rule_file.read()
	        rules = yara.compile(source=file_data)
        except:
        	raise forms.ValidationError("There is syntax error in yar file")
        from . import rule_parser
        return rule_parser.split_rules(file_data)