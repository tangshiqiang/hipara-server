from django import forms

class UpdateRoutineForm(forms.Form):
    fullDiskScan = forms.BooleanField(required=False)
    memoryScan = forms.BooleanField(required=False)

class UploadConfigForm(forms.Form):
    configFile = forms.FileField(allow_empty_file=False, required=True)