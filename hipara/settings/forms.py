from django import forms
import magic

class UpdateRoutineForm(forms.Form):
	fullDiskScan = forms.BooleanField(required=False)
	memoryScan = forms.BooleanField(required=False)

class UploadConfigForm(forms.Form):
	configFile = forms.FileField(allow_empty_file=False, required=True)

class UploadMsiPackageForm(forms.Form):
	msiPackageFile = forms.FileField(allow_empty_file=False, required=True)
	buildNumber = forms.IntegerField(required=True)

	def clean_msiPackageFile(self):
		file = self.cleaned_data.get("msiPackageFile", False)
		max_size = 1024*1024*2
		fileContent = file.read()
		filetype = magic.from_buffer(fileContent)
		if not "MSI" in filetype:
			raise forms.ValidationError("File is not MSI.")
		if file.size > max_size:
			raise forms.ValidationError("Ensure this file size is not greater than 2MB.")
		return {"fileContent": fileContent, "fileName": file.name}