from django import forms


class AESKeyForm(forms.Form):
    key = forms.CharField(max_length=128)
    file_to_encrypt = forms.FileField(required=True, widget=forms.FileInput(attrs={'required': True}))


class SignatureForm(forms.Form):
    file_to_sign = forms.FileField(required=True, widget=forms.FileInput(attrs={'required': True}))


class VerifySignatureForm(forms.Form):
    file_to_verify = forms.FileField(required=True, widget=forms.FileInput(attrs={'required': True}))
    public_key = forms.FileField(required=True, widget=forms.FileInput(attrs={'required': True}))
