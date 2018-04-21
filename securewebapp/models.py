from django.db import models
from django.contrib.auth.models import User


def content_file_name(instance, filename):
    return '/'.join(['content', instance.user.username, filename])


# Create your models here.
class ExtendUser(models.Model):
    user = models.OneToOneField(User)
    password_sha1 = models.CharField(max_length=128, blank=True)
    private_key = models.CharField(max_length=128, blank=True)
    public_key = models.CharField(max_length=128, blank=True)
    submitted_file = models.FileField(upload_to=content_file_name, blank=True, null=True)
    aes_encrypted_file = models.FileField(upload_to='aes_encrypted_files', blank=True, null=True)
    # digital_signature = models.CharField(max_length=128, blank=True)
