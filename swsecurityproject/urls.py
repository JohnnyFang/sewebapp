"""swsecurityproject URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from django.conf.urls import include

from securewebapp import views

urlpatterns = [
    url(r'^$', views.home, name='home'),
    url(r'^aes/file_upload', views.aes_file_upload, name='aes_file_upload'),
    url(r'^aes/file_decrypt', views.aes_file_decrypt, name='aes_file_decrypt'),
    url(r'^digital_signature/sign', views.generate_digital_signature, name='generate_digital_signature'),
    url(r'^digital_signature/verify', views.verify_digital_signature, name='verify_digital_signature'),
    # Accounts
    url(r'^accounts/', include('accounts.urls')),
    url(r'^admin/', admin.site.urls),
]
