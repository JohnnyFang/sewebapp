from django.conf.urls import url
from django.conf.urls import include

from securewebapp import views

urlpatterns = [
    url(r'^$', views.home, name='home'),
]