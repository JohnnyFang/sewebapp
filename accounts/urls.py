from django.conf.urls import url
from django.conf.urls import include
from django.contrib import admin
from django.contrib.auth import views as auth_views

from accounts import views

urlpatterns = [
    #url(r'^user_login/$', views.user_login, name='user_login'),
    url(r'^user_login/$', views.user_login, name='user_login'),
    url(r'^user_login/$', auth_views.login, {'template_name': 'accounts/login.html'}, name='user_login'),
    url(r'^logout/$', auth_views.LogoutView.as_view(), name='logout'),
    url(r'^signup/$', views.sign_up, name='signup'),
]