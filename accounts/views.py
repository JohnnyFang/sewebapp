from django.contrib.auth import authenticate, login
from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.forms import AuthenticationForm

from accounts.forms import UserCreateForm
from securewebapp.models import ExtendUser
from securewebapp.views import generate_keys
import hashlib

# Create your views here.


def user_login(request):
    context_dict = {'head_title': 'Software Security Project - Login'}

    # If the request is a HTTP POST, try to pull out the relevant information.
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        print(hashlib.sha1(password.encode('utf-8')).hexdigest())
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                if user.extenduser.public_key is None:
                    extenduser = user.extenduser
                    public_key, private_key = generate_keys()
                    extenduser.public_key = public_key
                    extenduser.private_key = private_key
                    extenduser.save()

                message = 'Producto creado exitosamente'
                messages.add_message(request, messages.SUCCESS, message, 'login', fail_silently=True)
                # if next == "":
                #     next="/"
                return HttpResponseRedirect("/")
            else:
                context_dict = {'response': "Tu cuenta ha sido desactivada, contacta al webmaster"}
        else:
            context_dict = {'response': "Usuario y/o contrasena invalidos", 'username': request.POST['username']}
    else:
        context_dict['form'] = AuthenticationForm()
    return render(request, 'accounts/login.html', context_dict)


def sign_up(request):
    context_dict = {'head_title': 'Software Security Project - Sign Up'}
    if request.method == 'POST':
        # form = UserCreationForm(request.POST)
        form = UserCreateForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=raw_password)
            # this is where we hash the password using sha1 and store it in out ExtendUser model
            sha1 = hashlib.sha1(raw_password.encode('utf-8')).hexdigest()
            public_key, private_key = generate_keys()
            ext_user = ExtendUser(user=user, password_sha1=sha1, public_key=public_key, private_key=private_key)
            ext_user.save()
            login(request, user)
            return redirect('home')
    else:
        # form = UserCreationForm()
        form = UserCreateForm()
    context_dict['form'] = form
    return render(request, 'accounts/signup.html', context_dict)

