# Create your views here.
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.hashers import check_password
import random
import string

def randomString(stringlength=26):
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(stringlength))

code = randomString()

def register(request):
    if request.method == 'POST':
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        username = request.POST['username']
        email = request.POST['email']
        phone = request.POST['phone']
        password = request.POST['password']
        password2 = request.POST['password2']
        user = User

        context ={
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'username': username,
            'phone': phone,
            'password': password,
        }

        if password == password2:
            if user.objects.filter(username=username).exists():
                messages.error(request, 'Username is already taken')
                return redirect('register')
            else:
                if user.objects.filter(email=email).exists():
                    messages.error(request, 'Email is already used')
                    return redirect('register')
                else:
                    if user.objects.filter(phone=phone).exists():
                        messages.error(request, 'Phone no  is already used')
                        return redirect('register')
        else:
            messages.error(request,'passwords donot match')
            return redirect('register')
    else:
        return render(request, 'accounts/register.html')

def confirmregister(request):
    if request.method == 'POST':
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        username = request.POST['username']
        email = request.POST['email']
        phone = request.POST['phone']
        password = request.POST['password']
        user = User
        context ={
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'username': username,
            'phone': phone,
            'password': password,
        }
        user = user.objects.create_user(username=username, email=email, password=password,  phone=phone, first_name=first_name, last_name=last_name)
        user.save()
        login(request, user)
        messages.success(request, 'You are now logged in')
        return redirect('index')
    else:
        return redirect('register')

def userlogin(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, 'You are now logged in')
            return redirect('index')
        else:
            messages.error(request, 'Invalid Credentials')
            return redirect('login')
    else:
        return render(request, 'accounts/login.html')

@login_required
def userlogout(request):
    if request.method == 'POST':
        logout(request)
        messages.success(request, "you are now logged out")
        return redirect('index')