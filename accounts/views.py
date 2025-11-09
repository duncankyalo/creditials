from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
import random

def signup_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password != confirm_password:
            messages.error(request, 'Passwords do not match')
            return redirect('signup')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
            return redirect('signup')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered')
            return redirect('signup')

        User.objects.create_user(username=username, email=email, password=password)
        messages.success(request, 'Account created successfully')
        return redirect('login')

    return render(request, 'accounts/signup.html')


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, 'Invalid credentials')
    return render(request, 'accounts/login.html')


def logout_view(request):
    logout(request)
    return redirect('login')


def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            token = str(random.randint(100000, 999999))
            request.session['reset_token'] = token
            request.session['user_email'] = email
            send_mail(
                'Password Reset Code',
                f'Your password reset code is {token}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )
            messages.success(request, 'Reset code sent to your email')
            return redirect('reset_password')
        except User.DoesNotExist:
            messages.error(request, 'Email not found')
    return render(request, 'accounts/forgot_password.html')


def reset_password(request):
    if request.method == 'POST':
        token = request.POST.get('token')
        password = request.POST.get('password')
        confirm = request.POST.get('confirm')

        if password != confirm:
            messages.error(request, 'Passwords do not match')
            return redirect('reset_password')

        session_token = request.session.get('reset_token')
        email = request.session.get('user_email')

        if str(session_token) == token and email:
            user = User.objects.get(email=email)
            user.set_password(password)
            user.save()
            # Clear session after reset
            request.session.pop('reset_token')
            request.session.pop('user_email')
            messages.success(request, 'Password reset successful')
            return redirect('login')
        else:
            messages.error(request, 'Invalid code')
    return render(request, 'accounts/reset_password.html')


@login_required
def home_view(request):
    return render(request, 'accounts/home.html')
