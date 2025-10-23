from django.shortcuts import render, redirect, get_object_or_404
from django.views import View
from django.contrib.auth import login
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib.auth.mixins import LoginRequiredMixin
from .forms import (
    DonorRegistrationForm, 
    DonorProfileForm, 
    UserUpdateForm, 
    ProfileUpdateForm
)
# --- THIS IS THE FIX ---
from .models import CustomUser, DonorProfile
# --- END OF FIX ---

# We need the mixin from the blood app to protect the view
from blood.views import DonorRequiredMixin 
from django.contrib import messages

class CustomLoginView(LoginView):
    template_name = 'login.html'
    redirect_authenticated_user = True

class CustomLogoutView(LogoutView):
    next_page = 'login' 

class DashboardRedirectView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        if request.user.role == CustomUser.Role.ADMIN:
            return redirect('dashboard-admin')
        elif request.user.role == CustomUser.Role.DONOR:
            # Check if donor has a profile, if not, send to create it
            if not hasattr(request.user, 'profile'):
                return redirect('update-profile') 
            return redirect('dashboard-donor')
        else:
            return redirect('login') 

class RegisterDonorView(View):    
    def get(self, request, *args, **kwargs):
        user_form = DonorRegistrationForm()
        profile_form = DonorProfileForm()
        return render(request, 'register.html', {
            'user_form': user_form,
            'profile_form': profile_form
        })

    def post(self, request, *args, **kwargs):
        user_form = DonorRegistrationForm(request.POST)
        profile_form = DonorProfileForm(request.POST)

        if user_form.is_valid() and profile_form.is_valid():
            user = user_form.save(commit=False)
            user.role = CustomUser.Role.DONOR # Set role
            user.save()

            profile = profile_form.save(commit=False)
            profile.user = user # Link to the new user
            profile.save()

            login(request, user) # Log the user in
            return redirect('dashboard-redirect')
        
        return render(request, 'register.html', {
            'user_form': user_form,
            'profile_form': profile_form
        })

# --- NEW VIEW FOR UPDATING PROFILE ---

class UpdateProfileView(DonorRequiredMixin, View):
        
    def get(self, request, *args, **kwargs):
        # This line was crashing because DonorProfile was not imported
        profile, created = DonorProfile.objects.get_or_create(user=request.user)

        user_form = UserUpdateForm(instance=request.user)
        profile_form = ProfileUpdateForm(instance=profile)
        
        return render(request, 'update_profile.html', {
            'user_form': user_form,
            'profile_form': profile_form
        })

    def post(self, request, *args, **kwargs):
        profile = request.user.profile
        user_form = UserUpdateForm(request.POST, instance=request.user)
        profile_form = ProfileUpdateForm(request.POST, instance=profile)

        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, 'Your profile has been updated successfully!')
            return redirect('dashboard-donor')
        
        return render(request, 'update_profile.html', {
            'user_form': user_form,
            'profile_form': profile_form
        })

