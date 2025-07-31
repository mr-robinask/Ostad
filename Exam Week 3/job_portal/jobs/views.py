from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Job, Application, UserProfile
from .forms import RegistrationForm, JobForm, ApplicationForm
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist

def job_list(request):
    jobs = Job.objects.all()
    query = request.GET.get('q')
    if query:
        jobs = jobs.filter(title__icontains=query) | jobs.filter(company__icontains=query) | jobs.filter(location__icontains=query)
    return render(request, 'jobs/job_list.html', {'jobs': jobs})

def job_detail(request, job_id):
    job = get_object_or_404(Job, id=job_id)
    return render(request, 'jobs/job_detail.html', {'job': job})

@login_required
def post_job(request):
    try:
        user_profile = request.user.userprofile
        if user_profile.user_type != 'employer':
            messages.error(request, "Only employers can post jobs.")
            return redirect('job_list')
    except ObjectDoesNotExist:
        messages.error(request, "Please set up your user profile before posting a job.")
        return redirect('job_list')
    if request.method == 'POST':
        form = JobForm(request.POST)
        if form.is_valid():
            job = form.save(commit=False)
            job.posted_by = request.user
            job.save()
            messages.success(request, "Job posted successfully.")
            return redirect('job_list')
    else:
        form = JobForm()
    return render(request, 'jobs/post_job.html', {'form': form})

@login_required
def apply_job(request, job_id):
    job = get_object_or_404(Job, id=job_id)
    try:
        user_profile = request.user.userprofile
        if user_profile.user_type != 'applicant':
            messages.error(request, "Only applicants can apply for jobs.")
            return redirect('job_list')
    except ObjectDoesNotExist:
        messages.error(request, "Please set up your user profile before applying for a job.")
        return redirect('job_list')
    if request.method == 'POST':
        form = ApplicationForm(request.POST, request.FILES)
        if form.is_valid():
            application = form.save(commit=False)
            application.job = job
            application.applicant = request.user
            application.save()
            messages.success(request, "Application submitted successfully.")
            return redirect('job_list')
    else:
        form = ApplicationForm()
    return render(request, 'jobs/apply_job.html', {'form': form, 'job': job})

@login_required
def applications_list(request, job_id):
    job = get_object_or_404(Job, id=job_id)
    if request.user != job.posted_by:
        messages.error(request, "You can only view applications for your own jobs.")
        return redirect('job_list')
    applications = Application.objects.filter(job=job)
    return render(request, 'jobs/applications_list.html', {'job': job, 'applications': applications})

@login_required
def my_applications(request):
    try:
        user_profile = request.user.userprofile
        if user_profile.user_type != 'applicant':
            messages.error(request, "Only applicants can view their applications.")
            return redirect('job_list')
    except ObjectDoesNotExist:
        messages.error(request, "Please set up your user profile to view your applications.")
        return redirect('job_list')
    applications = Application.objects.filter(applicant=request.user)
    return render(request, 'jobs/my_applications.html', {'applications': applications})

@login_required
def dashboard(request):
    try:
        user_profile = request.user.userprofile
        if user_profile.user_type == 'employer':
            jobs = Job.objects.filter(posted_by=request.user)
            return render(request, 'jobs/dashboard.html', {'jobs': jobs, 'user_type': 'employer'})
        else:
            applications = Application.objects.filter(applicant=request.user)
            return render(request, 'jobs/dashboard.html', {'applications': applications, 'user_type': 'applicant'})
    except ObjectDoesNotExist:
        messages.error(request, "Please set up your user profile to access the dashboard.")
        return redirect('job_list')

def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Check if UserProfile already exists to avoid IntegrityError
            if not UserProfile.objects.filter(user=user).exists():
                UserProfile.objects.create(user=user, user_type=form.cleaned_data['user_type'])
            messages.success(request, "Registration successful. Please log in.")
            return redirect('login')
    else:
        form = RegistrationForm()
    return render(request, 'registration/register.html', {'form': form})