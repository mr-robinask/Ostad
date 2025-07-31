from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login
from django.db.models import Q
from .models import Job, Application
from .forms import JobForm, ApplicationForm, CustomUserCreationForm
from django.contrib import messages

def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('dashboard')
    else:
        form = CustomUserCreationForm()
    return render(request, 'registration/register.html', {'form': form})

@login_required
def dashboard(request):
    profile = request.user.userprofile
    if profile.role == 'employer':
        return render(request, 'employer_dashboard.html', {'jobs': Job.objects.filter(posted_by=request.user)})
    return render(request, 'applicant_dashboard.html', {'applications': Application.objects.filter(applicant=request.user)})

@login_required
def job_list(request):
    query = request.GET.get('q', '')
    jobs = Job.objects.filter(
        Q(title__icontains=query) | 
        Q(company_name__icontains=query) | 
        Q(location__icontains=query)
    )
    return render(request, 'job_list.html', {'jobs': jobs, 'query': query})

@login_required
def job_detail(request, job_id):
    job = get_object_or_404(Job, id=job_id)
    return render(request, 'job_detail.html', {'job': job})

@login_required
def post_job(request):
    if request.user.userprofile.role != 'employer':
        return redirect('job_list')
    if request.method == 'POST':
        form = JobForm(request.POST)
        if form.is_valid():
            job = form.save(commit=False)
            job.posted_by = request.user
            job.save()
            return redirect('dashboard')
    else:
        form = JobForm()
    return render(request, 'job_form.html', {'form': form})

@login_required
def apply_job(request, job_id):
    if request.user.userprofile.role != 'applicant':
        return redirect('job_list')
    job = get_object_or_404(Job, id=job_id)
    if request.method == 'POST':
        form = ApplicationForm(request.POST, request.FILES)
        if form.is_valid():
            application = form.save(commit=False)
            application.job = job
            application.applicant = request.user
            application.save()
            return redirect('dashboard')
    else:
        form = ApplicationForm()
    return render(request, 'application_form.html', {'form': form, 'job': job})

@login_required
def applications_list(request, job_id):
    if request.user.userprofile.role != 'employer':
        return redirect('job_list')
    job = get_object_or_404(Job, id=job_id)
    if job.posted_by != request.user:
        return redirect('job_list')
    applications = Application.objects.filter(job=job)
    return render(request, 'applications_list.html', {'job': job, 'applications': applications})

@login_required
def update_application_status(request, application_id, status):
    if request.user.userprofile.role != 'employer':
        return redirect('job_list')
    application = get_object_or_404(Application, id=application_id)
    if application.job.posted_by != request.user:
        return redirect('job_list')
    if status in ['approved', 'rejected']:
        application.status = status
        application.save()
        messages.success(request, f"Application status updated to {status.capitalize()}.")
    return redirect('applications_list', job_id=application.job.id)

@login_required
def my_applications(request):
    if request.user.userprofile.role != 'applicant':
        return redirect('job_list')
    status = request.GET.get('status', '')
    applications = Application.objects.filter(applicant=request.user)
    if status in ['pending', 'approved', 'rejected']:
        applications = applications.filter(status=status)
    return render(request, 'my_applications.html', {
        'applications': applications,
        'current_status': status
    })