from django.shortcuts import render, redirect, get_object_or_404
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from .models import DonationRecord, BloodRequest
from users.models import CustomUser
from .forms import DonationRequestForm, BloodRequestForm

class AdminRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self):
        return self.request.user.role == CustomUser.Role.ADMIN

class DonorRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self):
        return self.request.user.role == CustomUser.Role.DONOR

class AdminDashboardView(AdminRequiredMixin, View):
    def get(self, request):
        total_donors = CustomUser.objects.filter(role=CustomUser.Role.DONOR).count()
        pending_donations = DonationRecord.objects.filter(status='PENDING')
        pending_requests = BloodRequest.objects.filter(status='PENDING')
        blood_group_filter = request.GET.get('blood_group', '')
        all_requests = BloodRequest.objects.all().order_by('-created_at')
        if blood_group_filter:
            all_requests = all_requests.filter(blood_group=blood_group_filter)
        context = {
            'total_donors': total_donors,
            'pending_donations': pending_donations,
            'pending_requests': pending_requests,
            'all_requests': all_requests,
            'blood_request_form': BloodRequestForm(),
        }
        return render(request, 'dashboard_admin.html', context)

    def post(self, request):
        form = BloodRequestForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('dashboard-admin')
        total_donors = CustomUser.objects.filter(role=CustomUser.Role.DONOR).count()
        pending_donations = DonationRecord.objects.filter(status='PENDING')
        pending_requests = BloodRequest.objects.filter(status='PENDING')
        all_requests = BloodRequest.objects.all().order_by('-created_at')
        context = {
            'total_donors': total_donors,
            'pending_donations': pending_donations,
            'pending_requests': pending_requests,
            'all_requests': all_requests,
            'blood_request_form': form,
        }
        return render(request, 'dashboard_admin.html', context)

class UpdateDonationStatusView(AdminRequiredMixin, View):
    def get(self, request, pk, status):
        donation = get_object_or_404(DonationRecord, pk=pk)
        if status in ['APPROVED', 'REJECTED']:
            donation.status = status
            donation.save()
        return redirect('dashboard-admin')

class UpdateRequestStatusView(AdminRequiredMixin, View):
    def get(self, request, pk, status):
        blood_request = get_object_or_404(BloodRequest, pk=pk)
        if status in ['APPROVED', 'REJECTED']:
            blood_request.status = status
            blood_request.save()
        return redirect('dashboard-admin')

class DonorDashboardView(DonorRequiredMixin, View):
    def get(self, request):
        profile = getattr(request.user, 'profile', None)
        donation_history = request.user.donations.all().order_by('-created_at')
        form = DonationRequestForm()
        return render(request, 'dashboard_donor.html', {
            'profile': profile,
            'donation_history': donation_history,
            'form': form
        })

    def post(self, request):
        form = DonationRequestForm(request.POST)
        if form.is_valid():
            donation = form.save(commit=False)
            donation.donor = request.user
            donation.save()
            return redirect('dashboard-donor')
        profile = getattr(request.user, 'profile', None)
        donation_history = request.user.donations.all().order_by('-created_at')
        return render(request, 'dashboard_donor.html', {
            'profile': profile,
            'donation_history': donation_history,
            'form': form
        })
