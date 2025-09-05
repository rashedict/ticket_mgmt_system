from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic import ListView, CreateView, UpdateView, DetailView, TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView
from django.db.models import Count
from django.db.models.functions import TruncMonth
from django.http import JsonResponse, HttpResponseRedirect
from .models import Ticket, TicketType, Profile
from .forms import TicketForm, TicketTypeForm, ReportFilterForm, UserCreateForm, PasswordChangeForm
from django.contrib.auth.models import User
from django.contrib.auth import update_session_auth_hash, login, authenticate
import json
from django.contrib import messages
import random
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.contrib.auth.views import LogoutView
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta

class CustomLoginView(LoginView):
    template_name = 'login.html'
    
    def form_valid(self, form):
        # Check if user needs to change password
        user = form.get_user()
        if hasattr(user, 'profile') and user.profile.force_password_change:
            # Store user ID in session to force password change
            self.request.session['force_password_change_user_id'] = user.id
            return redirect('force_password_change')
        
        messages.success(self.request, f'Welcome back, {user.username}!')
        return super().form_valid(form)
    
    def form_invalid(self, form):
        messages.error(self.request, 'Invalid username or password. Please try again.')
        return super().form_invalid(form)

class ForcePasswordChangeView(TemplateView):
    template_name = 'force_password_change.html'
    
    def dispatch(self, request, *args, **kwargs):
        # Check if user is coming from login with the session flag
        user_id = request.session.get('force_password_change_user_id')
        if not user_id:
            return redirect('login')
        
        # Get the user
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return redirect('login')
        
        # Check if user really needs to change password
        if not (hasattr(user, 'profile') and user.profile.force_password_change):
            return redirect('login')
            
        return super().dispatch(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user_id = self.request.session.get('force_password_change_user_id')
        user = User.objects.get(id=user_id)
        context['form'] = PasswordChangeForm(user)
        return context
    
    def post(self, request, *args, **kwargs):
        user_id = request.session.get('force_password_change_user_id')
        if not user_id:
            return redirect('login')
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return redirect('login')
        
        form = PasswordChangeForm(user, request.POST)
        if form.is_valid():
            # Save the new password
            user = form.save()
            
            # Update the force_password_change flag
            user.profile.force_password_change = False
            user.profile.save()
            
            # Authenticate the user with the new password
            username = user.username
            password = form.cleaned_data['new_password1']
            authenticated_user = authenticate(request, username=username, password=password)
            
            if authenticated_user is not None:
                # Login the user
                login(request, authenticated_user)
                
                # Remove the session flag
                if 'force_password_change_user_id' in request.session:
                    del request.session['force_password_change_user_id']
                
                messages.success(request, 'Your password has been changed successfully. You are now logged in.')
                return redirect('home')
            else:
                # If authentication fails, redirect to login page
                messages.success(request, 'Password changed successfully. Please login with your new password.')
                return redirect('login')
        
        return render(request, self.template_name, {'form': form})

# Create a custom LoginRequiredMixin that checks for password change
class PasswordChangeRequiredMixin:
    def dispatch(self, request, *args, **kwargs):
        # Check if user needs to change password
        if hasattr(request.user, 'profile') and request.user.profile.force_password_change:
            # Store user ID in session and redirect to password change
            request.session['force_password_change_user_id'] = request.user.id
            return redirect('force_password_change')
        return super().dispatch(request, *args, **kwargs)

# Create a new base class that combines both mixins
class AuthRequiredMixin(PasswordChangeRequiredMixin, LoginRequiredMixin):
    pass

class HomeView(AuthRequiredMixin, ListView):
    template_name = 'home.html'
    model = Ticket
    context_object_name = 'tickets'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Check user role
        try:
            profile = self.request.user.profile
            role = profile.role
        except Profile.DoesNotExist:
            Profile.objects.create(user=self.request.user, role='normal')
            role = 'normal'
        
        is_admin = self.request.user.is_superuser or self.request.user.is_staff or role == 'admin'
        is_support = role == 'support'
        
        # Get ticket counts based on user role
        if is_admin:
            context['total_solved'] = Ticket.objects.filter(status='solved').count()
            context['total_pending'] = Ticket.objects.filter(status='pending').count()
            context['total_in_process'] = Ticket.objects.filter(status='in_process').count()
            # Get all recent tickets for admin
            context['recent_tickets'] = Ticket.objects.all().order_by('-created_at')[:3]
        elif is_support:
            # For support staff, show tickets assigned to them
            context['total_solved'] = Ticket.objects.filter(assigned_to=self.request.user, status='solved').count()
            context['total_pending'] = Ticket.objects.filter(assigned_to=self.request.user, status='pending').count()
            context['total_in_process'] = Ticket.objects.filter(assigned_to=self.request.user, status='in_process').count()
            # Get support staff's assigned recent tickets
            context['recent_tickets'] = Ticket.objects.filter(assigned_to=self.request.user).order_by('-created_at')[:5]
        else:
            # Regular users
            context['total_solved'] = Ticket.objects.filter(created_by=self.request.user, status='solved').count()
            context['total_pending'] = Ticket.objects.filter(created_by=self.request.user, status='pending').count()
            context['total_in_process'] = Ticket.objects.filter(created_by=self.request.user, status='in_process').count()
            # Get user's recent tickets
            context['recent_tickets'] = Ticket.objects.filter(created_by=self.request.user).order_by('-created_at')[:5]
        
        # Get monthly data based on user role
        if is_admin:
            monthly_data = Ticket.objects.annotate(month=TruncMonth('created_at')).values('month', 'status').annotate(count=Count('id')).order_by('month')
        elif is_support:
            monthly_data = Ticket.objects.filter(assigned_to=self.request.user).annotate(month=TruncMonth('created_at')).values('month', 'status').annotate(count=Count('id')).order_by('month')
        else:
            monthly_data = Ticket.objects.filter(created_by=self.request.user).annotate(month=TruncMonth('created_at')).values('month', 'status').annotate(count=Count('id')).order_by('month')
        
        context['is_admin'] = is_admin
        context['is_support'] = is_support
        context['user_role'] = role
        
        # Prepare chart data
        months = sorted(set(d['month'].strftime('%Y-%m') for d in monthly_data)) if monthly_data else []
        solved = {m: 0 for m in months}
        pending = {m: 0 for m in months}
        in_process = {m: 0 for m in months}
        
        for d in monthly_data:
            month_str = d['month'].strftime('%Y-%m')
            if d['status'] == 'solved':
                solved[month_str] = d['count']
            elif d['status'] == 'pending':
                pending[month_str] = d['count']
            elif d['status'] == 'in_process':
                in_process[month_str] = d['count']

        chart_data = {
            'labels': months,
            'datasets': [
                {'label': 'Solved', 'data': [solved[m] for m in months], 'backgroundColor': 'rgba(75, 192, 192, 0.2)'},
                {'label': 'Pending', 'data': [pending[m] for m in months], 'backgroundColor': 'rgba(255, 206, 86, 0.2)'},
                {'label': 'In Process', 'data': [in_process[m] for m in months], 'backgroundColor': 'rgba(54, 162, 235, 0.2)'},
            ]
        }
        context['chart_data'] = json.dumps(chart_data)
        return context

    def get_queryset(self):
        # Check user role
        try:
            profile = self.request.user.profile
            role = profile.role
        except Profile.DoesNotExist:
            Profile.objects.create(user=self.request.user, role='normal')
            role = 'normal'
        
        is_admin = self.request.user.is_superuser or self.request.user.is_staff or role == 'admin'
        is_support = role == 'support'
        
        # Return appropriate tickets based on role
        if is_admin:
            return Ticket.objects.all().order_by('-created_at')[:10]
        elif is_support:
            return Ticket.objects.filter(assigned_to=self.request.user).order_by('-created_at')[:10]
        else:
            return Ticket.objects.filter(created_by=self.request.user).order_by('-created_at')[:10]

class TicketListView(AuthRequiredMixin, ListView):
    model = Ticket
    template_name = 'ticket_list.html'
    context_object_name = 'tickets'

    def get_queryset(self):
        qs = super().get_queryset()
        try:
            profile = self.request.user.profile
            role = profile.role
        except Profile.DoesNotExist:
            Profile.objects.create(user=self.request.user, role='normal')
            role = 'normal'

        if role == 'admin' or self.request.user.is_staff or self.request.user.is_superuser:
            pass
        elif role == 'support':
            qs = qs.filter(assigned_to=self.request.user)
        else:
            qs = qs.filter(created_by=self.request.user)
        search = self.request.GET.get('search')
        if search:
            qs = qs.filter(title__icontains=search) | qs.filter(description__icontains=search)
        return qs.order_by('-created_at')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Get all support users for display purposes
        support_users = User.objects.filter(profile__role='support', is_active=True)
        context['support_users'] = support_users
        return context

class TicketCreateView(AuthRequiredMixin, CreateView):
    model = Ticket
    form_class = TicketForm
    template_name = 'ticket_form.html'
    success_url = '/tickets/'

    def form_valid(self, form):
        ticket = form.save(commit=False)
        ticket.created_by = self.request.user
        ticket.save()
        # Auto-assign if created by normal user
        ticket.assign_to_least_busy_support()
        return super().form_valid(form)

class TicketUpdateView(AuthRequiredMixin, UpdateView):
    model = Ticket
    form_class = TicketForm
    template_name = 'ticket_form.html'
    success_url = '/tickets/'

    def get_queryset(self):
        qs = super().get_queryset()
        try:
            profile = self.request.user.profile
            role = profile.role
        except Profile.DoesNotExist:
            Profile.objects.create(user=self.request.user, role='normal')
            role = 'normal'
        if role != 'admin' and not self.request.user.is_staff and not self.request.user.is_superuser:
            qs = qs.filter(assigned_to=self.request.user) | qs.filter(created_by=self.request.user)
        return qs

class TicketDetailView(AuthRequiredMixin, DetailView):
    model = Ticket
    template_name = 'ticket_detail.html'

class TicketTypeListView(AuthRequiredMixin, ListView):
    model = TicketType
    template_name = 'ticket_type_list.html'
    context_object_name = 'ticket_types'

    def get_queryset(self):
        try:
            role = self.request.user.profile.role
        except Profile.DoesNotExist:
            Profile.objects.create(user=self.request.user, role='normal')
            role = 'normal'
        if role != 'admin' and not self.request.user.is_staff and not self.request.user.is_superuser:
            return TicketType.objects.none()
        return super().get_queryset()

class TicketTypeCreateView(AuthRequiredMixin, CreateView):
    model = TicketType
    fields = ['name']
    template_name = 'ticket_type_form.html'
    success_url = '/ticket-types/'

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_staff and not request.user.is_superuser:
            try:
                role = request.user.profile.role
                if role != 'admin':
                    messages.error(request, 'You do not have permission to create ticket types.')
                    return redirect('ticket_type_list')
            except Profile.DoesNotExist:
                messages.error(request, 'You do not have permission to create ticket types.')
                return redirect('ticket_type_list')
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        messages.success(self.request, 'Ticket type created successfully.')
        return super().form_valid(form)

class TicketTypeUpdateView(AuthRequiredMixin, UpdateView):
    model = TicketType
    fields = ['name']
    template_name = 'ticket_type_form.html'
    success_url = '/ticket-types/'

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_staff and not request.user.is_superuser:
            try:
                role = request.user.profile.role
                if role != 'admin':
                    messages.error(request, 'You do not have permission to edit ticket types.')
                    return redirect('ticket_type_list')
            except Profile.DoesNotExist:
                messages.error(request, 'You do not have permission to edit ticket types.')
                return redirect('ticket_type_list')
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        messages.success(self.request, 'Ticket type updated successfully.')
        return super().form_valid(form)

def delete_ticket_type(request, pk):
    if request.method == 'POST':
        if not request.user.is_staff and not request.user.is_superuser:
            try:
                role = request.user.profile.role
                if role != 'admin':
                    messages.error(request, 'You do not have permission to delete ticket types.')
                    return redirect('ticket_type_list')
            except Profile.DoesNotExist:
                messages.error(request, 'You do not have permission to delete ticket types.')
                return redirect('ticket_type_list')
        
        ticket_type = get_object_or_404(TicketType, pk=pk)
        ticket_type_name = ticket_type.name
        ticket_type.delete()
        messages.success(request, f'Ticket type "{ticket_type_name}" has been deleted successfully.')
    return redirect('ticket_type_list')

class UserCreateView(AuthRequiredMixin, CreateView):
    model = User
    form_class = UserCreateForm
    template_name = 'user_form.html'
    success_url = '/users/'

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_staff and not request.user.is_superuser:
            try:
                role = request.user.profile.role
                if role != 'admin':
                    messages.error(request, 'You do not have permission to create users.')
                    return redirect('user_list')
            except Profile.DoesNotExist:
                messages.error(request, 'You do not have permission to create users.')
                return redirect('user_list')
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        try:
            # Save the user but don't commit to database yet
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()  # Now commit to database
            
            # Set the object for the success URL
            self.object = user
            
            # Handle profile creation
            role = form.cleaned_data.get('role', 'normal')
            profile, created = Profile.objects.get_or_create(
                user=user,
                defaults={'role': role}
            )
            
            if not created:
                profile.role = role
                profile.save()
            
            messages.success(self.request, f'User {user.username} created successfully.')
            return HttpResponseRedirect(self.get_success_url())
            
        except Exception as e:
            messages.error(self.request, 'Please correct the errors below.')
            return self.form_invalid(form)

    def form_invalid(self, form):
        messages.error(self.request, 'Please correct the errors below.')
        return super().form_invalid(form)

class UserListView(AuthRequiredMixin, ListView):
    model = User
    template_name = 'user_list.html'
    context_object_name = 'users'

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_staff and not request.user.is_superuser:
            try:
                role = request.user.profile.role
                if role != 'admin':
                    return redirect('home')
            except Profile.DoesNotExist:
                return redirect('home')
        return super().dispatch(request, *args, **kwargs)

class ReportView(AuthRequiredMixin, ListView):
    model = Ticket
    template_name = 'report.html'
    context_object_name = 'tickets'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['form'] = ReportFilterForm(self.request.GET or None)
        context['title'] = 'Ticket Report'
        return context

    def get_queryset(self):
        qs = super().get_queryset()
        try:
            profile = self.request.user.profile
            role = profile.role
        except Profile.DoesNotExist:
            Profile.objects.create(user=self.request.user, role='normal')
            role = 'normal'
        
        if role == 'admin' or self.request.user.is_staff or self.request.user.is_superuser:
            pass
        elif role == 'support':
            qs = qs.filter(assigned_to=self.request.user)
        else:
            qs = qs.filter(created_by=self.request.user)
        
        form = ReportFilterForm(self.request.GET or None)
        if form.is_valid():
            start_date = form.cleaned_data.get('start_date')
            end_date = form.cleaned_data.get('end_date')
            status = form.cleaned_data.get('status')
            if start_date:
                qs = qs.filter(created_at__gte=start_date)
            if end_date:
                qs = qs.filter(created_at__lte=end_date)
            if status:
                qs = qs.filter(status=status)
        # FIXED: Changed .order() to .order_by()
        return qs.order_by('-created_at')

def user_update(request):
    if not request.user.is_staff and not request.user.is_superuser:
        try:
            role = request.user.profile.role
            if role != 'admin':
                messages.error(request, 'You do not have permission to edit users.')
                return redirect('user_list')
        except Profile.DoesNotExist:
            messages.error(request, 'You do not have permission to edit users.')
            return redirect('user_list')
    
    if request.method == 'POST':
        try:
            user_id = request.POST.get('user_id')
            user = User.objects.get(id=user_id)
            
            # Update user fields
            user.username = request.POST.get('username')
            user.first_name = request.POST.get('first_name')
            user.last_name = request.POST.get('last_name')
            user.email = request.POST.get('email')
            user.is_active = (request.POST.get('status') == 'active')
            user.save()
            
            # Update profile role if exists
            profile, created = Profile.objects.get_or_create(user=user)
            profile.role = request.POST.get('role', 'normal')
            profile.save()
            
            messages.success(request, f'User {user.username} updated successfully.')
            return redirect('user_list')
            
        except Exception as e:
            messages.error(request, f'Error updating user: {str(e)}')
            return redirect('user_list')
    
    messages.error(request, 'Invalid request method.')
    return redirect('user_list')

def activate_user(request, pk):
    if not request.user.is_staff and not request.user.is_superuser:
        try:
            role = request.user.profile.role
            if role != 'admin':
                return redirect('home')
        except Profile.DoesNotExist:
            return redirect('home')
    user = get_object_or_404(User, pk=pk)
    user.is_active = True
    user.save()
    messages.success(request, f'User {user.username} activated.')
    return redirect('user_list')

def deactivate_user(request, pk):
    if not request.user.is_staff and not request.user.is_superuser:
        try:
            role = request.user.profile.role
            if role != 'admin':
                return redirect('home')
        except Profile.DoesNotExist:
            return redirect('home')
    user = get_object_or_404(User, pk=pk)
    user.is_active = False
    user.save()
    messages.success(request, f'User {user.username} deactivated/locked.')
    return redirect('user_list')

def reset_password(request, pk):
    if not request.user.is_staff and not request.user.is_superuser:
        try:
            role = request.user.profile.role
            if role != 'admin':
                return redirect('home')
        except Profile.DoesNotExist:
            return redirect('home')
    user = get_object_or_404(User, pk=pk)
    user.set_password('Abcd123456.#')
    user.save()
    
    # Set force password change flag
    profile, created = Profile.objects.get_or_create(user=user)
    profile.force_password_change = True
    profile.save()
    
    messages.success(request, f'Password for {user.username} reset to default. User must change password on next login.')
    return redirect('user_list')

class CustomLogoutView(LogoutView):
    template_name = 'logout.html'
    
    def dispatch(self, request, *args, **kwargs):
        messages.info(request, "You have been successfully logged out.")
        return super().dispatch(request, *args, **kwargs)