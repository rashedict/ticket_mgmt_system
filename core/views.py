import logging
import json
from datetime import timedelta

from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic import (
    ListView, CreateView, UpdateView, DetailView, TemplateView
)
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView, LogoutView
from django.db.models import Count
from django.db.models.functions import TruncMonth
from django.http import JsonResponse, HttpResponseRedirect
from django.contrib.auth.models import User
from django.contrib.auth import update_session_auth_hash, login, authenticate, logout
from django.contrib import messages
from django.utils import timezone

from .models import Ticket, TicketType, Profile
from .forms import (
    TicketForm, TicketTypeForm, ReportFilterForm,
    UserCreateForm, PasswordChangeForm
)

# --------------------------------------------------
# Logger
# --------------------------------------------------
logger = logging.getLogger(__name__)


class CustomLoginView(LoginView):
    template_name = 'login.html'

    def form_valid(self, form):
        user = form.get_user()
        logger.info("Login successful: user=%s", user.username)

        if hasattr(user, 'profile') and user.profile.force_password_change:
            logger.warning("Force password change required: user=%s", user.username)
            self.request.session['force_password_change_user_id'] = user.id
            return redirect('force_password_change')

        messages.success(self.request, f'Welcome back, {user.username}!')
        return super().form_valid(form)

    def form_invalid(self, form):
        logger.warning(
            "Login failed from IP=%s",
            self.request.META.get("REMOTE_ADDR")
        )
        messages.error(self.request, 'Invalid username or password.')
        return super().form_invalid(form)


class ForcePasswordChangeView(TemplateView):
    template_name = 'force_password_change.html'

    def dispatch(self, request, *args, **kwargs):
        user_id = request.session.get('force_password_change_user_id')
        if not user_id:
            return redirect('login')

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return redirect('login')

        if not user.profile.force_password_change:
            return redirect('login')

        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = User.objects.get(id=self.request.session['force_password_change_user_id'])
        context['form'] = PasswordChangeForm(user)
        return context

    def post(self, request, *args, **kwargs):
        user = User.objects.get(id=request.session['force_password_change_user_id'])
        form = PasswordChangeForm(user, request.POST)

        if form.is_valid():
            user = form.save()
            user.profile.force_password_change = False
            user.profile.save()

            logger.warning("Password changed: user=%s", user.username)

            login(request, user)
            del request.session['force_password_change_user_id']
            messages.success(request, 'Password changed successfully.')
            return redirect('home')

        return render(request, self.template_name, {'form': form})


class PasswordChangeRequiredMixin:
    def dispatch(self, request, *args, **kwargs):
        if hasattr(request.user, 'profile') and request.user.profile.force_password_change:
            request.session['force_password_change_user_id'] = request.user.id
            return redirect('force_password_change')
        return super().dispatch(request, *args, **kwargs)


class AuthRequiredMixin(PasswordChangeRequiredMixin, LoginRequiredMixin):
    pass


class HomeView(AuthRequiredMixin, ListView):
    template_name = 'home.html'
    model = Ticket
    context_object_name = 'tickets'

    def get_queryset(self):
        try:
            role = self.request.user.profile.role
        except Profile.DoesNotExist:
            Profile.objects.create(user=self.request.user, role='normal')
            role = 'normal'

        if role == 'admin' or self.request.user.is_staff:
            return Ticket.objects.all().order_by('-created_at')[:10]
        elif role == 'support':
            return Ticket.objects.filter(
                assigned_to=self.request.user
            ).order_by('-created_at')[:10]
        return Ticket.objects.filter(
            created_by=self.request.user
        ).order_by('-created_at')[:10]


class TicketListView(AuthRequiredMixin, ListView):
    model = Ticket
    template_name = 'ticket_list.html'
    context_object_name = 'tickets'

    def get_queryset(self):
        qs = super().get_queryset()
        role = self.request.user.profile.role

        if role == 'support':
            qs = qs.filter(assigned_to=self.request.user)
        elif role == 'normal':
            qs = qs.filter(created_by=self.request.user)

        search = self.request.GET.get('search')
        if search:
            qs = qs.filter(title__icontains=search)

        return qs.order_by('-created_at')


class TicketCreateView(AuthRequiredMixin, CreateView):
    model = Ticket
    form_class = TicketForm
    template_name = 'ticket_form.html'
    success_url = '/tickets/'

    def form_valid(self, form):
        ticket = form.save(commit=False)
        ticket.created_by = self.request.user
        ticket.save()
        ticket.assign_to_least_busy_support()

        logger.info(
            "Ticket created: id=%s title=%s user=%s",
            ticket.id, ticket.title, self.request.user.username
        )
        return super().form_valid(form)


class TicketUpdateView(AuthRequiredMixin, UpdateView):
    model = Ticket
    form_class = TicketForm
    template_name = 'ticket_form.html'
    success_url = '/tickets/'

    def form_valid(self, form):
        ticket = form.save()
        logger.info(
            "Ticket updated: id=%s status=%s by user=%s",
            ticket.id, ticket.status, self.request.user.username
        )
        return super().form_valid(form)


class TicketDetailView(AuthRequiredMixin, DetailView):
    model = Ticket
    template_name = 'ticket_detail.html'


class TicketTypeCreateView(AuthRequiredMixin, CreateView):
    model = TicketType
    fields = ['name']
    template_name = 'ticket_type_form.html'
    success_url = '/ticket-types/'

    def form_valid(self, form):
        logger.warning(
            "Ticket type created: %s by %s",
            form.cleaned_data['name'], self.request.user.username
        )
        return super().form_valid(form)


class UserCreateView(AuthRequiredMixin, CreateView):
    model = User
    form_class = UserCreateForm
    template_name = 'user_form.html'
    success_url = '/users/'

    def form_valid(self, form):
        user = form.save(commit=False)
        user.set_password(form.cleaned_data['password'])
        user.save()

        Profile.objects.create(user=user, role=form.cleaned_data.get('role', 'normal'))

        logger.warning(
            "User created: username=%s by admin=%s",
            user.username, self.request.user.username
        )

        messages.success(self.request, f'User {user.username} created.')
        return HttpResponseRedirect(self.get_success_url())


def reset_password(request, pk):
    user = get_object_or_404(User, pk=pk)
    user.set_password('Abcd123456.#')
    user.save()

    profile, _ = Profile.objects.get_or_create(user=user)
    profile.force_password_change = True
    profile.save()

    logger.warning(
        "Password reset by admin=%s for user=%s",
        request.user.username, user.username
    )

    messages.success(request, f'Password reset for {user.username}.')
    return redirect('user_list')


class CustomLogoutView(LogoutView):
    template_name = 'logout.html'

    def dispatch(self, request, *args, **kwargs):
        logger.info("User logged out: %s", request.user.username)
        messages.info(request, "Logged out successfully.")
        return super().dispatch(request, *args, **kwargs)
