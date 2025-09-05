from django.contrib import admin
from django.urls import path
from core.views import (
    CustomLoginView, HomeView, TicketListView, TicketCreateView, TicketUpdateView, TicketDetailView,
    TicketTypeListView, TicketTypeCreateView, TicketTypeUpdateView, delete_ticket_type,
    ReportView, UserListView, UserCreateView, activate_user, deactivate_user, reset_password,
    user_update, ForcePasswordChangeView
)
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('', HomeView.as_view(), name='home'),
    path('tickets/', TicketListView.as_view(), name='ticket_list'),
    path('tickets/create/', TicketCreateView.as_view(), name='ticket_create'),
    path('tickets/<int:pk>/', TicketDetailView.as_view(), name='ticket_detail'),
    path('tickets/<int:pk>/update/', TicketUpdateView.as_view(), name='ticket_update'),
    path('ticket-types/', TicketTypeListView.as_view(), name='ticket_type_list'),
    path('ticket-types/create/', TicketTypeCreateView.as_view(), name='ticket_type_create'),
    path('ticket-types/<int:pk>/update/', TicketTypeUpdateView.as_view(), name='ticket_type_update'),
    path('ticket-types/<int:pk>/delete/', delete_ticket_type, name='ticket_type_delete'),
    path('reports/', ReportView.as_view(), name='report'),
    path('users/', UserListView.as_view(), name='user_list'),
    path('users/create/', UserCreateView.as_view(), name='user_create'),
    path('users/update/', user_update, name='user_update'),
    path('users/<int:pk>/activate/', activate_user, name='activate_user'),
    path('users/<int:pk>/deactivate/', deactivate_user, name='deactivate_user'),
    path('users/<int:pk>/reset-password/', reset_password, name='reset_password'),
    path('force-password-change/', ForcePasswordChangeView.as_view(), name='force_password_change'),
]