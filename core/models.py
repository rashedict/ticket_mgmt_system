from django.db import models
from django.contrib.auth.models import User
from django.db.models import Count
from django.db.models.signals import post_save
from django.dispatch import receiver

class Profile(models.Model):
    ROLE_CHOICES = [
        ('normal', 'Normal User'),
        ('support', 'Support Staff'),
        ('admin', 'Administrator'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='normal')
    force_password_change = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.user.username} - {self.role}"

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if hasattr(instance, 'profile'):
        instance.profile.save()

class TicketType(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name

class Ticket(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_process', 'In Process'),
        ('solved', 'Solved'),
    ]
    title = models.CharField(max_length=200)
    description = models.TextField()
    ticket_type = models.ForeignKey(TicketType, on_delete=models.SET_NULL, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_by = models.ForeignKey(User, related_name='created_tickets', on_delete=models.CASCADE)
    assigned_to = models.ForeignKey(User, related_name='assigned_tickets', on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

    def assign_to_least_busy_support(self):
        """
        Assign ticket to the support staff with the fewest assigned tickets
        to ensure equal distribution
        """
        # Get all active support users
        support_profiles = Profile.objects.filter(role='support', user__is_active=True)
        
        if not support_profiles.exists():
            return False
        
        # Count tickets assigned to each support staff (excluding solved tickets if desired)
        support_users = [profile.user for profile in support_profiles]
        
        # Get ticket counts for each support staff
        ticket_counts = Ticket.objects.filter(
            assigned_to__in=support_users
        ).exclude(status='solved').values('assigned_to').annotate(
            count=Count('id')
        )
        
        # Create a dictionary of user_id to ticket count
        count_dict = {item['assigned_to']: item['count'] for item in ticket_counts}
        
        # Find the support staff with the fewest tickets
        least_busy_user = None
        min_count = float('inf')
        
        for user in support_users:
            current_count = count_dict.get(user.id, 0)
            if current_count < min_count:
                min_count = current_count
                least_busy_user = user
        
        if least_busy_user:
            self.assigned_to = least_busy_user
            self.save()
            return True
        
        return False

    def save(self, *args, **kwargs):
        # Call assign_to_least_busy_support when creating a new ticket (not updating)
        is_new = self.pk is None
        super().save(*args, **kwargs)
        
        # Auto-assign only when creating a new ticket
        if is_new and not self.assigned_to:
            self.assign_to_least_busy_support()

# Safe method to get user profile
def get_user_profile(self):
    try:
        return self.profile
    except Profile.DoesNotExist:
        profile, created = Profile.objects.get_or_create(
            user=self, 
            defaults={'role': 'normal'}
        )
        return profile

# Add the method to User model
User.add_to_class('get_profile', get_user_profile)