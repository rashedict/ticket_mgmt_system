from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from core.models import Profile

class Command(BaseCommand):
    help = 'Creates profiles for users that do not have one'

    def handle(self, *args, **options):
        users_without_profile = User.objects.filter(profile__isnull=True)
        count = 0
        for user in users_without_profile:
            Profile.objects.create(user=user, role='normal')
            self.stdout.write(self.style.SUCCESS(f'Created profile for user: {user.username}'))
            count += 1
        self.stdout.write(self.style.SUCCESS(f'Total profiles created: {count}'))