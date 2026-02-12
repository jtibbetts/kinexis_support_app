from django.apps import AppConfig


class KinexisSupportConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'kinexis_support'

    def ready(self):
        pass
