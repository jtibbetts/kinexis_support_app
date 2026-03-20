  # Single file (existing behavior)
  python manage.py refresh_secrets ~/.config/openchannel/env.dev

  # All env files in a directory
  python manage.py refresh_secrets --all-in ~/.config/openchannel