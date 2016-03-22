import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    from secret_key import *
except ImportError:
    with open('secret_key.py', 'w') as out:
        chars = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'
        from django.utils.crypto import get_random_string
        out.write("SECRET_KEY = '{0}'".format(get_random_string(50, chars)))
    from secret_key import *

DEBUG = True

ALLOWED_HOSTS = []

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'registration',
    'rule_manager',
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.security.SecurityMiddleware',
)

ROOT_URLCONF = 'hipara.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates'), ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'hipara.wsgi.application'


DATABASES = {
    'sqlite': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'hipara.sqlite3'),
    },
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'mysql',
        'USER': 'bitroots',
        'PASSWORD': 'bitroots',
        'HOST': 'localhost',
        'PORT': '',
    }
}

LANGUAGE_CODE = 'en-us'
#Update timezone
TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

STATIC_URL = '/static/'
STATICFILES_DIRS = (
    os.path.join(BASE_DIR, 'static'),
)
MEDIA_URL = '/media/'

MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

STATIC_ROOT = 'staticfiles'
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    'compressor.finders.CompressorFinder',
)

#test SMTP
EMAIL_BACKEND = "djrill.mail.backends.djrill.DjrillBackend"
MANDRILL_API_KEY = "NdSCtKw7lEn77e9dtvfEQw"

##use following SMTP for PRODUCTION
# EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
# DEFAULT_FROM_EMAIL = 'no-reply@hipara.org'
# SERVER_EMAIL = 'brettcu@gmail.com'
# EMAIL_HOST = '<EMAIL_HOST>'
# EMAIL_PORT = <PORT>
# EMAIL_HOST_USER = '<HOST_EMAIL>'
# EMAIL_HOST_PASSWORD = '<HOST_EMAIL_PASSWORD>'

SESSION_COOKIE_NAME = 'bitroots_hipara'
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_COOKIE_AGE = 86400

AUTHENTICATION_BACKENDS = ['django-dual-authentication.backends.DualAuthentication']
AUTHENTICATION_METHOD = 'both'
AUTHENTICATION_CASE_SENSITIVE = 'both'
