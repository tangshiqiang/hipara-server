import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECRET_KEY = os.environ['DJANGO_SECRET_KEY']

DEBUG = True

DEMO = True

ALLOWED_HOSTS = []

INSTALLED_APPS = (
	'django.contrib.admin',
	'django.contrib.auth',
	'django.contrib.contenttypes',
	'django.contrib.sessions',
	'django.contrib.messages',
	'django.contrib.staticfiles',
	'djcelery',
	'rest_framework',
	'registration',
	'rule_manager',
	'alert',
	'settings',
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
		'NAME': os.environ['MYSQL_DATABASE'],
		'USER': os.environ['MYSQL_USER'],
		'PASSWORD': os.environ['MYSQL_PASSWORD'],
		'HOST': os.environ['DJANGO_MYSQL_HOST'],
		'PORT': os.environ['DJANGO_MYSQL_PORT'],
	}
}

LANGUAGE_CODE = 'en-us'

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

EMAIL_BACKEND = 'django.core.mail.backends.filebased.EmailBackend'
EMAIL_FILE_PATH = os.path.join(BASE_DIR, 'email')

SESSION_COOKIE_NAME = os.environ['DJANGO_SESSION_COOKIE_NAME']
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_COOKIE_AGE = 86400

AUTHENTICATION_BACKENDS = ['django-dual-authentication.backends.DualAuthentication']
AUTHENTICATION_METHOD = 'both'
AUTHENTICATION_CASE_SENSITIVE = 'both'

# Celery config

# redis server address
REDIS_HOST = "redis://%s:%s/0" % (os.environ.get('REDIS_HOST', 'localhost'), os.environ.get('REDIS_PORT', '6379'))
BROKER_URL = REDIS_HOST
# store task results in redis
CELERY_RESULT_BACKEND = REDIS_HOST
# task result life time until they will be deleted
CELERY_TASK_RESULT_EXPIRES = 7*86400  # 7 days
# needed for worker monitoring
CELERY_SEND_EVENTS = True
# where to store periodic tasks (needed for scheduler)
CELERYBEAT_SCHEDULER = "djcelery.schedulers.DatabaseScheduler"

# add following lines to the end of settings.py
import djcelery
djcelery.setup_loader()

# GRR server settings
GRR_HOST_URL = os.environ.get('GRR_HOST_URL')
GRR_USER_NAME = os.environ.get('GRR_USER_NAME')
GRR_USER_PASSWORD = os.environ.get('GRR_USER_PASSWORD')