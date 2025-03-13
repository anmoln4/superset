import os
import boto3
import json
import requests
import base64

from botocore.exceptions import ClientError

# Superset specific config
ROW_LIMIT = 50000

SUPERSET_WEBSERVER_PORT = 8088
SUPERSET_WORKERS = 16  # os.getenv('APP_WORKERS','2')
# print("superset_Workers----->",SUPERSET_WORKERS)

# ---------------------------------------------------------
# Flask App Builder configuration
# ---------------------------------------------------------
# Your App secret key
SECRET_KEY = 'CoqajHIpJ92SUN2llbxhpe9t5DI7aoyzjoGnMA8izgAtLVB/I/UHBq6p'

# ---------------------------------------------------------
db_name = os.getenv('DB_IDENK', 'Superset')
db_hostname = os.getenv('DB_HOST','database-1.cftakoabckjk.ap-south-1.rds.amazonaws.com')
db = os.getenv('DB_VENDOR','postgresql')
secret_name = os.getenv('SM_IDENK','rds!db-f58a82e8-613e-4b54-b838-83b7f8efea9d')
region_name = os.getenv('REGION_NAME','ap-south-1')
db_schema = os.getenv('DB_SCHEMA', 'public')
# OpenBao-specific environment variables
vault_enabled = os.getenv('VAULT_ENABLED', 'FALSE').lower() == 'true'
vault_url = os.getenv('VAULT_URL', '')
vault_url_redis = os.getenv('VAULT_URL_REDIS', '')

def get_openbao_token(token_path):
    try:
        with open(token_path, 'r') as file:
            token = file.read().strip()
        return token
    except Exception as e:
        print(f"Error reading token from {token_path}: {e}")
        return None

vault_token = get_openbao_token(os.getenv('VAULT_TOKEN_PATH'))
# print("Fetched vault token:", get_openbao_token(os.getenv('VAULT_TOKEN_PATH')))

# Function to fetch secrets from OpenBao

def get_openbao_secret(vault_url, vault_token):
    headers = {'X-Vault-Token': vault_token}
    try:
        response = requests.get(vault_url, headers=headers)
        response.raise_for_status()  # Raise an error for HTTP status codes 4xx/5xx
        secret = response.json()
        if 'data' in secret:
            return secret['data']
        else:
            raise KeyError("Expected 'data' key in OpenBao response")
    except requests.RequestException as e:
        print(f"Error fetching OpenBao secret: {e}")
        raise

# Function to fetch secrets from AWS Secrets Manager
def get_aws_secret(secret_name, region_name):
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=region_name)
    
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return json.loads(secret)  # Parse JSON string if needed
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])
        #print("secret ----->",secret)
        return json.loads(secret)  # returns the secret as dictionary
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        else:
            raise e
    return NULL
        
# Function to determine which secret manager to use
def get_secret():
  if vault_enabled:
    print("Fetching secret from OpenBao...")
    secret = get_openbao_secret(vault_url, vault_token)
    if 'username' not in secret or 'password' not in secret:
      raise KeyError("OpenBao secret missing 'username' or 'password' keys")
    return secret
  else:
    print("Fetching secret from AWS Secrets Manager...")
    return get_aws_secret(secret_name, region_name)

# Fetch secrets and extract credentials
fetch_secret = get_secret()
# print("get secret:", fetch_secret)
db_username = fetch_secret.get('username')
db_pass = fetch_secret.get('password')

# Construct the SQLAlchemy URI (remains unchanged)
SQLALCHEMY_DATABASE_URI = db+'://'+db_username+':'+db_pass+'@'+db_hostname+'/'+db_name+'?options=-csearch_path='+db_schema


# Maximum number of rows returned for any analytical database query
SQL_MAX_ROW = 50000

# Maximum number of rows displayed in SQL Lab UI
# Is set to avoid out of memory/localstorage issues in browsers. Does not affect
# exported CSVs
#DISPLAY_MAX_ROW = 100000

# Default row limit for SQL Lab queries. Is overridden by setting a new limit in
# the SQL Lab UI
#DEFAULT_SQLLAB_LIMIT = 100000
#VIZ_ROW_LIMIT = 100000
# max rows retrieved by filter select auto complete
#FILTER_SELECT_ROW_LIMIT = 100000

  # Flask-WTF flag for CSRF
WTF_CSRF_ENABLED = False
  # Add endpoints that need to be exempt from CSRF protection
WTF_CSRF_EXEMPT_LIST = []

  # Set this API key to enable Mapbox visualizations
MAPBOX_API_KEY = ''


# Enables SWAGGER UI for superset openapi spec
# ex: http://localhost:8080/swaggerview/v1
FAB_API_SWAGGER_UI = True
FEATURE_FLAGS = {
    "ENABLE_TEMPLATE_PROCESSING": True,
    "EMBEDDED_SUPERSET": True,
    "DASHBOARD_RBAC":True,
    "DRILL_TO_DETAIL": True,
    "DRILL_BY": True,
    "GUEST_TOKEN": True,
    "HORIZONTAL_FILTER_BAR": True
    }

SECURE_SSL_REDIRECT = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "None"
SESSION_COOKIE_SECURE = True
#SESSION_COOKIE_SAMESITE = 'Lax'
#SESSION_COOKIE_SECURE = False
ENABLE_PROXY_FIX = True
#PUBLIC_ROLE_LIKE = 'APPUSER'
#AUTH_ROLE_PUBLIC= 'Public'
HTTP_HEADERS = {'X-Frame-Options': 'ALLOWALL'}
GUEST_ROLE_NAME = "DashboardEmbedding"
ENABLE_CORS = True
APP_SX_DOMAIN=os.getenv('APP_SX_DOMAIN')
ANALYTICS_DOMAIN=os.getenv('ANALYTICS_DOMAIN')
CORS_OPTIONS = {
  'supports_credentials': True,
  'allow_headers': ['*'],
  'resources':['*'],
  'origins': ['\''+APP_SX_DOMAIN+'\'','\''+ANALYTICS_DOMAIN+'\'']
}

SQLLAB_BACKEND_PERSISTENCE = True

# Visual Customizations
APP_NAME = "AnalytiXplore"
APP_ICON = "/static/assets/images/AnalyticXploreUpdated.png"

#Enable HTTPS
ENABLE_PROXY_FIX= True
#PROXY_FIX_CONFIG = {"x_for": 1, "x_proto": 1, "x_host": 1, "x_port": 0, "x_prefix": 1}
#set the scheme to "https"
PREFERRED_URL_SCHEME= 'https'

ALERT_REPORTS_NOTIFICATION_DRY_RUN = True
WEBDRIVER_BASEURL = "https://superset:8088/"
# The base URL for the email report hyperlinks.
WEBDRIVER_BASEURL_USER_FRIENDLY = WEBDRIVER_BASEURL

SQLLAB_CTAS_NO_LIMIT = True

SQLLAB_TIMEOUT=300
SUPERSET_WEBSERVER_TIMEOUT = 300
CUSTOM_HEADER_MESSAGE ="Welcome to Analytics"
TALISMAN_ENABLED = False

# FAB Rate limiting: this is a security feature for preventing DDOS attacks. The
# feature is on by default to make Superset secure by default, but you should
# fine tune the limits to your needs. You can read more about the different
# parameters here: https://flask-limiter.readthedocs.io/en/stable/configuration.html
RATELIMIT_ENABLED = True
RATELIMIT_APPLICATION = "50 per second"
AUTH_RATE_LIMITED = True
AUTH_RATE_LIMIT = "5 per second"

#Redis Config
secret_name_redis = os.getenv('REDIS_SM')

def get_openbao_secret_redis(vault_url_redis, vault_token):
    headers = {'X-Vault-Token': vault_token}
    try:
        response = requests.get(vault_url_redis, headers=headers)
        response.raise_for_status()  # Raise an error for HTTP status codes 4xx/5xx
        secret_redis = response.json()
        if 'data' in secret_redis:
            return secret_redis['data']
        else:
            raise KeyError("Expected 'data' key in OpenBao response")
    except requests.RequestException as e:
        print(f"Error fetching OpenBao secret: {e}")
        raise

# Function to fetch secrets from AWS Secrets Manager
def get_aws_secret_redis(secret_name_redis, region_name):
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=region_name)
    
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name_redis)
        if 'SecretString' in get_secret_value_response:
            secret_redis = get_secret_value_response['SecretString']
            return json.loads(secret_redis)  # Parse JSON string if needed
        else:
            secret_redis = base64.b64decode(get_secret_value_response['SecretBinary'])
        #print("secret ----->",secret)
        return json.loads(secret_redis)  # returns the secret as dictionary
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        else:
            raise e
    return NULL

        
# Function to determine which secret manager to use
def get_secret_redis():
  if vault_enabled:
    print("Fetching redis secret from OpenBao...")
    secret_redis = get_openbao_secret_redis(vault_url_redis, vault_token)['data']
    if 'username' not in secret_redis or 'password' not in secret_redis or 'master' not in secret_redis or 'port' not in secret_redis:
      raise KeyError("OpenBao secret missing 'username' or 'password' or 'master' or 'port' keys")
    return secret_redis
  else:
    print("Fetching redis secret from AWS Secrets Manager...")
    return get_aws_secret_redis(secret_name_redis, region_name)
    
fetch_secret_redis=get_secret_redis()

#print("fetch_secret_redis-->",fetch_secret_redis)
#print("redis username------>",fetch_secret_redis.get('username'))
redis_username=fetch_secret_redis.get('username','default')
#print('redis password------>',fetch_secret_redis.get('password'))
redis_pass=fetch_secret_redis.get('password')
redis_master=fetch_secret_redis.get('master')
#redis_host=fetch_secret_redis.get('host')
redis_port=fetch_secret_redis.get('port')
REDIS_URL = 'redis://'+redis_username+':'+redis_pass+'@'+redis_master+':'+redis_port+'/0'

FILTER_STATE_CACHE_CONFIG = {
'CACHE_TYPE': 'RedisCache',
'CACHE_DEFAULT_TIMEOUT': 43200,
'CACHE_KEY_PREFIX': 'superset_filter_cache',
'CACHE_REDIS_URL': REDIS_URL
}
EXPLORE_FORM_DATA_CACHE_CONFIG = {
'CACHE_TYPE': 'RedisCache',
'CACHE_DEFAULT_TIMEOUT': 43200,
'CACHE_KEY_PREFIX': 'superset_exploreformdata_cache',
'CACHE_REDIS_URL': REDIS_URL
}
CACHE_CONFIG = {
'CACHE_TYPE': 'RedisCache',
'CACHE_DEFAULT_TIMEOUT': 43200,
'CACHE_KEY_PREFIX': 'superset_cacheconfig_cache',
'CACHE_REDIS_URL': REDIS_URL
}
DATA_CACHE_CONFIG = {
'CACHE_TYPE': 'RedisCache',
'CACHE_DEFAULT_TIMEOUT': 43200,
'CACHE_KEY_PREFIX': 'superset_datacache_cache',
'CACHE_REDIS_URL': REDIS_URL
}


#Token Expiration limit
GUEST_TOKEN_JWT_EXP_SECONDS = 1500

# JWT_ACCESS_TOKEN_EXPIRES = 1800

# SESSION_COOKIE_EXPIRATION = 1800


#custom color scheme
EXTRA_CATEGORICAL_COLOR_SCHEMES = [
    {
        "id": "hcl_sw_color_scheme",
        "label": "HCL SW Color Scheme",
        "description": "A palette of HCL SW colors",
        "colors": [
        "#000078", "#043ace", "#2679ff", "#3c91ff",
        "#6faffd", "#15384e", "#006075", "#038d99",
        "#2ec0cb", "#4A4A56", "#8F8F8F", "#474747",
		"#121212"
    ],
    },
]


#QueuePool Changes
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_size': 100,            # Increase the pool size
    'max_overflow': 30,         # Allow more overflow connections
    'pool_timeout': 50,         # Increase timeout before declaring a connection as timed out
}
SUPERSET_WEBSERVER_THREADS = 8  # Reduce the number of concurrent threads if your database cannot handle the load

 
