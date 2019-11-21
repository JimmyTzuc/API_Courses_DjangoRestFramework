import os

_CONFIG = {
    'db': {
        'production': {
            'database': os.environ.get('DB_NAME', 'dacodes_db'),
            'username': os.environ.get('DB_USER', ''),
            'password': os.environ.get('DB_PASSWORD', ''),
            'host': os.environ.get('DB_HOST', ''),
            'port': os.environ.get('DB_PORT', ''),
            'pool': {
                'max': 1000,
                'overflow': 1500,
                'recycle': 3600
            }
        },
        'testing': {
            'database': os.environ.get('DB_NAME', 'drf_api'),
            'username': os.environ.get('DB_USER', 'postgres'),
            'password': os.environ.get('DB_PASSWORD', 'root'),
            'host': os.environ.get('DB_HOST', 'localhost'),
            'port': os.environ.get('DB_PORT', '5432'),
            'pool': {
                'max': 5,
                'overflow': 10,
                'recycle': 900
            }
        }

    },
    'server': {
        'port': 3000
    }
}

# Config Variables
DB = _CONFIG['db'].get(os.environ.get('FALCON_API', 'testing'))
SERVER = _CONFIG['server'].get(os.environ.get('DB_NAME', ''))
