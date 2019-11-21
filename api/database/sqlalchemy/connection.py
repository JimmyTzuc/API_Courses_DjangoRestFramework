
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import sessionmaker
from sqlalchemy_utils import create_database, database_exists

from config.conf import DB

URL = 'postgresql://{0}:{1}@{2}:{3}/{4}'.format(DB['username'], DB['password'], DB['host'], DB['port'], DB['database'])

# Verifies if database exists, if it doesn't exist, a new database is created.

if not database_exists(URL):
    create_database(URL)

# create a configured "Session" class
engine = create_engine(URL, pool_size=DB['pool']['max'], max_overflow=DB['pool']['overflow'])
with engine.connect() as conn:
    conn.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)


Base = declarative_base()
