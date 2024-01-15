# config.py
import pymysql.cursors

DATABASE_CONFIG = {
    'host': '', 
    'user': 'root',
    'password': '',
    'db': '',
    'charset': 'utf8',
    'cursorclass': pymysql.cursors.DictCursor
}

class Config:
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True
    MAIL_USERNAME = ''
    MAIL_PASSWORD = ''
