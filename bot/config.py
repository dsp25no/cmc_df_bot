from peewee import PostgresqlDatabase
import os

SECRET = os.environ.get('SECRET')
POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD')
POSTGRES_USER = os.environ.get('POSTGRES_USER')
POSTGRES_DB = os.environ.get('POSTGRES_DB')
TOKEN = os.environ.get('TOKEN')
GOD_ID = os.environ.get('GOD_ID')
GOD_NAME = os.environ.get('GOD_NAME')

db = PostgresqlDatabase(
    POSTGRES_DB,
    user=POSTGRES_USER,
    password=POSTGRES_PASSWORD,
    host='db')

# # for debug
# from peewee import SqliteDatabase
# import base64
#
# db = SqliteDatabase('bot.db')
# SECRET = base64.b64encode(open('secret', 'rb').read())
# TOKEN = '565567133:AAFrjt4yMptoRC1FUt8kB4RqTi1IoIEdnYY'
