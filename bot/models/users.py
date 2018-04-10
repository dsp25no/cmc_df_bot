from peewee import *
from enum import IntEnum

from bot.config import db


class Role(IntEnum):
    SHOP = 0
    USER = 1
    KP = 2
    ADMIN = 3
    GOD = 4


class RoleField(Field):
    field_type = 'smallint'

    def db_value(self, value):
        return int(value)

    def python_value(self, value):
        return Role(value)


class User(Model):
    tg_id = IntegerField(unique=True)
    username = CharField(null=True)
    role = RoleField(default=Role.USER)
    challenge = DeferredForeignKey('Challenge',
                                   default=None,
                                   null=True,
                                   backref="kp")

    class Meta:
        database = db
        # constraints = [Check('challenge_id == None or role == 2')]


class Challenge(Model):
    name = CharField()
    admin = ForeignKeyField(User, backref="own_challenge", null=False)
    amount = IntegerField()
    finished = BooleanField(default=False)
    crazy = BooleanField(default=False)

    class Meta:
        database = db
