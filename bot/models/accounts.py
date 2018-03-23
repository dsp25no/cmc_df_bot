from peewee import *
import datetime
import logging

from bot.config import db
from bot.models.users import User, Role

logger = logging.getLogger('bot')


class TransactionUsed(Exception):
    pass


class SelfTransaction(Exception):
    pass


class Account(Model):
    user = ForeignKeyField(User, backref='account')
    score = IntegerField(default=0)

    @db.atomic()
    def approve(self, transaction):
        if transaction.acceptor is not None:
            raise TransactionUsed()
        if transaction.actor is self:
            raise SelfTransaction()

        transaction.acceptor = self
        transaction.approve_time = datetime.datetime.now()
        if user.role != Role.SHOP:
            self.score += transaction.amount
        try:
            self.save()
            transaction.save()
        except Exception as e:
            logger.error(e)
            raise e

    class Meta:
        database = db
        # depends_on = User
