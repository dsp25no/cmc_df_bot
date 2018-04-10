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
        if transaction.actor == self:
            raise SelfTransaction()

        if self.user.role != Role.SHOP:
            acceptor = self
        else:
            acceptor = User.get(User.tg_id == 0).account.get()

        transaction.acceptor = acceptor
        transaction.approve_time = datetime.datetime.now()
        acceptor.score += transaction.amount
        try:
            acceptor.save()
            transaction.save()
        except Exception as e:
            logger.error(e)
            raise e

    class Meta:
        database = db
        # depends_on = User
