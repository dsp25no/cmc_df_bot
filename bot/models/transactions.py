from peewee import *
from uuid import uuid4, UUID
import qrcode
import pyzbar.pyzbar as pyzbar
import datetime

from bot.crypto import Cipher
from bot.config import db
from bot.models.accounts import Account


class Transaction(Model):
    uuid = UUIDField(default=uuid4, unique=True)
    amount = IntegerField()
    actor = ForeignKeyField(Account, backref='payments')
    acceptor = ForeignKeyField(Account, backref='profits', null=True,
                               default=None)
    created_time = DateTimeField(default=datetime.datetime.now)
    approve_time = DateTimeField(default=None, null=True)
    generated = BooleanField(default=False)
    exchanged = BooleanField(default=False)

    def to_qr(self):
        qr = qrcode.make(Cipher.encrypt(self.uuid.bytes))
        return qr._img  # return normal PIL image

    @classmethod
    def from_qr(cls, img):
        res = pyzbar.decode(img)
        uuids = []
        for cipher_text, _type in res:
            if _type == 'QRCODE':
                uuids.append(UUID(bytes=Cipher.decrypt(cipher_text)))
        return [cls.get(cls.uuid == uuid) for uuid in uuids]

    class Meta:
        database = db
