from telegram.ext import Updater, CommandHandler, MessageHandler, StringRegexHandler, RegexHandler
from telegram.ext.filters import Filters
from telegram import ReplyKeyboardMarkup, InlineKeyboardMarkup, InlineKeyboardButton, ReplyKeyboardRemove
import logging
from peewee import DoesNotExist
from functools import wraps
from io import BytesIO
from PIL import Image

from .config import db, TOKEN, GOD_ID, GOD_NAME
from .models.users import User, Role
from .models.accounts import Account, TransactionUsed, SelfTransaction
from .models.transactions import Transaction
from .mwt import MWT

logger = logging.getLogger('bot')
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.DEBUG)
logger.setLevel(logging.DEBUG)

# create tables in db
db.create_tables([Transaction, User, Account], safe=True)

# create GOD if not exists
try:
    god = User.get(User.tg_id == GOD_ID)
except DoesNotExist:
    god = User.create(tg_id=GOD_ID, username=GOD_NAME, role=Role.GOD)
    Account.get_or_create(user=god)


user_keyboard = ReplyKeyboardMarkup([['pay', 'balance']])


@MWT(timeout=60*5)
def get_privilege_ids(role):
    logger.info("Update list of %s", role)
    return [user.tg_id for user in User.select().where(User.role >= role)]


def restricted(role):

    def wrapper(func):
        @wraps(func)
        def wrapped(bot, update, *args, **kwargs):
            user_id = update.effective_user.id
            if user_id not in get_privilege_ids(role):
                logger.warning("Unauthorized access by {}.".format(user_id))
                return
            return func(bot, update, *args, **kwargs)
        return wrapped

    return wrapper


@MWT(timeout=60*5)
def amounts_keyboard(user):
    challenge = user.challenge or user.own_challenge.get()
    amount = challenge.amount
    return ReplyKeyboardMarkup([[amount, amount/2]])


def start(bot, update):
    t_user = update.effective_user
    try:
        User.get(tg_id=t_user.id)
    except DoesNotExist:
        with db.atomic() as txn:
            user = User.create(tg_id=t_user.id, username=t_user.username)
            Account.create(user=user)
    bot.send_message(chat_id=update.message.chat_id,
                     text="Привет, %s!" % (t_user.first_name),
                     reply_markup=user_keyboard)


@restricted(Role.KP)
def generate(bot, update, args):
    tg_user = update.effective_user
    user = User.get(User.tg_id == tg_user.id)
    bot.send_message(chat_id=update.message.chat_id,
                     text="Send me amount of transaction",
                     reply_markup=amounts_keyboard(user))


def approve(bot, update):
    photo = update.message.photo[-1].get_file()
    bytesarray = photo.download_as_bytearray()
    qr = Image.open(BytesIO(bytesarray))
    try:
        transactions = Transaction.from_qr(qr)
    except Exception as e:
        logger.warning(e)
        bot.send_message(chat_id=update.message.chat_id,
                         text="Hacker? ._.")
        return
    if not transactions:
        self.logger.debug("Didn't recognize QR-codes on photo")
        bot.send_message(chat_id=update.message.chat_id,
                         text="Transaction not found")
        return
    tg_user = update.effective_user
    user = User.get(User.tg_id == tg_user.id)
    account = user.account.get()
    for transaction in transactions:
        try:
            account.approve(transaction)
            text = "Added %d CMCoins" % transaction.amount
        except TransactionUsed:
            text = "Transaction was used"
            self.logger.debug('Transaction was used')
        except SelfTransaction:
            text = "You can't use your's transaction"
            self.logger.debug("You can't use your's transaction")
        except Exception as e:
            text = "Something go wrong ☠️\nWrite to @dsp25no"
            self.logger.critical(e)
        bot.send_message(chat_id=update.message.chat_id,
                         text=text)


def balance(bot, update):
    tg_user = update.effective_user
    user = User.get(User.tg_id == tg_user.id)
    account = user.account.get()
    bot.send_message(chat_id=update.message.chat_id,
                     text="You have %d CMCoins" % account.score)


def pay(bot, update):
    bot.send_message(chat_id=update.message.chat_id,
                     text="Send me amount of transaction",
                     reply_markup=ReplyKeyboardRemove())


@restricted(Role.ADMIN)
def make_user(bot, update, args):
    if len(args) != 1:
        bot.send_message(chat_id=update.message.chat_id,
                         text="Wrong format!\n/make_user username")
        return
    username = args[0]
    try:
        user = User.get(User.username == username)
    except DoesNotExist:
        bot.send_message(chat_id=update.message.chat_id,
                         text="No such user")
        return
    admin_user = User.get(User.tg_id == update.effective_user.id)
    if (admin_user.role == Role.ADMIN and
            admin_user.own_challenge.get() != user.challenge):
        bot.send_message(chat_id=update.message.chat_id,
                         text="It's not your slave")
        return
    user.role = Role.USER
    user.challenge = None
    user.save()
    bot.send_message(chat_id=update.message.chat_id,
                     text="Success")
    bot.send_message(chat_id=user.tg_id,
                     text="You become simple user",
                     reply_markup=user_keyboard)


@restricted(Role.ADMIN)
def make_kp(bot, update, args):
    request_user = User.get(User.tg_id == update.effective_user.id)
    try:
        challenge = request_user.own_challenge.get()
    except:
        challenge = None

    if not challenge and len(args) != 2:
        bot.send_message(chat_id=update.message.chat_id,
                         text="Wrong format!\n/make_kp username challenge_name")
        return

    username = args[0]
    challenge = challenge or args[1]

    try:
        user = User.get(User.username == username)
    except DoesNotExist:
        bot.send_message(chat_id=update.message.chat_id,
                         text="No such user")
    user.role = Role.KP
    user.challenge = challenge
    user.save()
    bot.send_message(chat_id=update.message.chat_id,
                     text="Success")
    bot.send_message(chat_id=user.tg_id,
                     text="You become KP of %s" % challenge.name)  # TODO: keyboard


@restricted(Role.USER)
def transaction(bot, update):
    amount = update.message.text
    t_user = update.effective_user
    user = User.get(User.tg_id == t_user.id)
    if user.role == Role.USER:
        account = user.account.get()
        if account.score < amount:
            bot.send_message(chat_id=update.message.chat_id,
                             text="Not enougth CMCoins")
            return
        with db.atomic() as txn:
            transaction = Transaction.create(amount=amount, actor=user)
            account.score -= amount
            account.save()
        qr = transaction.to_qr()
        qr_bytes = BytesIO()
        qr_bytes.name = 'qr.png'
        qr.save(qr_bytes)
        qr_bytes.seek(0)
        bot.send_photo(chat_id=update.message.chat_id,
                       photo=qr_bytes,
                       reply_markup=amounts_keyboard())
        return

    if user.role == Role.KP:
        challenge = user.challenge
        if not challenge.crazy and amount > challenge.amount:
            bot.send_message(chat_id=update.message.chat_id,
                             text="😡")
    transaction = Transaction.create(amount=amount, actor=user)
    qr = transaction.to_qr()
    qr_bytes = BytesIO()
    qr_bytes.name = 'qr.png'
    qr.save(qr_bytes)
    qr_bytes.seek(0)
    bot.send_photo(chat_id=update.message.chat_id,
                   photo=qr_bytes,
                   reply_markup=user_keyboard)


@restricted(Role.GOD)
def make_challenge(bot, update, args):
    if len(args) != 3:
        bot.send_message(chat_id=update.message.chat_id,
                         text="Wrong format!\n/make_challenge challenge_name admin_username max_amount")
    challenge_name = args[0]
    admin_username = args[1]
    max_amount = args[2]

    try:
        admin = User.get(User.username == admin_username)
    except DoesNotExist:
        bot.send_message(chat_id=update.message.chat_id,
                         text="No such user")
        return

    try:
        max_amount = int(max_amount)
    except ValueError:
        bot.send_message(chat_id=update.message.chat_id,
                         text="Wrong max amount")

    with db.atom() as txn:
        challenge = Challenge.create(name=challenge_name,
                                     admin=admin, amount=max_amount)
        admin.role = Role.ADMIN

    bot.send_message(chat_id=update.message.chat_id,
                     text="Success")
    bot.send_message(chat_id=admin.tg_id,
                     text="You become an admin of %s" % challenge_name)


def sleep(bot, update, args):
        from time import sleep
        sleep(args[0])
        bot.send_message(chat_id=update.message.chat_id,
                         text="Success")


updater = Updater(token=TOKEN)
dispatcher = updater.dispatcher
dispatcher.add_handler(CommandHandler('start', start))
dispatcher.add_handler(MessageHandler(Filters.photo, approve))
dispatcher.add_handler(CommandHandler('generate', generate, pass_args=True))
dispatcher.add_handler(RegexHandler('balance', balance))
dispatcher.add_handler(RegexHandler('pay', pay))
dispatcher.add_handler(CommandHandler('make_user', make_user, pass_args=True))
dispatcher.add_handler(CommandHandler('make_kp', make_kp, pass_args=True))
dispatcher.add_handler(RegexHandler('\d+', transaction))
dispatcher.add_handler(CommandHandler('make_challenge', make_challenge, pass_args=True))
dispatcher.add_handler(CommandHandler('sleep', sleep, pass_args=True))

if __name__ == '__main__':
    updater.start_polling()
