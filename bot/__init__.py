from telegram.ext import Updater, CommandHandler, MessageHandler, StringRegexHandler, RegexHandler
from telegram.ext.filters import Filters
from telegram import ReplyKeyboardMarkup, InlineKeyboardMarkup, InlineKeyboardButton, ReplyKeyboardRemove
import logging
from peewee import DoesNotExist
from functools import wraps
from io import BytesIO
from PIL import Image
from functools import reduce
import operator
import datetime

from .config import db, TOKEN, GOD_ID, GOD_NAME, MAX_SUM
from .models.users import User, Role, Challenge
from .models.accounts import Account, TransactionUsed, SelfTransaction
from .models.transactions import Transaction
from .mwt import MWT

logger = logging.getLogger('bot')
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)
logger.setLevel(logging.DEBUG)

# create tables in db
db.create_tables([Transaction, User, Account], safe=True)
db.create_tables([Challenge], safe=True)

# create GOD if not exists
try:
    god = User.get(User.tg_id == GOD_ID)
except DoesNotExist:
    god = User.create(tg_id=GOD_ID, username=GOD_NAME, role=Role.GOD)
    Account.get_or_create(user=god)

# create  account if not exists
try:
    shop = User.get(User.tg_id == 0)
except DoesNotExist:
    shop = User.create(tg_id=0, username='crew', role=Role.SHOP)
    Account.get_or_create(user=shop)

GENERATED_SUM = reduce(
    lambda x, y: x + y.amount,
    Transaction.select().where(Transaction.generated == True),
    0
)

EXCHANGED_SUM = reduce(
    lambda x, y: x + y.amount,
    Transaction.select().where(Transaction.exchanged == True),
    0
)

user_keyboard = ReplyKeyboardMarkup([['pay', 'balance']], resize_keyboard=True)
cancel_keyboard = ReplyKeyboardMarkup(
                    [['cancel']],
                    resize_keyboard=True, one_time_keyboard=True)


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
    return ReplyKeyboardMarkup(
        [[str(amount//2), str(amount), str(amount//2 + amount)]],
        resize_keyboard=True
    )


def start(bot, update):
    t_user = update.effective_user
    try:
        user = User.get(tg_id=t_user.id)
        if user.username is None and t_user.username:
            user.username = t_user.username
            user.save()
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


def exchange_coins2cash(transaction, god):
    global EXCHANGED_SUM
    transaction.exchanged = True
    transaction.acceptor = god.account.get()
    transaction.approve_time = datetime.datetime.now()
    transaction.save()
    EXCHANGED_SUM += transaction.amount
    return transaction.amount


def approve(bot, update):
    photo = update.message.photo[-1].get_file()
    bytesarray = photo.download_as_bytearray()
    qr = Image.open(BytesIO(bytesarray))
    try:
        transactions = Transaction.from_qr(qr)
    except Exception as e:
        logger.warning('Error, when decode qr: %s', e)
        bot.send_message(chat_id=update.message.chat_id,
                         text="Hacker? ._.")
        return
    if not transactions:
        logger.debug("Didn't recognize QR-codes on photo")
        bot.send_message(chat_id=update.message.chat_id,
                         text="Transaction not found")
        return
    tg_user = update.effective_user
    user = User.get(User.tg_id == tg_user.id)
    if user.role == Role.GOD:
        cash = exchange_coins2cash(transactions[0], god)
        bot.send_message(chat_id=update.message.chat_id,
                         text="Give %d cash" % cash)
        return
    account = user.account.get()
    for transaction in transactions:
        try:
            account.approve(transaction)
            text = "Added %d CMCoins" % transaction.amount
        except TransactionUsed:
            text = "Transaction was used"
            logger.debug('Transaction was used')
        except SelfTransaction:
            text = "You can't use your's transaction"
            logger.debug("You can't use your's transaction")
        except Exception as e:
            text = "Something go wrong ☠️\nWrite to @dsp25no"
            logger.critical('Error, when approve transaction: %s', e)
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
                     reply_markup=cancel_keyboard)


def cancel(bot, update):
    bot.send_message(chat_id=update.message.chat_id,
                     text="Ok",
                     reply_markup=user_keyboard)


def _make_user(admin, user):
    if admin.role != Role.GOD and user.role != Role.KP:
        return (False, "😡")

    if (admin.role == Role.ADMIN and
            user.challenge not in [challenge for challenge in admin.own_challenge]):
        return (False, "It's not your slave")
    user.role = Role.USER
    user.challenge = None
    user.save()
    return (True, "Success")


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
    result, text = _make_user(admin_user, user)
    bot.send_message(chat_id=update.message.chat_id,
                     text=text)
    if result:
        bot.send_message(chat_id=user.tg_id,
                         text="You become simple user",
                         reply_markup=user_keyboard)


@restricted(Role.ADMIN)
def make_kp(bot, update, args):
    request_user = User.get(User.tg_id == update.effective_user.id)
    try:
        count = request_user.own_challenge.count()
    except:
        count = 0

    if count != 1 and len(args) != 2:
        bot.send_message(chat_id=update.message.chat_id,
                         text="Wrong format!\n/make_kp username challenge_name")
        return

    username = args[0]
    if request_user.role == Role.ADMIN:
        if count == 1:
            challenge_name = request_user.own_challenge.get().name
        else:
            challenge_name = args[1]
            allow = False
            for challenge in request_user.own_challenge:
                if challenge_name == challenge.name:
                    allow = True
            if not allow:
                bot.send_message(chat_id=update.message.chat_id,
                                 text="It's not your challenge")
                return
    else:
        challenge_name = args[1]

    try:
        user = User.get(User.username == username)
    except DoesNotExist:
        bot.send_message(chat_id=update.message.chat_id,
                         text="No such user")
        return
    try:
        challenge = Challenge.get(Challenge.name == challenge_name)
    except DoesNotExist:
        bot.send_message(chat_id=update.message.chat_id,
                         text="No such challenge")
        return
    if user.role != Role.USER:
        bot.send_message(chat_id=update.message.chat_id,
                         text="NOPE")
        return
    user.role = Role.KP
    user.challenge = challenge
    user.save()
    bot.send_message(chat_id=update.message.chat_id,
                     text="Success")
    bot.send_message(chat_id=user.tg_id,
                     text="You become KP of %s" % challenge.name,
                     reply_markup=amounts_keyboard(user))


@restricted(Role.GOD)
def make_shop(bot, update, args):
    if len(args) != 1:
        bot.send_message(chat_id=update.message.chat_id,
                         text="Wrong format!\n/make_shop username")
        return
    username = args[0]
    try:
        user = User.get(User.username == username)
    except DoesNotExist:
        bot.send_message(chat_id=update.message.chat_id,
                         text="No such user")
        return

    user.role = Role.SHOP
    user.challenge = None
    user.save()
    bot.send_message(chat_id=update.message.chat_id,
                     text="Success")
    bot.send_message(chat_id=user.tg_id,
                     text="You become shop",
                     reply_markup=ReplyKeyboardRemove())


def transaction(bot, update):
    global GENERATED_SUM
    try:
        amount = int(update.message.text)
    except ValueError:
        bot.send_message(chat_id=update.message.chat_id,
                         text="Invalid sum")
        return
    t_user = update.effective_user
    user = User.get(User.tg_id == t_user.id)
    if user.role == Role.USER:
        account = user.account.get()
        if account.score < amount:
            bot.send_message(chat_id=update.message.chat_id,
                             text="Not enough CMCoins",
                             reply_markup=user_keyboard)
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
                       reply_markup=user_keyboard)
        return

    if user.role == Role.KP:
        challenge = user.challenge
        max_amount = challenge.amount//2 + challenge.amount
        if not challenge.crazy and amount > max_amount:
            bot.send_message(chat_id=update.message.chat_id,
                             text="😡")
            return
    if user.role == Role.ADMIN:
        allowed = False
        for challenge in user.own_challenge:
            max_amount = challenge.amount//2 + challenge.amount
            if challenge.crazy or amount <= max_amount:
                allowed = True
        if not allowed:
            bot.send_message(chat_id=update.message.chat_id,
                             text="😡")
            return
    if user.role == Role.ADMIN:
        allowed = False
        for challenge in user.own_challenge:
            max_amount = challenge.amount//2 + challenge.amount
            if challenge.crazy or amount <= max_amount:
                allowed = True
        if not allowed:
            bot.send_message(chat_id=update.message.chat_id,
                             text="😡")
            return
    if amount > 5000 or amount == 0:
        bot.send_message(chat_id=update.message.chat_id,
                         text='Nope')
        return
    transaction = Transaction.create(amount=amount, actor=user, generated=True)
    GENERATED_SUM += transaction.amount
    qr = transaction.to_qr()
    qr_bytes = BytesIO()
    qr_bytes.name = 'qr.png'
    qr.save(qr_bytes)
    qr_bytes.seek(0)
    reply_markup = amounts_keyboard(user) if user.role != Role.GOD else ReplyKeyboardRemove()
    bot.send_photo(chat_id=update.message.chat_id,
                   photo=qr_bytes,
                   reply_markup=reply_markup)


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

    with db.atomic() as txn:
        challenge = Challenge.create(name=challenge_name,
                                     admin=admin, amount=max_amount)
        admin.role = Role.ADMIN
        admin.save()

    bot.send_message(chat_id=update.message.chat_id,
                     text="Success")
    bot.send_message(chat_id=admin.tg_id,
                     text="You become an admin of %s" % challenge_name,
                     reply_markup=amounts_keyboard(admin))


def help(bot, update):
    t_user = update.effective_user
    user = User.get(User.tg_id == t_user.id)
    if user.role == Role.SHOP:
        bot.send_message(chat_id=update.message.chat_id,
                         text="Role: SHOP",
                         reply_markup=ReplyKeyboardRemove())  # TODO: write about balance commands
    if user.role == Role.USER:
        bot.send_message(chat_id=update.message.chat_id,
                         text="Use bot and be happy",
                         reply_markup=user_keyboard)  # TODO: beauty text
    if user.role == Role.KP:
        bot.send_message(chat_id=update.message.chat_id,
                         text="Role: KP\nChallenge: %s\nGenerate rewards and be happy" % user.challenge.name,
                         reply_markup=amounts_keyboard(user))
    if user.role == Role.ADMIN:
        bot.send_message(chat_id=update.message.chat_id,
                         text="Role: ADMIN\nChallenges: %s\n" % [challenge.name for challenge in user.own_challenge],
                         reply_markup=amounts_keyboard(user))


@restricted(Role.GOD)
def get_user_info(bot, update, args):
    for username in args:
        try:
            user = User.get(User.username == username)
        except DoesNotExist:
            bot.send_message(chat_id=update.message.chat_id,
                             text="Didn't find {}".format(username))
            continue
        if user.role == Role.USER:
            bot.send_message(chat_id=update.message.chat_id,
                             text="Role: USER\nBalance: %d" % user.account.get().score)
        if user.role == Role.KP:
            challenge = user.challenge
            admin = challenge.admin
            balance = user.account.get().score
            bot.send_message(chat_id=update.message.chat_id,
                             text="Role: KP\nChallenge: {challenge}\nAdmin of challenge: {admin}\nBalance: {balance}".format(challenge=challenge.name, admin=admin.username, balance=balance))
        if user.role == Role.ADMIN:
            challenges = [challenge.name for challenge in user.own_challenge]
            balance = user.account.get().score
            bot.send_message(chat_id=update.message.chat_id,
                             text="Role: ADMIN\nChallenges: {challenges}\nBalance: {balance}".format(challenges=challenges, balance=balance))
        if user.role == Role.SHOP:
            balance = user.account.get().score
            bot.send_message(chat_id=update.message.chat_id,
                             text="Role: SHOP\nBalance: {balance}".format(balance=balance))

@restricted(Role.GOD)
def get_user_info(bot, update, args):
    for username in args:
        try:
            user = User.get(User.username == username)
        except DoesNotExist:
            bot.send_message(chat_id=update.message.chat_id,
                             text="Didn't find {}".format(username))
            continue
        if user.role == Role.USER:
            bot.send_message(chat_id=update.message.chat_id,
                             text="Role: USER\nBalance: %d" % user.account.get().score)
        if user.role == Role.KP:
            challenge = user.challenge
            admin = challenge.admin
            balance = user.account.get().score
            bot.send_message(chat_id=update.message.chat_id,
                             text="Role: KP\nChallenge: {challenge}\nAdmin of challenge: {admin}\nBalance: {balance}".format(challenge=challenge.name, admin=admin.username, balance=balance))
        if user.role == Role.ADMIN:
            challenges = [challenge.name for challenge in user.own_challenge]
            balance = user.account.get().score
            bot.send_message(chat_id=update.message.chat_id,
                             text="Role: ADMIN\nChallenges: {challenges}\nBalance: {balance}".format(challenges=challenges, balance=balance))
        if user.role == Role.SHOP:
            balance = user.account.get().score
            bot.send_message(chat_id=update.message.chat_id,
                             text="Role: SHOP\nBalance: {balance}".format(balance=balance))


@restricted(Role.GOD)
def get_challenge_info(bot, update, args):
    for challenge_name in args:
        try:
            challenge = Challenge.get(Challenge.name == challenge_name)
        except DoesNotExist:
            bot.send_message(chat_id=update.message.chat_id,
                             text="Didn't find {}".format(challenge_name))
            continue
        admin = challenge.admin
        kps = [kp.username for kp in challenge.kp]
        bot.send_message(chat_id=update.message.chat_id,
                         text="Admin: {admin}\nKPs: {kps}\nFinished: {finished}\nCrazy: {crazy}".format(admin=admin.username, kps=kps, finished=challenge.finished, crazy=challenge.crazy))


@restricted(Role.GOD)
def finish(bot, update, args):
    if len(args) != 1:
        bot.send_message(chat_id=update.message.chat_id,
                         text="Wrong format!\n/finish challenge_name")
    challenge_name = args[0]
    try:
        challenge = Challenge.get(Challenge.name == challenge_name)
    except DoesNotExist:
        bot.send_message(chat_id=update.message.chat_id,
                         text="Didn't find {}".format(challenge_name))
        return
    admin = challenge.admin
    global god
    with db.atomic() as txn:
        challenge.finished = True
        challenge.save()
        challenges_statuses = [challenge.finished for
                             challenge in admin.own_challenge]
        logger.debug(challenges_statuses)
        if False not in challenges_statuses:
            _make_user(god, admin)
            bot.send_message(chat_id=admin.tg_id, text="You become user")
        for user in challenge.kp:
            _make_user(god, user)
            bot.send_message(chat_id=admin.tg_id, text="You become user")
    bot.send_message(chat_id=admin.tg_id,
                     text="Challenge %s finished" % challenge.name)
    bot.send_message(chat_id=update.message.chat_id,
                     text="Success")


@restricted(Role.GOD)
def status(bot, update):
    global GENERATED_SUM
    global EXCHANGED_SUM
    crew = User.get(User.tg_id == 0)
    balance = crew.account.get().score
    coins = GENERATED_SUM - EXCHANGED_SUM
    bot.send_message(chat_id=update.message.chat_id,
                     text="Shop balance: {shop_balance}\nGenerated: {generated}\nOn hands: {hands}".format(shop_balance=balance, generated=coins, hands=coins-balance))


@restricted(Role.GOD)
def change_costs(bot, update, args):
    try:
        op = getattr(operator, args[0])
    except AttributeError:
        bot.send_message(chat_id=update.message.chat_id,
                         text="Unknown operation. Use: add, mul, floordiv, sub")
        return
    try:
        value = int(args[1])
    except ValueError:
        bot.send_message(chat_id=update.message.chat_id,
                         text="Wrong format!\n/change_costs op value")
        return
    with db.atomic():
        for challenge in Challenge.select():
            challenge.amount = op(challenge.amount, value)
            challenge.save()


@restricted(Role.GOD)
def exchange(bot, update, args):
    try:
        amount = int(args[0])
    except ValueError:
        bot.send_message(chat_id=update.message.chat_id,
                         text="Wrong format!\n/exchange value")
        return
    update.message.text = amount
    transaction(bot, update)


@restricted(Role.GOD)
def get_challenge_info(bot, update, args):
    for challenge_name in args:
        try:
            challenge = Challenge.get(Challenge.name == challenge_name)
        except DoesNotExist:
            bot.send_message(chat_id=update.message.chat_id,
                             text="Didn't find {}".format(challenge_name))
            continue
        admin = challenge.admin
        kps = [kp.username for kp in challenge.kp]
        bot.send_message(chat_id=update.message.chat_id,
                         text="Admin: {admin}\nKPs: {kps}".format(admin=admin.username, kps=kps))


@restricted(Role.GOD)
def status(bot, update):
    global GENERATED_SUM
    crew = User.get(User.tg_id == 0)
    balance = crew.account.get().score
    bot.send_message(chat_id=update.message.chat_id,
                     text="Shop balance: {shop_balance}\nGenerated: {generated}".format(shop_balance=balance, generated=GENERATED_SUM))


@restricted(Role.GOD)
def sleep(bot, update, args):
    from time import sleep
    sleep(args[0])
    bot.send_message(chat_id=update.message.chat_id,
                     text="Success")


@restricted(Role.GOD)
def wall(bot, update, args):  # TODO: wall for certain roles
    message = ' '.join(args)
    for user in User.select():
        if user.tg_id != 0:
            bot.send_message(chat_id=user.tg_id, text=message)
    bot.send_message(chat_id=update.message.chat_id, text='Success')


updater = Updater(token=TOKEN)
dispatcher = updater.dispatcher
dispatcher.add_handler(CommandHandler('start', start))
dispatcher.add_handler(MessageHandler(Filters.photo, approve))
dispatcher.add_handler(CommandHandler('generate', generate, pass_args=True))
dispatcher.add_handler(RegexHandler('balance', balance))
dispatcher.add_handler(RegexHandler('pay', pay))
dispatcher.add_handler(RegexHandler('cancel', cancel))
dispatcher.add_handler(CommandHandler('make_user', make_user, pass_args=True))
dispatcher.add_handler(CommandHandler('make_kp', make_kp, pass_args=True))
dispatcher.add_handler(CommandHandler('make_shop', make_shop, pass_args=True))
dispatcher.add_handler(RegexHandler('\d+', transaction))
dispatcher.add_handler(CommandHandler('make_challenge', make_challenge, pass_args=True))
dispatcher.add_handler(CommandHandler('help', help))
dispatcher.add_handler(CommandHandler('get_user_info', get_user_info, pass_args=True))
dispatcher.add_handler(CommandHandler('get_challenge_info', get_challenge_info, pass_args=True))
dispatcher.add_handler(CommandHandler('finish', finish, pass_args=True))
dispatcher.add_handler(CommandHandler('status', status))
dispatcher.add_handler(CommandHandler('change_costs', change_costs, pass_args=True))
dispatcher.add_handler(CommandHandler('exchange', exchange, pass_args=True))
dispatcher.add_handler(CommandHandler('sleep', sleep, pass_args=True))
dispatcher.add_handler(CommandHandler('wall', wall, pass_args=True))

if __name__ == '__main__':
    updater.start_polling()
