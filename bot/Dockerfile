from python:3

RUN apt update
RUN apt install libzbar0 libzbar-dev postgresql-client -y

ADD requirements.txt /bot/
WORKDIR bot
RUN pip install -r requirements.txt

ADD . .
RUN mv run.py ..
RUN mv wait-for-postgres.sh ..

WORKDIR /

CMD python run.py
