FROM python:3

WORKDIR /usr/src/app
COPY . /usr/src/app

RUN python setup.py install

ENTRYPOINT python linguini.py
