FROM python:3.13-slim

WORKDIR /usr/src/app
COPY . /usr/src/app

RUN pip install --no-cache-dir .

ENTRYPOINT ["sitadel"]
