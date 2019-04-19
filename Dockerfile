FROM python:3

WORKDIR /usr/src/app
COPY . /usr/src/app

RUN pip3 install .

ENTRYPOINT ["python", "sitadel.py"]
