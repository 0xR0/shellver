FROM alpine:latest
MAINTAINER Furkan SAYIM <furkan.sayim@yandex.com>

RUN apk update \
    && apk add git \
    && apk add python \
    && python -m ensurepip \
    && rm -r /usr/lib/python*/ensurepip \
    && pip install --upgrade pip setuptools \
    && rm -r /root/.cache \
    && git clone https://github.com/0xR0/shellver.git 

RUN pip install -r shellver/requirements.txt
CMD python shellver/setup.py -i
CMD python shellver/shellver.py shell
WORKDIR /
