import sys
from urllib.parse import urlparse


def validate_target(url):
    try:
        u = urlparse(url)
        if u.scheme and u.netloc:
            return u.geturl()
        else:
            raise ValueError('Url not valid, please try with a valid target url!')
    except ValueError as e:
        print(e)
        sys.exit(2)
