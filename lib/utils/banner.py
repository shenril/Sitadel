import time

from colorama import Fore, Style

from lib import __version__ as version

class Banner:
    r = Fore.RED
    y = Fore.YELLOW
    ny = Fore.YELLOW
    nw = Fore.WHITE
    g = Fore.GREEN
    e = Style.RESET_ALL

    def banner(self):
        print(self.ny + "   _   _   _        ______ _                 _       _  " + self.e)
        print(self.ny + "  | |_| |_| |      / _____|_)  _            | |     | | " + self.e)
        print(self.ny + "  |         |     ( (____  _ _| |_ _____  __| |_____| | " + self.e)
        print(self.ny + "  |    _    |      \____ \| (_   _|____ |/ _  | ___ | | " + self.e)
        print(self.ny + "  |   |_|   |      _____) ) | | |_/ ___ ( (_| | ____| | " + self.e)
        print(self.ny + "  |         |     (______/|_|  \__)_____|\____|_____)\_)" + self.r + " " + version + "\n" + self.e)
        print(self.g + "~/#" + self.e + " Sitadel - Web Application Security Scanner" + self.g + " #\\~" + self.e)
        print(self.g + "~/#" + self.e + " Shenril (@shenril)" + self.g + " #\\~" + self.e)
        print(self.g + "~/#" + self.e + " https://github.com/shenril/Sitadel" + self.g + " #\\~" + self.e)
        print("\n")

    @classmethod
    def preamble(cls, url):
        print('URL: %s' % url)
        print('---------  Scan Started: %s ---------' % (time.strftime('%d/%m/%Y %H:%M:%S')))

    @classmethod
    def postscript(cls):
        print('---------  Scan Finished: %s ---------' % (time.strftime('%d/%m/%Y %H:%M:%S')))

    def version(self):
        return self.g + "~/#" + self.e + " Sitadel (" + version + ")\n"
