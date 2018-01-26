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
        print(self.ny + "  _     _                   _       _" + self.e)
        print(self.ny + " | |   (_)_ __   __ _ _   _(_)_ __ (_)" + self.e)
        print(self.ny + " | |   | | '_ \ / _` | | | | | '_ \| |" + self.e)
        print(self.ny + " | |___| | | | | (_| | |_| | | | | | |" + self.e)
        print(self.ny + " |_____|_|_| |_|\__, |\__,_|_|_| |_|_|" + self.e)
        print(self.ny + "                |___/     " + self.r + version + "\n" + self.e)
        print(self.g + "~/#" + self.e + " Linguini - Web Application Security Scanner" + self.e)
        print(self.g + "~/#" + self.e + " Shenril (@shenril)" + self.e)
        print(self.g + "~/#" + self.e + " https://github.com/shenril/Linguini\n" + self.e)

    def preamble(self, url):
        print('URL: %s' % url)
        print('Started: %s' % (time.strftime('%d/%m/%Y %H:%M:%S')))

    def version(self):
        return self.g + "~/#" + self.e + " Linguini (" + version + ")\n"
