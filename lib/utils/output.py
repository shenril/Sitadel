from colorama import Fore, Style


class Output:
    r = Fore.RED
    g = Fore.GREEN
    y = Fore.YELLOW
    w = Fore.WHITE
    c = Fore.CYAN
    e = Style.RESET_ALL

    def __init__(self, level=0):
        self.level = level

    def finding(self, value):
        print(
            "{}[+]{} {}{}{}".format(self.g, self.e, self.w, value, self.e),
            flush=True,
        )

    def error(self, value):
        print(
            "{}[-]{} {}{}{}".format(self.r, self.e, self.w, value, self.e),
            flush=True,
        )

    def info(self, value):
        print(
            "{}[i]{} {}{}{}".format(self.y, self.e, self.w, value, self.e),
            flush=True,
        )

    def debug(self, value):
        if self.level == 1:
            print(
                "{}[d]{} {}{}{}".format(self.c, self.e, self.w, value, self.e),
                flush=True,
            )
