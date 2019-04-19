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
            "{}[+]{} {}{}{}".format(Output.g, Output.e, Output.w, value, Output.e),
            flush=True,
        )

    def error(self, value):
        print(
            "{}[-]{} {}{}{}".format(Output.r, Output.e, Output.w, value, Output.e),
            flush=True,
        )

    def info(self, value):
        print(
            "{}[i]{} {}{}{}".format(Output.y, Output.e, Output.w, value, Output.e),
            flush=True,
        )

    def debug(self, value):
        if self.level == 1:
            print(
                "{}[i]{} {}{}{}".format(Output.c, Output.e, Output.w, value, Output.e),
                flush=True,
            )
