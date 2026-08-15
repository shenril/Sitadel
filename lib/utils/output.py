from __future__ import annotations

from colorama import Fore, Style


class Output:
    r = Fore.RED
    g = Fore.GREEN
    y = Fore.YELLOW
    w = Fore.WHITE
    c = Fore.CYAN
    e = Style.RESET_ALL

    def __init__(self, level: int = 0):
        self.level = level

    def finding(self, value: str) -> None:
        print(f"{self.g}[+]{self.e} {self.w}{value}{self.e}", flush=True)

    def error(self, value: str) -> None:
        print(f"{self.r}[-]{self.e} {self.w}{value}{self.e}", flush=True)

    def info(self, value: str) -> None:
        print(f"{self.y}[i]{self.e} {self.w}{value}{self.e}", flush=True)

    def debug(self, value: str) -> None:
        if self.level == 1:
            print(f"{self.c}[d]{self.e} {self.w}{value}{self.e}", flush=True)
