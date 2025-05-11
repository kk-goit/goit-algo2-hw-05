import random
import mmh3
import math
import time

LOG_FILE = "lms-stage-access.log"


class HyperLogLog:
    def __init__(self, p=5):
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()
        self.small_range_correction = 5 * self.m / 2  # Поріг для малих значень

    def _get_alpha(self):
        if self.p <= 16:
            return 0.673
        elif self.p == 32:
            return 0.697
        else:
            return 0.7213 / (1 + 1.079 / self.m)

    def add(self, item):
        x = mmh3.hash(str(item), signed=False)
        j = x & (self.m - 1)
        w = x >> self.p
        self.registers[j] = max(self.registers[j], self._rho(w))

    def _rho(self, w):
        return len(bin(w)) - 2 if w > 0 else 32

    def count(self):
        Z = sum(2.0**-r for r in self.registers)
        E = self.alpha * self.m * self.m / Z

        if E <= self.small_range_correction:
            V = self.registers.count(0)
            if V > 0:
                return self.m * math.log(self.m / V)

        return E


def read_ips_from_log(log_file: str) -> str:
    """
    Generator to read remote addresses from log file and yield them as strings.

    :param log_file: Path to Apache log file.
    :type log_file: str
    :yield: Remote address as string.
    :rtype: str
    """
    with open("lms-stage-access.log", "r") as log_file:
        for log_line in log_file:
            data = log_line.split(",")
            if len(data) > 1 and "remote_addr" in data[1]:
                ra_data = data[1].split('"')
                if len(ra_data) > 3:
                    yield ra_data[3]


def unique_ips_by_set(log_file: str) -> int:
    ips = set()
    for ip in read_ips_from_log(log_file):
        ips.update([ip])
    return len(ips)


def unique_ips_by_hll(log_file: str) -> float:
    hll = HyperLogLog(p=5)
    for ip in read_ips_from_log(log_file):
        hll.add(ip)
    return hll.count()


def print_table(data: list[str]) -> None:
    if not data:
        return
    num_cols = len(data[0])
    col_widths = [max(len(str(row[i])) for row in data) for i in range(num_cols)]
    for row in data:
        formatted_row = [f"{str(cell):>{col_widths[i]}}" for i, cell in enumerate(row)]
        print(f"| {' | '.join(formatted_row)} |")


if __name__ == "__main__":

    st = time.time()
    set_ips = unique_ips_by_set(LOG_FILE)
    set_time = time.time() - st

    st = time.time()
    hll_ips = unique_ips_by_hll(LOG_FILE)
    hll_time = time.time() - st

    print("Результати порівняння:")
    tab_data = [
        ["", "Точний підрахунок", "HyperLogLog"],
        ["Унікальні елементи", f"{set_ips:.1f}", f"{hll_ips:.1f}"],
        ["Час виконання (сек.)", f"{set_time:.5f}", f"{hll_time:.5f}"],
    ]
    print_table(tab_data)
