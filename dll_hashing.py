def rol6(x):
    return ((x << 6) | (x >> 26)) & 0xFFFFFFFF


def calc_hash(name):
    h = 0

    name = name.upper()

    for c in name:
        h = (rol6(h) + ord(c)) & 0xFFFFFFFF

    return h


def main():
    ntdll = calc_hash("ntdll.dll")
    kernel32 = calc_hash("kernel32.dll")

    print("ntdll.dll   =", hex(ntdll))
    print("kernel32.dll =", hex(kernel32))


if __name__ == "__main__":
    main()
