import pefile


def rol6(x):
    return ((x << 6) | (x >> 26)) & 0xFFFFFFFF


def calc_hash(name):
    h = 0

    for c in name.upper():
        h = (rol6(h) + ord(c)) & 0xFFFFFFFF

    return h


def main():
    dlls = [
        (r"C:\Windows\System32\ntdll.dll", "ntdll.dll"),
        (r"C:\Windows\System32\kernel32.dll", "kernel32.dll")
    ]
    with open("api_hash.txt", "w", encoding="utf-8") as file:
        
        for dll_path, dll_name in dlls:

            dll_hash = calc_hash(dll_name)

            pe = pefile.PE(dll_path)

            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    fn_name = exp.name.decode("ascii", errors="ignore")
                    fn_hash = calc_hash(fn_name)

                    line = "0x{:08X} - 0x{:08X} - {}.{}\n".format(
                            dll_hash,
                            fn_hash,
                            dll_name,
                            fn_name
                        )
                    file.write(line)


if __name__ == "__main__":
    main()
