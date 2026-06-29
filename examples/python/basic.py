import hat


def main():
    data = (
        b"\x00\x00\x00\x00\x00\x00"
        b"\x48\x8D\x05\xBE\x53\x23\x01"
        b"\xE8\x00\x00\x00\x00"
        b"\x48\x8B\x8D\x00\x00\x00\x00"
    )

    with hat.parse_signature("48 8D 05 ? ? ? ? E8") as sig:
        offset = hat.find_pattern(sig, data)
        if offset is not None:
            print(f"Found at offset: {offset}")
            print(f"Match hex: {data[offset:offset + 8].hex()}")
        else:
            print("Not found")

    with hat.create_signature(
        b"\x48\x8D\x05\x00\x00\x00\x00\xE8",
        b"\xFF\xFF\xFF\x00\x00\x00\x00\xFF",
    ) as sig:
        offset = hat.find_pattern(sig, data, alignment=hat.X1)
        if offset is not None:
            print(f"Found at offset: {offset}")

    mod = hat.get_process_module()
    if mod is not None:
        print(f"Process module at: 0x{mod:x}")
        result = hat.find_pattern_mod(sig, mod, ".text")
        if result is not None:
            print(f"Found in .text at: 0x{result:x}")


if __name__ == "__main__":
    main()
