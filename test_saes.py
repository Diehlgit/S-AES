from saes import print_saes


def main():
    plaintext = input("Enter a 2-character ASCII plaintext: ")
    if len(plaintext) != 2:
        raise ValueError("Plaintext must be exactly 2 characters long.")

    key_str = input("Enter a 16-bit key (as integer, 0x-prefixed hex or 0b-prefixed bin): ").strip()
    try:
        key = int(key_str, 0) 
    except ValueError:
        raise ValueError("Invalid key. Enter as integer (e.g., 12345 or 0x3031).")

    if not (0 <= key <= 0xFFFF):
        raise ValueError("Key must be a 16-bit integer (0–65535)")
    
    print("")
    print_saes(plaintext, key)

if __name__ == "__main__":
    main()