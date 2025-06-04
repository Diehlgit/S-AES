from saes import print_saes, encrypt_saes_ecb


def main():
    mode = input(f"Do you want to use ECB mode of operation? \n [Y] (ECB) \n [n] (plain S-AES)\n")
    
    if mode.lower() in ("y", ""):
        plaintext = input("Enter the ASCII plaintext: ")
    elif mode.lower() == "n":
        plaintext = input("Enter a 2-character ASCII plaintext: ")
        if len(plaintext) != 2:
            raise ValueError("Plaintext must be exactly 2 characters long.")

    key_str = input("Enter a 16-bit key (as integer, 0x-prefixed hex or 0b-prefixed bin): ").strip()
    
    try:
        key = int(key_str, 0) 
    except ValueError:
        raise ValueError("Invalid key")
    if not (0 <= key <= 0xFFFF):
        raise ValueError("Key must be a 16-bit integer")
    

    print()
    if mode.lower() in ("y", ""):
        print(f"Base64 encoded ciphertext: {encrypt_saes_ecb(plaintext, key)}")
    elif mode.lower() == "n":
        print_saes(plaintext, key)

if __name__ == "__main__":
    main()