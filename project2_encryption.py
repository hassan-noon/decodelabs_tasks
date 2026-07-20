import string
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result
def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)
def vigenere_encrypt(text, key):
    key = key.upper()
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            base = 65 if char.isupper() else 97
            result += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result
def vigenere_decrypt(text, key):
    key = key.upper()
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 65
            base = 65 if char.isupper() else 97
            result += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

def brute_force(text):
    print("\n[BRUTE FORCE — All 25 possible keys]")
    print("-" * 45)
    for shift in range(1, 26):
        attempt = caesar_decrypt(text, shift)
        print(f"  Key {shift:2d}: {attempt}")
    print("-" * 45)

def frequency_analysis(text):
    text_upper = text.upper()
    counts = {}
    total = 0
    for char in text_upper:
        if char.isalpha():
            counts[char] = counts.get(char, 0) + 1
            total += 1
    if total == 0:
        print("  No alphabetic characters found.")
        return
    print("\n[FREQUENCY ANALYSIS]")
    print("-" * 45)
    sorted_chars = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    for char, count in sorted_chars[:8]:
        bar = "#" * int((count / total) * 40)
        print(f"  {char}: {bar} {count / total * 100:.1f}%")
    most_common = sorted_chars[0][0]
    guessed_shift = (ord(most_common) - ord('E')) % 26
    print(f"\n  Most frequent: '{most_common}' → likely maps to 'E'")
    print(f"  Probable shift: {guessed_shift}")
    print(f"  Attempted crack: {caesar_decrypt(text, guessed_shift)}")
    print("-" * 45)

def display_banner():
    print("""
        CRYPTOGRAPHIC ENGINE — DecodeLabs
        Basic Encryption & Decryption

""")

def display_menu():
    print("""
  [1] Caesar Cipher — Encrypt
  [2] Caesar Cipher — Decrypt
  [3] Vigenère Cipher — Encrypt
  [4] Vigenère Cipher — Decrypt
  [5] Brute Force Attack (Caesar)
  [6] Frequency Analysis
  [0] Exit
""")

def main():
    display_banner()
    while True:
        display_menu()
        choice = input("  Select operation: ").strip()

        if choice == "0":
            print("\n  Session terminated.\n")
            break

        elif choice in ("1", "2"):
            text = input("  Enter text: ")
            shift = int(input("  Enter shift key (1-25): "))
            if choice == "1":
                output = caesar_encrypt(text, shift)
                label = "ENCRYPTED"
            else:
                output = caesar_decrypt(text, shift)
                label = "DECRYPTED"
            print(f"\n  INPUT:     {text}")
            print(f"  {label}: {output}")

        elif choice in ("3", "4"):
            text = input("  Enter text: ")
            key = input("  Enter keyword (letters only): ")
            if not key.isalpha():
                print("  Invalid key. Letters only.")
                continue
            if choice == "3":
                output = vigenere_encrypt(text, key)
                label = "ENCRYPTED"
            else:
                output = vigenere_decrypt(text, key)
                label = "DECRYPTED"
            print(f"\n  INPUT:     {text}")
            print(f"  KEY:       {key.upper()}")
            print(f"  {label}: {output}")

        elif choice == "5":
            text = input("  Enter ciphertext to attack: ")
            brute_force(text)

        elif choice == "6":
            text = input("  Enter ciphertext to analyze: ")
            frequency_analysis(text)

        else:
            print("  Invalid option.")
main()