"""
Project 1: Password Strength Checker
Goal:
    Evaluate a password's strength based on length and character composition (uppercase letters, digits, symbols), then classify it as Weak, Medium or Strong
"""
import string
def analyze_password(password: str) -> dict:
    """Run all checks on the password and return a results dictionary."""
    length = len(password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_symbol = any(char in string.punctuation for char in password)
    return {"length": length,"has_upper": has_upper,"has_lower": has_lower,"has_digit": has_digit,"has_symbol": has_symbol,}

def score_password(results: dict) -> int:
    score = sum([
        results["has_upper"],
        results["has_lower"],
        results["has_digit"],
        results["has_symbol"],
    ])
    if results["length"] >= 12:
        score += 1
    return score


def classify_strength(password: str) -> tuple[str, dict, int]:
    results = analyze_password(password)
    score = score_password(results)
    if results["length"] < 8:
        strength = "Weak"
    elif score <= 2:
        strength = "Weak"
    elif score in (3, 4):
        strength = "Medium"
    else:
        strength = "Strong"
    return strength, results, score


def print_report(password: str) -> None:
    """Pretty-print the strength report for a password."""
    strength, results, score = classify_strength(password)
    print("\n" + "-" * 40)
    print(f"Password : {'*' * len(password)}")
    print(f"Length : {results['length']} chars")
    print(f"Uppercase : {'Yes' if results['has_upper'] else 'No'}")
    print(f"Lowercase : {'Yes' if results['has_lower'] else 'No'}")
    print(f"Digit : {'Yes' if results['has_digit'] else 'No'}")
    print(f"Symbol : {'Yes' if results['has_symbol'] else 'No'}")
    print(f"Score : {score}/5")
    print(f"STRENGTH : {strength.upper()}")
    print("-" * 40)

def main() -> None:
    print("=" * 40)
    print("  DecodeLabs Password Strength Checker")
    print("=" * 40)
    while True:
        password = input("\nEnter a password to check (or 'q' to quit): ")
        if password.lower() == "q":
            print("Goodbye!")
            break
        if password == "":
            print("Password cannot be empty. Try again.")
            continue
        print_report(password)

if __name__ == "__main__":
    main()