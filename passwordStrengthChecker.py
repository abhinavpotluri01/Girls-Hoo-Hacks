import string
import math
import os


def is_long_enough(password, min_length=8):
    return len(password) >= min_length

def has_uppercase(password):
    return any(char.isupper() for char in password)

def has_lowercase(password):
    return any(char.islower() for char in password)

def has_number(password):
    return any(char.isdigit() for char in password)

def has_special_char(password):
    special_chars = string.punctuation
    return any(char in special_chars for char in password)


def calculate_entropy(password):
    pool_size = 0
    if has_uppercase(password):
        pool_size += 26
    if has_lowercase(password):
        pool_size += 26
    if has_number(password):
        pool_size += 10
    if has_special_char(password):
        pool_size += len(string.punctuation)

    entropy = len(password) * math.log2(pool_size) if pool_size else 0
    return entropy


def calculate_password_score(password):
    score = 0
    feedback = []

    if is_long_enough(password):
        score += 2
    else:
        feedback.append("Password should be at least 8 characters long.")

    if has_uppercase(password):
        score += 2
    else:
        feedback.append("Password should contain at least one uppercase letter.")

    if has_lowercase(password):
        score += 1

    if has_number(password):
        score += 2
    else:
        feedback.append("Password should contain at least one number.")

    if has_special_char(password):
        score += 3
    else:
        feedback.append("Password should contain at least one special character (e.g., @, #, $).")

    if len(password) >= 12:
        score += 2
    else:
        feedback.append("Password should be at least 12 characters long for added security.")

    entropy = calculate_entropy(password)
    if entropy < 40:
        feedback.append("Password's entropy is too low. Consider adding more complexity for better security.")

    return score, feedback, entropy
    def calculate_password_score(password):
    score = 0
    feedback = []

    if is_long_enough(password):
        score += 2
    else:
        feedback.append("Password should be at least 8 characters long.")

    if has_uppercase(password):
        score += 2
    else:
        feedback.append("Password should contain at least one uppercase letter.")

    if has_lowercase(password):
        score += 1

    if has_number(password):
        score += 2
    else:
        feedback.append("Password should contain at least one number.")

    if has_special_char(password):
        score += 3
    else:
        feedback.append("Password should contain at least one special character (e.g., @, #, $).")

    if len(password) >= 12:
        score += 2
    else:
        feedback.append("Password should be at least 12 characters long for added security.")

    entropy = calculate_entropy(password)
    if entropy < 40:
        feedback.append("Password's entropy is too low. Consider adding more complexity for better security.")

    return score, feedback, entropy

def get_strength_level(score):
    if score >= 11:
        return "Very Strong"
    elif score >= 8:
        return "Strong"
    elif score >= 5:
        return "Moderate"
    elif score >= 3:
        return "Weak"
    else:
        return "Very Weak"

HISTORY_FILE = "password_history.txt"

def load_password_history():
    """ Load the password history from a file """
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as file:
            history = file.read().splitlines()
            return history
    return []

def store_password(password):
    """ Save a new password into the history file """
    with open(HISTORY_FILE, 'a') as file:
        file.write(password + "\n")

def password_already_used(password, history):
    return password in history

# ---------------------- Password Generator ---------------------- #

def generate_password(length=12, include_upper=True, include_numbers=True, include_special=True):
    """ Generate a random password based on user preferences """
    char_set = string.ascii_lowercase
    if include_upper:
        char_set += string.ascii_uppercase
    if include_numbers:
        char_set += string.digits
    if include_special:
        char_set += string.punctuation
    
    return ''.join(random.choice(char_set) for _ in range(length))

# ---------------------- Advanced Password Strength Checker ---------------------- #

def check_password(password):
    """ Main function to check password strength """
    score, feedback, entropy = calculate_password_score(password)
    strength_level = get_strength_level(score)
    
    print(f"\nPassword Strength: {strength_level}")
    print(f"Password Entropy: {entropy:.2f} bits")
    if feedback:
        print("\nHere are some suggestions to improve your password:")
        for suggestion in feedback:
            print(f"- {suggestion}")
    else:
        print("Your password is strong enough!")

# ---------------------- Command Line Menu ---------------------- #

def display_menu():
    """ Show the user a menu of options """
    print("\nPassword Strength Checker")
    print("1. Check Password Strength")
    print("2. Generate a Strong Password")
    print("3. View Password History")
    print("4. Exit")

def main():
    password_history = load_password_history()

    while True:
        display_menu()
        choice = input("Please choose an option (1-4): ")

        if choice == '1':
            password = input("Enter a password to check: ")
            if password_already_used(password, password_history):
                print("You've already used this password before. Please choose a new one.")
            else:
                check_password(password)
                store_password(password)
                password_history.append(password)

        elif choice == '2':
            print("\nGenerate a Password:")
            length = int(input("Enter the desired password length: "))
            include_upper = input("Include uppercase letters? (y/n): ").lower() == 'y'
            include_numbers = input("Include numbers? (y/n): ").lower() == 'y'
            include_special = input("Include special characters? (y/n): ").lower() == 'y'
            
            generated_password = generate_password(length, include_upper, include_numbers, include_special)
            print(f"\nGenerated Password: {generated_password}")
            check_password(generated_password)

        elif choice == '3':
            print("\nPassword History:")
            for pwd in password_history:
                print(f"- {pwd}")
            if not password_history:
                print("No passwords in history.")

        elif choice == '4':
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")

