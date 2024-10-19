import string
import math
import os

# --------------------- Helper Functions for Password Strength --------------------- #

# Check if the password meets basic requirements
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

# Entropy Calculation based on the pool size (uppercase, lowercase, numbers, special chars)
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
   
    # Entropy formula: length of password * log2(pool size)
    entropy = len(password) * math.log2(pool_size) if pool_size else 0
    return entropy

# Password strength score calculation with detailed feedback
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
