import math
import string
import os
import urllib.request
import re

WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt"
WORDLIST_FILE = "top_100k_passwords.txt"

def load_common_passwords():
    """Loads the top 100k passwords into a Python set for O(1) lookup."""
    if not os.path.exists(WORDLIST_FILE):
        print("Downloading Top 100k password list (this only happens once)...\n")
        # Added User-Agent to prevent 403 Forbidden errors
        req = urllib.request.Request(WORDLIST_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(WORDLIST_FILE, 'wb') as out_file:
            out_file.write(response.read())
            
    with open(WORDLIST_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        # Lowercase everything for case-insensitive matching
        return set(line.strip().lower() for line in f)

# Load into memory once using O(1) lookup set
try:
    COMMON_PASSWORDS = load_common_passwords()
except Exception as e:
    print(f"Warning: Could not load wordlist ({e}). Continuing without common password check.")
    COMMON_PASSWORDS = set()

def calculate_base_entropy(password):
    """Calculates base entropy using E = L * log2(R)"""
    if not password:
        return 0
        
    pool_size = 0
    if any(c.islower() for c in password): pool_size += 26
    if any(c.isupper() for c in password): pool_size += 26
    if any(c.isdigit() for c in password): pool_size += 10
    if any(c in string.punctuation for c in password): pool_size += 32
    if any(c == ' ' for c in password): pool_size += 1
    
    if pool_size == 0:
        return 0
        
    return len(password) * math.log2(pool_size)

def assess_password(password):
    """Core function returning score, band, and actionable issues."""
    issues = []
    
    # 1. Handle Edge Cases
    if not isinstance(password, str):
        return {"score": 0, "band": "Weak", "issues": ["Invalid input type."]}
    if not password.strip():
        return {"score": 0, "band": "Weak", "issues": ["Password cannot be empty. Add length."]}
    if len(password) > 1000:
        return {"score": 100, "band": "Strong", "issues": ["Password is exceptionally long."]}

    # 2. Base Entropy Calculation
    final_score = calculate_base_entropy(password)
    lower_pwd = password.lower()
    
    # 3. Predictability Deductions
    if lower_pwd in COMMON_PASSWORDS:
        final_score -= 50
        # Exact remediation text required by the project brief
        issues.append("Found in the top 100,000 most common passwords; add length rather than symbols — a four-word passphrase beats P@ssw0rd!.")
        
    if len(set(password)) == 1 and len(password) > 1:
        final_score -= 15
        issues.append("Consists of a single repeated character. Use a variety of characters.")
        
    if any(run in lower_pwd for run in ["qwerty", "12345", "qazwsx", "asdf"]):
        final_score -= 20
        issues.append("Contains a predictable keyboard run. Use random characters.")
        
    if re.search(r'(19|20)\d{2}', password):
        final_score -= 10
        issues.append("Contains a recognizable year. Attackers commonly guess dates.")

    final_score = max(0, final_score)

    # 4. Determine Band
    if final_score > 60:
        band = "Strong"
    elif final_score >= 36:
        band = "Fair"
    else:
        band = "Weak"

    return {
        "score": round(final_score, 2),
        "band": band,
        "issues": issues
    }

# --- TESTS ---
if __name__ == "__main__":
    print("Running Password Checker Tests...\n")
    test_passwords = [
        "", "a", "aaaa", "password", "123456", "Password123!", 
        "correcthorsebatterystaple", "P@ssw0rd123", "Admin2026!", 
        "ZainSajid", "A" * 5000, "hello", "aB1!", 
        "ThisIsAVeryLongPassphrase123!@#", "   "
    ]
    
    print(f"{'Password':<32} | {'Band':<6} | {'Score':<6} | {'Issues'}")
    print("-" * 110)
    
    for pwd in test_passwords:
        display_pwd = pwd if len(pwd) <= 30 else pwd[:27] + "..."
        result = assess_password(pwd)
        first_issue = result["issues"][0] if result["issues"] else "None"
        print(f"{display_pwd:<32} | {result['band']:<6} | {result['score']:<6} | {first_issue}")