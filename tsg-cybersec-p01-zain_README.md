# Password Strength Checker - Scoring Logic

## 1. Base Score: Entropy Calculation
The core strength of the password is measured in bits of entropy, utilizing the standard mathematical formula E = L × log2(R).
* **E** represents the total entropy (the base score).
* **L** represents the password length.
* **R** represents the character pool size (Lowercase = 26, Uppercase = 26, Numbers = 10, Symbols = 32).

**Justification:** This formula objectively calculates the mathematical search space an attacker must cover to brute-force the password, naturally rewarding length and character variety.

## 2. Deductions for Predictability
Because humans often rely on recognizable patterns that bypass raw entropy, the logic subtracts bits for the following vulnerabilities:
* **Common Passwords (Top 100k list):** Deduct 50 bits.
* **Keyboard Runs (e.g., "qwerty"):** Deduct 20 bits.
* **Repeated Characters (e.g., "aaaa"):** Deduct 15 bits.
* **Years (e.g., "2024", "1998"):** Deduct 10 bits.
* **Leetspeak Substitutions (e.g., "@" for "a"):** Deduct 10 bits.

**Justification:** Attackers heavily utilize rule-based permutations. A password like "P@ssw0rd2026" generates a falsely high raw entropy score but is trivial to crack using standard password-cracking dictionaries. Deductions account for this human predictability.

## 3. Final Scoring Bands
After deductions are subtracted from the base entropy, the script categorizes the final score into one of three bands:
* **Strong ( > 60 bits ):** Highly resistant to massive offline brute-force attacks.
* **Fair ( 36 - 60 bits ):** Safe from basic online throttling but vulnerable to dedicated offline cracking.
* **Weak ( < 36 bits ):** Trivially easily cracked instantly or within minutes.