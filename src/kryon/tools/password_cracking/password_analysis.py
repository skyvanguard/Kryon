"""
KRYON Password Cracking - Password Analysis and Wordlist Generation

Intelligent password analysis and custom wordlist generation.

Clearance Level: Alpha-Red (Offensive Operations Authority)
Specialization: Password pattern analysis and targeted wordlist creation
Mission: Optimize password attacks through intelligence analysis

This module provides:
- Password pattern analysis and statistics
- Corporate password policy detection
- Custom wordlist generation from OSINT
- Password strength assessment
- Cracking strategy recommendations
"""

import itertools
import re
import string
from collections import Counter
from datetime import datetime
from typing import Any


def analyze_password_policy(passwords: list[str]) -> dict[str, Any]:
    """
    Analyze cracked passwords to identify patterns and policies.

    Discovers:
    - Length distribution
    - Character complexity requirements
    - Common patterns (dates, names, substitutions)
    - Password policy hints (min length, character requirements)
    - Most common passwords and patterns

    Args:
        passwords: List of cracked passwords to analyze

    Returns:
        Dictionary containing:
        - statistics: Length, complexity, pattern statistics
        - common_patterns: Most frequent password patterns
        - policy_hints: Detected password policy requirements
        - recommendations: Attack strategy recommendations
        - top_passwords: Most common passwords
        - character_analysis: Character usage statistics
        - success: Whether analysis completed
        - error: Error message if failed

    Example:
        >>> cracked = [
        ...     "Password123!",
        ...     "Summer2024!",
        ...     "Admin@123",
        ...     "Welcome1!"
        ... ]
        >>> analysis = analyze_password_policy(cracked)
        >>> print(f"Average length: {analysis['statistics']['avg_length']}")
        >>> print(f"Common patterns: {analysis['common_patterns']}")
        >>> print(f"Policy hints: {analysis['policy_hints']}")

    Use Cases:
        - Identify corporate password policies
        - Optimize attack strategies for remaining hashes
        - Generate targeted wordlists
        - Predict password patterns
    """
    results = {
        "statistics": {},
        "common_patterns": {},
        "policy_hints": {},
        "recommendations": [],
        "top_passwords": [],
        "character_analysis": {},
        "success": False,
        "error": None,
    }

    try:
        if not passwords:
            results["error"] = "No passwords provided for analysis"
            return results

        # Length statistics
        lengths = [len(p) for p in passwords]
        results["statistics"]["total_passwords"] = len(passwords)
        results["statistics"]["min_length"] = min(lengths)
        results["statistics"]["max_length"] = max(lengths)
        results["statistics"]["avg_length"] = sum(lengths) / len(lengths)
        results["statistics"]["most_common_length"] = Counter(lengths).most_common(1)[0][0]

        # Character complexity analysis
        has_lower = sum(1 for p in passwords if any(c.islower() for c in p))
        has_upper = sum(1 for p in passwords if any(c.isupper() for c in p))
        has_digit = sum(1 for p in passwords if any(c.isdigit() for c in p))
        has_special = sum(1 for p in passwords if any(c in string.punctuation for c in p))

        results["statistics"]["percent_lowercase"] = (has_lower / len(passwords)) * 100
        results["statistics"]["percent_uppercase"] = (has_upper / len(passwords)) * 100
        results["statistics"]["percent_digits"] = (has_digit / len(passwords)) * 100
        results["statistics"]["percent_special"] = (has_special / len(passwords)) * 100

        # Pattern detection
        patterns = {
            "starts_with_capital": sum(1 for p in passwords if p and p[0].isupper()),
            "ends_with_digit": sum(1 for p in passwords if p and p[-1].isdigit()),
            "ends_with_special": sum(1 for p in passwords if p and p[-1] in string.punctuation),
            "contains_year": sum(1 for p in passwords if re.search(r"20[0-2][0-9]", p)),
            "contains_season": sum(
                1 for p in passwords if any(s in p.lower() for s in ["spring", "summer", "fall", "winter", "autumn"])
            ),
            "contains_month": sum(
                1
                for p in passwords
                if any(
                    m in p.lower()
                    for m in [
                        "jan",
                        "feb",
                        "mar",
                        "apr",
                        "may",
                        "jun",
                        "jul",
                        "aug",
                        "sep",
                        "oct",
                        "nov",
                        "dec",
                    ]
                )
            ),
            "leet_speak": sum(1 for p in passwords if any(c in p for c in ["@", "3", "1", "0", "$", "7"])),
        }

        results["common_patterns"] = {k: (v / len(passwords)) * 100 for k, v in patterns.items()}

        # Password policy hints
        policy = {}

        # Minimum length
        policy["likely_min_length"] = results["statistics"]["min_length"]

        # Complexity requirements
        if results["statistics"]["percent_uppercase"] > 80:
            policy["requires_uppercase"] = True
        if results["statistics"]["percent_lowercase"] > 80:
            policy["requires_lowercase"] = True
        if results["statistics"]["percent_digits"] > 80:
            policy["requires_digits"] = True
        if results["statistics"]["percent_special"] > 80:
            policy["requires_special_chars"] = True

        # Maximum length hint
        if results["statistics"]["max_length"] == results["statistics"]["most_common_length"]:
            policy["likely_max_length"] = results["statistics"]["max_length"]

        results["policy_hints"] = policy

        # Top passwords
        password_counts = Counter(passwords)
        results["top_passwords"] = [{"password": pwd, "count": count} for pwd, count in password_counts.most_common(10)]

        # Character usage analysis
        all_chars = "".join(passwords)
        char_freq = Counter(all_chars)

        results["character_analysis"] = {
            "most_common_chars": [{"char": char, "count": count} for char, count in char_freq.most_common(10)],
            "digit_usage": {str(i): all_chars.count(str(i)) for i in range(10)},
            "special_char_usage": {c: all_chars.count(c) for c in string.punctuation if all_chars.count(c) > 0},
        }

        # Generate recommendations
        recommendations = []

        # Length-based
        if results["statistics"]["min_length"] >= 12:
            recommendations.append("Passwords are relatively long (12+ chars) - use GPU acceleration")
        else:
            recommendations.append("Passwords are short - brute force feasible for remaining hashes")

        # Pattern-based
        if results["common_patterns"]["starts_with_capital"] > 70:
            recommendations.append("Most passwords start with capital letter - use '?u' for first char in masks")

        if results["common_patterns"]["ends_with_digit"] > 70:
            recommendations.append("Most passwords end with digits - append ?d?d or ?d?d?d in masks")

        if results["common_patterns"]["contains_year"] > 50:
            recommendations.append("Year patterns common (2020-2029) - generate wordlist with year suffixes")

        if results["common_patterns"]["leet_speak"] > 30:
            recommendations.append(
                "Leet speak substitutions detected - use John rules or hashcat rules for a->@, e->3, etc."
            )

        # Complexity-based
        if all(
            [
                results["statistics"]["percent_uppercase"] > 80,
                results["statistics"]["percent_lowercase"] > 80,
                results["statistics"]["percent_digits"] > 80,
                results["statistics"]["percent_special"] > 80,
            ]
        ):
            recommendations.append(
                "Strong complexity requirements - focus on dictionary + rules rather than brute force"
            )

        results["recommendations"] = recommendations
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def generate_custom_wordlist(
    target_info: dict[str, Any],
    output_file: str = "/tmp/custom_wordlist.txt",
    include_mutations: bool = True,
    include_dates: bool = True,
    include_combinations: bool = True,
) -> dict[str, Any]:
    """
    Generate targeted wordlist from OSINT and target information.

    Creates custom wordlist based on:
    - Company/organization name
    - Employee names
    - Locations (city, country)
    - Product names
    - Years and dates
    - Common substitutions

    Args:
        target_info: Dictionary containing target information:
            - company_name: Company/organization name
            - employee_names: List of employee names
            - locations: List of cities/countries
            - products: List of product/service names
            - keywords: Additional keywords
            - years: Specific years (default: current and past 5)
        output_file: Path to save generated wordlist
        include_mutations: Include leet speak and case variations
        include_dates: Include date patterns (seasons, months, years)
        include_combinations: Include word combinations

    Returns:
        Dictionary containing:
        - wordlist_path: Path to generated wordlist
        - word_count: Number of words generated
        - mutations_applied: List of mutation types used
        - success: Whether generation completed
        - error: Error message if failed

    Example:
        >>> target = {
        ...     "company_name": "TechCorp",
        ...     "employee_names": ["john", "smith", "admin"],
        ...     "locations": ["london", "newyork"],
        ...     "products": ["cloudapp", "securemail"],
        ...     "keywords": ["welcome", "password"],
        ...     "years": [2023, 2024, 2025]
        ... }
        >>> result = generate_custom_wordlist(
        ...     target_info=target,
        ...     output_file="/tmp/techcorp_wordlist.txt"
        ... )
        >>> print(f"Generated {result['word_count']} words")
        >>> print(f"Wordlist: {result['wordlist_path']}")

    Generated Patterns:
        - Base words: company, admin, welcome
        - Capitalized: Company, Admin, Welcome
        - With years: company2024, admin2024
        - With special: Company!, admin@123
        - Leet speak: C0mp@ny, @dm1n
        - Combinations: TechCorpAdmin, LondonWelcome2024
    """
    results = {
        "wordlist_path": output_file,
        "word_count": 0,
        "mutations_applied": [],
        "success": False,
        "error": None,
    }

    try:
        wordlist = set()  # Use set to avoid duplicates

        # Extract base words
        base_words = []

        # Company name
        if "company_name" in target_info:
            base_words.append(target_info["company_name"].lower())
            # Split camelCase or multi-word
            parts = re.findall(r"[A-Z][a-z]*|[a-z]+", target_info["company_name"])
            base_words.extend([p.lower() for p in parts if len(p) > 2])

        # Employee names
        if "employee_names" in target_info:
            base_words.extend([name.lower() for name in target_info["employee_names"]])

        # Locations
        if "locations" in target_info:
            base_words.extend([loc.lower().replace(" ", "") for loc in target_info["locations"]])

        # Products
        if "products" in target_info:
            base_words.extend([prod.lower() for prod in target_info["products"]])

        # Keywords
        if "keywords" in target_info:
            base_words.extend([kw.lower() for kw in target_info["keywords"]])

        # Common corporate words
        base_words.extend(
            [
                "admin",
                "administrator",
                "password",
                "welcome",
                "user",
                "login",
                "access",
                "secure",
                "company",
                "corporate",
            ]
        )

        # Remove duplicates and short words
        base_words = list({w for w in base_words if len(w) >= 3})

        # Add base words
        wordlist.update(base_words)
        results["mutations_applied"].append("base_words")

        # Capitalization variations
        for word in base_words:
            wordlist.add(word.capitalize())
            wordlist.add(word.upper())
        results["mutations_applied"].append("capitalization")

        # Date patterns
        if include_dates:
            years = target_info.get("years", [])
            if not years:
                current_year = datetime.now().year
                years = list(range(current_year - 5, current_year + 2))

            # Seasons
            seasons = ["spring", "summer", "fall", "autumn", "winter"]

            # Months
            months = [
                "january",
                "february",
                "march",
                "april",
                "may",
                "june",
                "july",
                "august",
                "september",
                "october",
                "november",
                "december",
            ]
            months_short = [
                "jan",
                "feb",
                "mar",
                "apr",
                "may",
                "jun",
                "jul",
                "aug",
                "sep",
                "oct",
                "nov",
                "dec",
            ]

            # Add year suffixes
            for word in list(base_words):
                for year in years:
                    wordlist.add(f"{word}{year}")
                    wordlist.add(f"{word.capitalize()}{year}")

            # Season + year
            for season in seasons:
                for year in years:
                    wordlist.add(f"{season}{year}")
                    wordlist.add(f"{season.capitalize()}{year}")

            # Month + year
            for month in months + months_short:
                for year in years:
                    wordlist.add(f"{month}{year}")
                    wordlist.add(f"{month.capitalize()}{year}")

            results["mutations_applied"].append("dates_and_years")

        # Common suffixes
        common_suffixes = ["123", "1234", "!", "!!", "@123", "#123", "1!", "2024!"]
        for word in list(base_words):
            for suffix in common_suffixes:
                wordlist.add(f"{word}{suffix}")
                wordlist.add(f"{word.capitalize()}{suffix}")
        results["mutations_applied"].append("common_suffixes")

        # Leet speak mutations
        if include_mutations:
            leet_map = {
                "a": "@",
                "e": "3",
                "i": "1",
                "o": "0",
                "s": "$",
                "t": "7",
                "l": "1",
                "g": "9",
            }

            for word in list(base_words)[:50]:  # Limit to avoid explosion
                # Single substitution
                for char, leet in leet_map.items():
                    if char in word:
                        leet_word = word.replace(char, leet, 1)
                        wordlist.add(leet_word)
                        wordlist.add(leet_word.capitalize())

                # Multiple substitutions
                leet_word = word
                for char, leet in leet_map.items():
                    leet_word = leet_word.replace(char, leet)
                wordlist.add(leet_word)
                wordlist.add(leet_word.capitalize())

            results["mutations_applied"].append("leet_speak")

        # Combinations
        if include_combinations and len(base_words) > 1:
            # Two-word combinations (limit to avoid explosion)
            top_words = base_words[:10]
            for word1, word2 in itertools.combinations(top_words, 2):
                wordlist.add(f"{word1}{word2}")
                wordlist.add(f"{word1.capitalize()}{word2}")
                wordlist.add(f"{word1.capitalize()}{word2.capitalize()}")

            results["mutations_applied"].append("word_combinations")

        # Common patterns
        for word in base_words[:20]:
            # admin123, Admin123!, admin@123
            wordlist.add(f"{word}123")
            wordlist.add(f"{word.capitalize()}123")
            wordlist.add(f"{word.capitalize()}123!")
            wordlist.add(f"{word}@123")

        # Write to file
        with open(output_file, "w") as f:
            for word in sorted(wordlist):
                f.write(word + "\n")

        results["word_count"] = len(wordlist)
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def assess_password_strength(password: str) -> dict[str, Any]:
    """
    Assess the strength of a password.

    Evaluates:
    - Length
    - Character diversity (lowercase, uppercase, digits, special)
    - Common patterns
    - Dictionary words
    - Entropy

    Args:
        password: Password to assess

    Returns:
        Dictionary containing:
        - strength_score: Score from 0-100
        - strength_rating: weak/medium/strong/very_strong
        - length_score: Length contribution to strength
        - complexity_score: Complexity contribution
        - pattern_vulnerabilities: List of detected weaknesses
        - recommendations: How to improve password
        - estimated_crack_time: Rough estimate of crack time
        - success: Whether assessment completed

    Example:
        >>> strength = assess_password_strength("Password123!")
        >>> print(f"Strength: {strength['strength_rating']}")
        >>> print(f"Score: {strength['strength_score']}/100")
        >>> for vuln in strength['pattern_vulnerabilities']:
        ...     print(f"  Weakness: {vuln}")
        >>> for rec in strength['recommendations']:
        ...     print(f"  Improve: {rec}")
    """
    results = {
        "strength_score": 0,
        "strength_rating": "",
        "length_score": 0,
        "complexity_score": 0,
        "pattern_vulnerabilities": [],
        "recommendations": [],
        "estimated_crack_time": "",
        "success": False,
        "error": None,
    }

    try:
        score = 0
        vulnerabilities = []
        recommendations = []

        # Length scoring (0-30 points)
        length = len(password)
        if length < 8:
            length_score = 0
            vulnerabilities.append("Password too short (< 8 characters)")
            recommendations.append("Use at least 12 characters")
        elif length < 12:
            length_score = 15
            recommendations.append("Consider using 12+ characters")
        elif length < 16:
            length_score = 25
        else:
            length_score = 30

        score += length_score
        results["length_score"] = length_score

        # Complexity scoring (0-40 points)
        complexity_score = 0

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)

        char_types = sum([has_lower, has_upper, has_digit, has_special])

        if char_types == 1:
            complexity_score = 0
            vulnerabilities.append("Only uses one character type")
            recommendations.append("Mix lowercase, uppercase, digits, and special characters")
        elif char_types == 2:
            complexity_score = 15
            recommendations.append("Add more character types (digits, special chars)")
        elif char_types == 3:
            complexity_score = 30
        else:
            complexity_score = 40

        score += complexity_score
        results["complexity_score"] = complexity_score

        # Pattern vulnerabilities (0-30 points penalty)
        pattern_penalty = 0

        # Common patterns
        common_passwords = [
            "password",
            "123456",
            "qwerty",
            "admin",
            "letmein",
            "welcome",
            "monkey",
            "dragon",
            "master",
            "sunshine",
        ]

        if password.lower() in common_passwords:
            vulnerabilities.append("Password is in common password list")
            pattern_penalty += 30

        # Sequential characters
        if re.search(r"(abc|bcd|cde|def|123|234|345|456)", password.lower()):
            vulnerabilities.append("Contains sequential characters")
            pattern_penalty += 10

        # Repeated characters
        if re.search(r"(.)\1{2,}", password):
            vulnerabilities.append("Contains repeated characters (aaa, 111)")
            pattern_penalty += 10

        # Simple patterns
        if re.search(r"^[a-z]+\d+$", password.lower()):
            vulnerabilities.append("Simple pattern: letters followed by numbers")
            pattern_penalty += 10

        if re.search(r"^[A-Z][a-z]+\d+!?$", password):
            vulnerabilities.append("Predictable corporate pattern (Capital+word+digits+!)")
            pattern_penalty += 5

        # Keyboard patterns
        if any(pattern in password.lower() for pattern in ["qwerty", "asdfgh", "zxcvbn"]):
            vulnerabilities.append("Contains keyboard pattern")
            pattern_penalty += 10

        score -= pattern_penalty
        score = max(0, score)  # Don't go negative

        # Uniqueness bonus (0-30 points)
        unique_chars = len(set(password))
        uniqueness_ratio = unique_chars / len(password)

        if uniqueness_ratio > 0.8:
            score += 30
        elif uniqueness_ratio > 0.6:
            score += 20
        else:
            score += 10
            recommendations.append("Avoid repeating characters")

        # Final score (0-100)
        results["strength_score"] = min(100, score)

        # Rating
        if results["strength_score"] < 30:
            results["strength_rating"] = "very_weak"
        elif results["strength_score"] < 50:
            results["strength_rating"] = "weak"
        elif results["strength_score"] < 70:
            results["strength_rating"] = "medium"
        elif results["strength_score"] < 90:
            results["strength_rating"] = "strong"
        else:
            results["strength_rating"] = "very_strong"

        results["pattern_vulnerabilities"] = vulnerabilities
        results["recommendations"] = recommendations

        # Estimate crack time (very rough)
        # Assumes 100 billion guesses/second (modern GPU)
        if results["strength_rating"] == "very_weak":
            results["estimated_crack_time"] = "< 1 second"
        elif results["strength_rating"] == "weak":
            results["estimated_crack_time"] = "< 1 minute"
        elif results["strength_rating"] == "medium":
            results["estimated_crack_time"] = "minutes to hours"
        elif results["strength_rating"] == "strong":
            results["estimated_crack_time"] = "days to weeks"
        else:
            results["estimated_crack_time"] = "months to years"

        results["success"] = True

    except Exception as e:
        results["error"] = str(e)

    return results


def compare_wordlists(
    wordlist1: str,
    wordlist2: str,
    output_unique1: str | None = None,
    output_unique2: str | None = None,
    output_common: str | None = None,
) -> dict[str, Any]:
    """
    Compare two wordlists and find unique/common words.

    Useful for:
    - Deduplicating wordlists
    - Finding gaps in coverage
    - Merging wordlists intelligently

    Args:
        wordlist1: Path to first wordlist
        wordlist2: Path to second wordlist
        output_unique1: Path to save words unique to wordlist1
        output_unique2: Path to save words unique to wordlist2
        output_common: Path to save words common to both

    Returns:
        Dictionary containing:
        - total_words_list1: Total words in wordlist1
        - total_words_list2: Total words in wordlist2
        - unique_to_list1: Words only in wordlist1
        - unique_to_list2: Words only in wordlist2
        - common_words: Words in both lists
        - success: Whether comparison completed

    Example:
        >>> result = compare_wordlists(
        ...     wordlist1="/usr/share/wordlists/rockyou.txt",
        ...     wordlist2="/tmp/custom_wordlist.txt",
        ...     output_unique2="/tmp/new_words.txt"
        ... )
        >>> print(f"Custom wordlist adds {result['unique_to_list2']} new words")
    """
    results = {
        "total_words_list1": 0,
        "total_words_list2": 0,
        "unique_to_list1": 0,
        "unique_to_list2": 0,
        "common_words": 0,
        "success": False,
        "error": None,
    }

    try:
        # Read wordlists
        with open(wordlist1, encoding="utf-8", errors="ignore") as f:
            words1 = {line.strip() for line in f if line.strip()}

        with open(wordlist2, encoding="utf-8", errors="ignore") as f:
            words2 = {line.strip() for line in f if line.strip()}

        results["total_words_list1"] = len(words1)
        results["total_words_list2"] = len(words2)

        # Find unique and common
        unique1 = words1 - words2
        unique2 = words2 - words1
        common = words1 & words2

        results["unique_to_list1"] = len(unique1)
        results["unique_to_list2"] = len(unique2)
        results["common_words"] = len(common)

        # Write output files if requested
        if output_unique1:
            with open(output_unique1, "w") as f:
                for word in sorted(unique1):
                    f.write(word + "\n")

        if output_unique2:
            with open(output_unique2, "w") as f:
                for word in sorted(unique2):
                    f.write(word + "\n")

        if output_common:
            with open(output_common, "w") as f:
                for word in sorted(common):
                    f.write(word + "\n")

        results["success"] = True

    except FileNotFoundError as e:
        results["error"] = f"Wordlist not found: {e.filename}"
    except Exception as e:
        results["error"] = str(e)

    return results
