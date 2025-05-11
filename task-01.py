from bloom_filter import BloomFilter


def check_password_uniqueness(bloom_filter: BloomFilter, passwords: list[str]) -> dict:
    """
    Check the uniqueness of passwords using a Bloom filter.

    Args:
        bloom_filter (BloomFilter): An instance of BloomFilter used to check for password presence.
        passwords (list[str]): A list of passwords to check for uniqueness.

    Returns:
        dict: A dictionary mapping each password to a boolean indicating whether it is unique
              (True if unique, False if not) or None if the password is invalid (empty or not a string).
    """

    results = {}
    for password in passwords:
        if not isinstance(password, str) or not password:
            results[password] = None
        else:
            results[password] = False if bloom_filter.contains(password) else True

    return results


def password_check_status(status: bool) -> str:
    """
    Return a string indicating whether a password is unique or has been used.

    Args:
        status (bool): A boolean indicating whether a password is unique (True) or has been used (False)
                       or None if the password is invalid (empty or not a string).

    Returns:
        str: A string indicating whether a password is unique ("унікальний" if unique, "вже використаний" if not)
             or "не может бути використаниим" if the password is invalid.
    """
    if status is None:
        return "не может бути використаниим"
    elif status:
        return "унікальний"
    else:
        return "вже використаний"


if __name__ == "__main__":
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = [
        "password123",
        "newpassword",
        "admin123",
        "guest",
    ]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' - {password_check_status(status)}.")
