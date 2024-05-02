def simple_encrypt(word):
    encrypted_word = ""
    for char in word:
        encrypted_char = chr(ord(char) + 1)  # Shift each character by 1
        encrypted_word += encrypted_char
    return encrypted_word