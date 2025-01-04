def custom_hash(data):
    """Fonction de hachage simplifiée basée sur une permutation et XOR."""
    hash_value = 0
    for byte in data:
        hash_value = (hash_value * 31 + byte) % 2**32
    return hash_value.to_bytes(16, 'big')  # Retourne un résultat de 16 octets (128 bits)

def pad_key(key, block_size):
    """
    Ajuste la clé à la taille du bloc :
    - Si elle est plus longue que le bloc, la hacher.
    - Si elle est plus courte, la compléter avec des zéros.
    """
    print('len_key\n', len(key))
    print('block_size', block_size)
    if len(key) > block_size:
        print("Clé trop longue, hachage appliqué.")
        key = custom_hash(key)  # Hacher la clé si elle est trop longue
        return key
    else:
        return key.ljust(block_size, b'\x00')  # Compléter avec des zéros si nécessaire

def xor_bytes(byte_array1, byte_array2):
    """Effectue un XOR entre deux tableaux de bytes."""
    return bytes([b1 ^ b2 for b1, b2 in zip(byte_array1, byte_array2)])

def hmac(key, message, block_size=64):
    """
    Implémentation de HMAC en Python.
    :param key: Clé secrète (bytes).
    :param message: Message à authentifier (bytes).
    :param block_size: Taille du bloc en octets (64 pour SHA-256 par exemple).
    """
    # Étape 1 : Préparer les paddings ipad et opad
    ipad = b'\x36' * block_size
    opad = b'\x5c' * block_size

    # Étape 2 : Ajuster la clé à la taille du bloc
    key = pad_key(key, block_size)

    # Debug : Afficher la clé après padding
    print(f"Clé après padding : {key.hex()}")

    # Étape 3 : Calculer HMAC
    inner = xor_bytes(key, ipad) + message  # Clé ⊕ ipad || message
    inner_hash = custom_hash(inner)        # h(inner)

    outer = xor_bytes(key, opad) + inner_hash  # Clé ⊕ opad || inner_hash
    hmac_result = custom_hash(outer)          # h(outer)

    return hmac_result

# Exemple d'utilisation
if __name__ == "__main__":
    # Clé non hexadécimale : chaîne de chiffres
    key_str = "172634937217551326450149128688274995551391711502676257553058629339169480021032809467001920208067677456567397728378240261812720370505531931572910015939635111099774619463943889209686697890481759352126281942577289936947369828970752110552725554289190174818332059935252895548517237352965048523487179858982887877218720640388829369303582185714512010307436254467451522965760064305435293880750892235612344743024939928154398596475090807062296803902767720772460587723400818"
    
    # Convertir la clé directement en bytes
    key = key_str.encode('utf-8')  # Convertit la chaîne de caractères en bytes

    # Message à authentifier
    message = "message import".encode('utf-8')  # Convertit le message en bytes

    # Calcul du HMAC
    hmac_result = hmac(key, message)

    # Affichage du résultat
    print("HMAC:", hmac_result.hex())