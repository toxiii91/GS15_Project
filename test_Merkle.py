def pad_key(key, block_size):
    """
    Ajuste la clé à la taille du bloc :
    - Si elle est plus longue que le bloc, la hacher.
    - Si elle est plus courte, la compléter avec des zéros.
    """       
    if len(key) > block_size:
        #print("Clé trop longue, hachage appliqué.")
        key = custom_hash(key)  # Hacher la clé si elle est trop longue
        #print(f"Clé après hachage : {key.hex()}")
        return key
    else:
        # Compléter avec des zéros si nécessaire
        key = key.ljust(block_size, b'\x00')
        key = custom_hash(key)
        #print(f"Longueur de la clé après padding : {len(key)}")
        #print(f"Clé après padding : {key.hex()}")
        return key


def xor_bytes(byte_array1, byte_array2):
    """Effectue un XOR entre deux tableaux de bytes."""
    return bytes([b1 ^ b2 for b1, b2 in zip(byte_array1, byte_array2)])


def rotate_left(value, shift, bits=32):
    """Effectue une rotation circulaire à gauche sur une valeur."""
    return ((value << shift) & (2**bits - 1)) | (value >> (bits - shift))


def custom_hash(data):
    """
    Fonction de hachage robuste basée sur une construction non linéaire.
    Inspirée des méthodes de Merkle-Damgård avec des permutations et XOR.
    """
    block_size = 64  # Taille du bloc en octets
    hash_size = 16   # Taille de sortie en octets (128 bits)
    
    # Valeur initiale (IV) choisie arbitrairement
    IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    # Découper les données en blocs
    blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]

    # Padding pour aligner sur des blocs multiples de block_size
    padding = b'\x80' + b'\x00' * ((block_size - len(data) % block_size - 9) % block_size) + len(data).to_bytes(8, 'big')
    if len(blocks) == 0 or len(blocks[-1]) < block_size:
        blocks.append(padding)
    else:
        blocks[-1] += padding

    # Initialiser avec IV
    H = IV[:]

    # Traiter chaque bloc
    for block in blocks:
        words = [int.from_bytes(block[i:i + 4], 'little') for i in range(0, len(block), 4)]
        a, b, c, d = H

        for i in range(16):  # 16 itérations
            f = (b & c) | (~b & d)  # Fonction non linéaire
            k = i % len(words)  # Index circulaire
            temp = (a + f + words[k] + i) & 0xFFFFFFFF
            temp = rotate_left(temp, (i % 5) + 1, 32)
            a, b, c, d = d, (b + temp) & 0xFFFFFFFF, b, c

        # Mise à jour des valeurs de hachage
        H = [(h + v) & 0xFFFFFFFF for h, v in zip(H, [a, b, c, d])]

    # Construire la sortie finale
    return b''.join(h.to_bytes(4, 'little') for h in H)[:hash_size]


def hmac(key, message, block_size=64):
    """
    Implémentation de HMAC sans bibliothèque externe.
    :param key: Clé secrète (bytes).
    :param message: Message à authentifier (bytes).
    :param block_size: Taille du bloc en octets.
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
    print("len: ", len(inner))
    inner_hash = custom_hash(inner)        # h(inner)

    outer = xor_bytes(key, opad) + inner_hash  # Clé ⊕ opad || inner_hash
    hmac_result = custom_hash(outer)          # h(outer)

    return hmac_result

# Exemple d'utilisation
if __name__ == "__main__":
    # Clé initiale
    key_str = "172634937217551326450149128688"
    key = key_str.encode('utf-8')  # Convertir la chaîne de caractères en bytes

    # Message à authentifier
    message = "message_import".encode('utf-8')  # Convertir le message en bytes

    # Calcul du HMAC
    hmac_result = hmac(key, message)

    # Affichage du résultat
    print("HMAC:", hmac_result.hex())

    # Test de l'effet avalanche
    #modified_key = key_str[:-1].encode('utf-8')  # Supprime le dernier caractère
    new_key = "1726349372175513264501491286881"
    modified_key = new_key.encode('utf-8')  # Convertir la chaîne de caractères en bytes
    modified_hmac = hmac(modified_key, message)
    print("HMAC (clé modifiée):", modified_hmac.hex())
    #print("Différences :", sum(b1 != b2 for b1, b2 in zip(hmac_result, modified_hmac)))
