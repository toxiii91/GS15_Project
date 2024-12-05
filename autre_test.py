# Fonction de hachage simple (pour illustration)
def simple_hash(data):
    # Initialiser un "résultat" de 64 bits (un entier de 0)
    result = 0
    # Traiter les données par blocs de 8 octets
    for i in range(0, len(data), 8):
        # Extraire un bloc de 8 octets (64 bits)
        block = data[i:i+8]
        # Si le bloc a moins de 8 octets, l'ajouter avec des zéros à droite
        if len(block) < 8:
            block = block.ljust(8, b'\x00')
        # Convertir le bloc en entier (sur 64 bits)
        block_value = int.from_bytes(block, byteorder='big')
        # Appliquer le XOR sur le résultat avec le bloc actuel
        result ^= block_value
    return result

# Fonction HMAC
def hmac_simple(key, message):
    block_size = 64  # Taille du bloc pour SHA-256 est de 64 octets
    
    # Convertir la clé de chaîne à entier, puis en bytes
    key = int(key)  # Convertir la clé en entier (si la clé est un nombre sous forme de chaîne)
    key = key.to_bytes((key.bit_length() + 7) // 8, byteorder='big')
    print('len\n', len(key))
    if len(key) > block_size:
        print('ici')
        key = simple_hash(key)  # Si la clé est trop longue, on la réduit
        print('\nkey2:\n', key)
        key = key.to_bytes(block_size, byteorder='big')  # On la transforme en octets
    
    # Si la clé est trop courte, on l'ajoute avec des zéros à droite
    if len(key) < block_size:
        print('la')
        key = key.ljust(block_size, b'\x00')

    # Appliquer ipad et opad
    ipad = bytes([k ^ 0x36 for k in key])  # XOR avec 0x36 pour ipad
    opad = bytes([k ^ 0x5C for k in key])  # XOR avec 0x5C pour opad

    # Phase 1 : H(ipad || message)
    inner_hash = simple_hash(ipad + message.encode('utf-8'))

    # Convertir inner_hash en bytes (64 bits = 8 octets)
    inner_hash_bytes = inner_hash.to_bytes(8, byteorder='big')

    # Phase 2 : H(opad || inner_hash)
    final_hmac = simple_hash(opad + inner_hash_bytes)  # Le hachage final est le HMAC
    
    return final_hmac

# Exemple d'utilisation
key = "1726349372175513264501491286882749955513917115026762575530586293391694800210328094670019202080676774565673977283782402618127203705055319315729100159396351110997746194639438892096866978904817593521262819425772899369473698289707521105527255542891901748183320599352528955485172373529650485234871798589828878772187206403888293693035821857145120103074362544674515229657600643054352938807508922356123447430249399281543985964750908070622968039027677207724605877234008180"
message = "Message à authentifier"
hmac_value = hmac_simple(key, message)
print(f"HMAC: {hmac_value}")
