import random
import os
from math import gcd

# Constantes
PHI = 0x9E3779B9  # Nombre parfait φ
MASQUE_128 = (1 << 128) - 1

# S-Boxes basées sur DES
S_BOXES = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
]

# Génération des S-Boxes inverses
INVERSE_S_BOXES = []
for sbox in S_BOXES:
    inverse_sbox = [0] * 16
    for i, val in enumerate(sbox):
        inverse_sbox[val] = i
    INVERSE_S_BOXES.append(inverse_sbox)

def validate_cle_initiale_dh(cle_initiale_dh):
    if not set(cle_initiale_dh).issubset({'0', '1'}):
        raise ValueError("La clé initiale doit être une chaîne binaire composée uniquement de '0' et '1'.")
    if len(cle_initiale_dh) > 256:
        raise ValueError("La clé initiale ne doit pas dépasser 256 bits.")

def generate_keys(cle_initiale_dh):
    validate_cle_initiale_dh(cle_initiale_dh)
    if len(cle_initiale_dh) < 256:
        cle_initiale_dh = cle_initiale_dh.ljust(256, '0')  # Padding si la clé Diffie Hellman est inférieure à 256 bits

    # Création des blocs
    blocs = []
    for i in range(0, 256, 32):
        blocs.append(int(cle_initiale_dh[i:i + 32], 2))
    
    w = blocs[:8]  # Initialisation avec les 8 premiers blocs
    for i in range(8, 132):
        nouvelle_cle = (w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ i) & 0xFFFFFFFF
        tournee = ((nouvelle_cle << 11) | (nouvelle_cle >> (32 - 11))) & 0xFFFFFFFF
        w.append(tournee)
    
    cles_tours = [w[i:i + 4] for i in range(0, 132, 4)]
    return cles_tours[:33]


def substitute_block(block, round_number):
    sbox = S_BOXES[round_number // 8]
    substituted = 0
    for i in range(32):
        nibble = (block >> (i * 4)) & 0xF
        substituted |= sbox[nibble] << (i * 4)
    return substituted & MASQUE_128

def inverse_substitute_block(block, round_number):
    inverse_sbox = INVERSE_S_BOXES[round_number // 8]
    substituted = 0
    for i in range(32):
        nibble = (block >> (i * 4)) & 0xF
        substituted |= inverse_sbox[nibble] << (i * 4)
    return substituted & MASQUE_128

def feistel_function(right_half, key):
    byte = right_half & 0xFF
    reversed_bits = int('{:08b}'.format(byte)[::-1], 2)
    to_invert = (reversed_bits + 1) % 257

    if gcd(to_invert, 257) != 1:
        transformed = 0
    else:
        transformed = (pow(to_invert, -1, 257) - 1) % 256

    permutation = [7, 6, 5, 4, 3, 2, 1, 0]
    permuted = sum(((transformed >> i) & 1) << permutation[i] for i in range(8))

    return permuted ^ (key & 0xFF)

def rotate_left(state, shift):
    return ((state << shift) | (state >> (128 - shift))) & MASQUE_128

def rotate_right(state, shift):
    return ((state >> shift) | (state << (128 - shift))) & MASQUE_128

def cobra_encrypt(plaintext, round_keys):
    state = plaintext & MASQUE_128

    # Début des 32 tours d'encryptage
    for round_number in range(32):
        # Calcul de la clé de tour
        key = 0
        for i in range(4):
            key += (round_keys[round_number][i] << (96 - 32 * i))
        key &= MASQUE_128  # Appliquer le masque pour limiter à 128 bits

        # Étape "Add Round Key"
        state ^= key

        # Étape de substitution
        state = substitute_block(state, round_number)

        # Séparer l'état en moitiés gauche et droite
        left = (state >> 64) & 0xFFFFFFFFFFFFFFFF  # Moitié gauche
        right = state & 0xFFFFFFFFFFFFFFFF        # Moitié droite

        # Étape Feistel
        temp = right
        f_out = feistel_function(right, round_keys[round_number][0])
        left ^= f_out
        state = ((left << 64) | temp) & MASQUE_128  # Réassembler les moitiés

        # Rotation gauche de l'état
        state = rotate_left(state, 7)

    # Ajouter la clé finale
    final_key = 0
    for i in range(4):
        final_key += (round_keys[32][i] << (96 - 32 * i))
    final_key &= MASQUE_128  # Appliquer le masque pour limiter à 128 bits

    state ^= final_key  # Ajouter la clé finale au résultat

    return state
def cobra_encrypt_file(chemin_fichier, round_keys, chemin_sortie=None):
    if not os.path.exists(chemin_fichier):
        print("[ERREUR] Fichier introuvable pour Cobra.")
        return None

    # Récupérer l'extension d’origine
    _, extension = os.path.splitext(chemin_fichier)  # ex. (fichier_test, .txt)
    extension_bytes = extension.encode('utf-8')       # b".txt"
    long_ext = len(extension_bytes)
    if long_ext > 255:
        print("[ERREUR] Extension trop longue (>255 octets).")
        return None

    # Fichier de sortie .cobra
    if chemin_sortie is None:
        chemin_sortie = chemin_fichier + ".cobra"

    # Lecture du fichier d’entrée (binaire)
    with open(chemin_fichier, "rb") as f_in:
        data = f_in.read()

    # On applique un padding PKCS#7 (16 octets) pour Cobra
    block_size = 16
    pad_len = block_size - (len(data) % block_size)
    padded_data = data + bytes([pad_len] * pad_len)

    # Construire le header : [1 octet: taille extension] + extension
    header = bytes([long_ext]) + extension_bytes
    # => ex. si extension = ".txt" => b'\x04.txt' (car .txt fait 4 octets)

    # On concatène header + le vrai contenu
    data_a_chiffrer = header + padded_data

    # Chiffrement bloc par bloc
    resultat = bytearray()
    for i in range(0, len(data_a_chiffrer), block_size):
        block = int.from_bytes(data_a_chiffrer[i:i + block_size], 'big')
        encrypted_block = cobra_encrypt(block, round_keys)
        resultat += encrypted_block.to_bytes(block_size, 'big')

    # Écriture du fichier chiffré
    with open(chemin_sortie, "wb") as f_out:
        f_out.write(resultat)

    print(f"[OK] Fichier chiffré avec Cobra : {chemin_sortie}")
    return chemin_sortie

def cobra_decrypt_file(chemin_fichier_chiffre, round_keys, chemin_sortie=None):
    if not os.path.exists(chemin_fichier_chiffre):
        print("[ERREUR] Fichier chiffré Cobra introuvable.")
        return None

    # Si on ne sait pas le nom de sortie, on met .dec ou un suffixe
    if chemin_sortie is None:
        chemin_sortie = chemin_fichier_chiffre + ".dec"

    with open(chemin_fichier_chiffre, "rb") as f_in:
        data_chiffree = f_in.read()

    block_size = 16
    resultat = bytearray()

    # Déchiffrement bloc par bloc
    for i in range(0, len(data_chiffree), block_size):
        block = int.from_bytes(data_chiffree[i : i + block_size], 'big')
        decrypted_block = cobra_decrypt(block, round_keys)
        resultat += decrypted_block.to_bytes(block_size, 'big')

    # Retirer le padding PKCS#7 après avoir tout déchiffré
    pad_len = resultat[-1]
    if pad_len > block_size or any(p != pad_len for p in resultat[-pad_len:]):
        print("[ERREUR] Padding Cobra invalide.")
        return None

    # On retire le padding
    resultat = resultat[:-pad_len]

    # ==========================
    # Relecture du header
    # ==========================
    if len(resultat) < 1:
        print("[ERREUR] Données trop courtes, pas de header.")
        return None

    long_ext = resultat[0]  # 1er octet = taille extension
    if len(resultat) < 1 + long_ext:
        print("[ERREUR] Header invalide ou corrompu.")
        return None

    extension_bytes = resultat[1 : 1 + long_ext]  # Lire l'extension
    extension = extension_bytes.decode('utf-8', errors='replace')  # ex. ".txt"

    # Le reste est le fichier clair
    corps = resultat[1 + long_ext :]

    # Écrire le fichier déchiffré
    # => si tu veux tout renommer précisément, tu peux
    #    par exemple stocker le "chemin_sortie" sans .dec
    #    et y ajouter extension.
    if chemin_sortie.endswith(".dec"):
        # on retire .dec
        chemin_base = chemin_sortie[:-4]
    else:
        chemin_base = chemin_sortie

    chemin_definitif = chemin_base + extension

    with open(chemin_definitif, "wb") as f_out:
        f_out.write(corps)

    print(f"[OK] Fichier déchiffré Cobra avec extension restaurée : {chemin_definitif}")
    return chemin_definitif



def cobra_decrypt(texte_chiffre, round_keys):
    state = texte_chiffre

    # Calcul de la clé finale
    final_key = 0
    for i in range(4):
        final_key += (round_keys[32][i] << (96 - 32 * i))
    final_key &= MASQUE_128
    state ^= final_key

    # Processus de déchiffrement sur 32 tours
    for round_number in reversed(range(32)):
        # Rotation droite de 7 bits
        state = rotate_right(state, 7)

        # Séparation en deux moitiés : gauche et droite
        left = (state >> 64) & 0xFFFFFFFFFFFFFFFF
        right = state & 0xFFFFFFFFFFFFFFFF

        # Fonction Feistel
        f_out = feistel_function(right, round_keys[round_number][0])
        left ^= f_out

        # Combinaison des moitiés
        state = ((left << 64) | right) & MASQUE_128

        # Substitution inverse
        state = inverse_substitute_block(state, round_number)

        # Ajout de la clé du tour
        key = 0
        for i in range(4):
            key += (round_keys[round_number][i] << (96 - 32 * i))
        key &= MASQUE_128
        state ^= key

    return state


def cobra_encrypt_message(message, round_keys):
    padded_length = 16 - (len(message.encode('utf-8')) % 16)
    padded_message = message.encode('utf-8') + bytes([padded_length] * padded_length)
    encrypted = b''
    for i in range(0, len(padded_message), 16):
        block = int.from_bytes(padded_message[i:i + 16], 'big')
        encrypted_block = cobra_encrypt(block, round_keys)
        encrypted += encrypted_block.to_bytes(16, 'big')
    return encrypted

def cobra_decrypt_message(encrypted_message, round_keys):
    decrypted = b''
    for i in range(0, len(encrypted_message), 16):
        block = int.from_bytes(encrypted_message[i:i + 16], 'big')
        decrypted_block = cobra_decrypt(block, round_keys)
        decrypted += decrypted_block.to_bytes(16, 'big')

    padding_len = decrypted[-1]
    if padding_len > 16 or any(p != padding_len for p in decrypted[-padding_len:]):
        raise ValueError("Padding invalide détecté lors du déchiffrement.")
    return decrypted[:-padding_len].decode('utf-8')

def test_message_encryption():
    cle_initiale_dh = "11011010101101001010101101101010101010101010101010101010101010101111"
    round_keys = generate_keys(cle_initiale_dh)

    #Entrer un message ou un fichier
    choix = input("Voulez-vous entrer un message ou un fichier ? (message/fichier) : ").strip().lower()

    if choix == "message":
        message = input("Entrez votre message : ")
        print("Message original :", message)
    elif choix == "fichier":
        chemin_fichier = input("Entrez le chemin du fichier : ").strip()
        try:
            with open(chemin_fichier, 'r', encoding='utf-8') as fichier:
                message = fichier.read()
                print(f"Contenu du fichier lu :\n{message}")
        except FileNotFoundError:
            print("Erreur : fichier non trouvé.")
            return
        except Exception as e:
            print(f"Erreur lors de la lecture du fichier : {e}")
            return
    else:
        print("Choix invalide. Veuillez choisir 'message' ou 'fichier'.")
        return

    # Chiffrement
    encrypted = cobra_encrypt_message(message, round_keys)
    print("\nMessage chiffré (hexadécimal) :", encrypted.hex())

    # Déchiffrement
    try:
        decrypted = cobra_decrypt_message(encrypted, round_keys)
        print("\nMessage déchiffré :", decrypted)
    except Exception as e:
        print("\nErreur lors du déchiffrement :", str(e))


if __name__ == "__main__":
    test_message_encryption()

