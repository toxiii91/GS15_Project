import random
import os
from math import gcd
import shutil

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

def key_to_binary(key):
    # Assurez-vous que la clé est un entier
    if isinstance(key, str):
        key = int(key)
    
    # Convertir l'entier en binaire (sans le préfixe '0b')
    binary_key = bin(key)[2:]
    
    return binary_key

def write_to_file(filename, content):
    """Crée un fichier et écrit le contenu dedans."""
    with open(filename, "w", encoding="utf-8") as file:
        file.write(content)

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

def test_message_encryption(username):
    # Lire la valeur depuis la clé de session stocké côté user (côté client)

    chemin_dossier_client = os.path.join("users", username)
    chemin_dossier_coffre = os.path.join("coffre_fort", username)
    # Sauvegarder la clé dans le fichier dans le repertoire de l'user côté client
    chemin_fichier = os.path.join(chemin_dossier_client, "keya.key")
    with open(chemin_fichier, "r") as f:
        cle = int(f.read().strip())
    # Exemple de cle :
    cle_initiale_dh = key_to_binary(cle)
    round_keys = generate_keys(cle_initiale_dh)

    #Entrer un message ou un fichier
    choix = input("Voulez-vous entrer un message ou un fichier ? (message/fichier) : ").strip().lower()

    if choix == "message":
        message = input("Entrez votre message : ")
        #print("Message original :", message)
    elif choix == "fichier":
        chemin_fichier = input("Entrez le chemin du fichier : ").strip()
        try:
            with open(chemin_fichier, 'r', encoding='utf-8') as fichier:
                message = fichier.read()
                #print(f"Contenu du fichier lu :\n{message}")
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
    nom_fichier = os.path.basename(chemin_fichier)  # Récupère le nom du fichier sans le chemin
    nom_fichier_encrypte = nom_fichier.split('.')[0] + '_encrypte.txt'  # Ajoute _encrypte.txt au nom
    chemin_fichier_encrypte = os.path.join(chemin_dossier_client, nom_fichier_encrypte)
    # print("\nMessage chiffré (hexadécimal) :", encrypted.hex())
    # Décommenter si on souhaite ecrire le message chiffre dans un nouveau fichier
    encrypted_hex = encrypted.hex()
    write_to_file(chemin_fichier_encrypte, encrypted_hex)

    print("Chiffrement du fichier réussi, voulez vous le rediriger vers le coffre")
    print("1. Oui")
    print("2. Non")
    choix = input("Choisissez une option : ")
    if choix == "1":
        # envoyer le fichier sur le coffre 
        chemin_source = chemin_fichier_encrypte
        chemin_destination = os.path.join(chemin_dossier_coffre, nom_fichier)
        # Déplacer le fichier
        try:
            shutil.move(chemin_source, chemin_destination)
            print(f"Le fichier a été déplacé vers {chemin_destination}")
        except FileNotFoundError:
            print("Erreur : Le fichier source n'a pas été trouvé.")
        except PermissionError:
            print("Erreur : Vous n'avez pas les permissions nécessaires pour déplacer ce fichier.")
        except Exception as e:
            print(f"Erreur lors du déplacement du fichier : {e}")
        # demander si on veut le déchiffrer

        print("Le fichier a été deplacé avec succès. Voulez vous le déchiffré")
        print("1. Oui")
        print("2. Non")
        choix = input("Choisissez une option : ")
        # Déchiffrement
        if choix == "1":
            try:
                decrypted = cobra_decrypt_message(encrypted, round_keys)
                # print("\nMessage déchiffré :", decrypted)
                # Décommenter si on souhaite ecrire le message chiffre dans un nouveau fichier
                write_to_file(chemin_destination, decrypted)
            except Exception as e:
                print("\nErreur lors du déchiffrement :", str(e))
        elif choix == "2":
            print("ne rien faire")
        else:
            print("Option invalide, veuillez réessayer.")
    elif choix == "2":
        print("ne rien faire")
    else:
        print("Option invalide, veuillez réessayer.")


    



#if __name__ == "__main__":
 #   test_message_encryption()

