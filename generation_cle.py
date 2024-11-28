from test_Rabin_miller import rabin_miller
import random

def Euclide_etendu(a, b):
        if b == 0:
            return a, 1, 0
        pgcd, x1, y1 = Euclide_etendu(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return pgcd, x, y

# Calcul de l'inverse modulaire (Algorithme d'Euclide étendu)
def mod_inverse(e, phi):
    """Calcule l'inverse modulaire de e modulo phi."""
    pgcd, x, _ = Euclide_etendu(e, phi)
    if pgcd != 1:
        raise ValueError("e et phi ne sont pas premiers entre eux")
    return x % phi

def generer_nombre_premier(bits):
    """Génère un grand nombre premier de 'bits' bits."""
    while True:
        nombre_candidat = random.getrandbits(bits) | (1 << bits - 1) | 1  # Assure que le nombre est impair et de taille correcte
        if rabin_miller(nombre_candidat):
            return nombre_candidat

# Fonction principale pour générer un couple de clés publique/privée
def generer_couple_cles():
    """Génère une paire de clés RSA (publique et privée) d'au moins 1024 bits."""
    # Étape 1 : Générer deux grands nombres premiers p et q
    p = generer_nombre_premier(512)
    q = generer_nombre_premier(512)
    # Étape 2 : Calculer n et phi(n)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Étape 3 : Trouver un e valide
    e = 65537  # e standard pour RSA
    if phi % e == 0:  # Assurer que e est premier avec phi
        e = 3
        while True:
            if rabin_miller(e) and phi % e != 0:
                break
            e += 2

    # Étape 4 : Calculer d, l'inverse modulaire de e
    d = mod_inverse(e, phi)

    # Retourner les clés publique (n, e) et privée (n, d)
    return (n, e), (n, d)

def creer_compte():
    """Crée un compte utilisateur en générant un couple de clés RSA."""
    print('\n Création de compte... \n')
    public_key, private_key = generer_couple_cles()
    #print(f"Clé publique : {public_key}")
    #print(f"Clé privée : {private_key}")

    # Stockage des clés dans des fichiers
    with open("cle_publique.key", "w") as f:
        # Sauvegarder la clé publique dans le format : n,e
        f.write(f"{public_key[0]},{public_key[1]}\n")

    with open("cle_privee_chiffree.key", "w") as f:
        # Sauvegarder la clé privée dans le format : n,d
        f.write(f"{private_key[0]},{private_key[1]}\n")

    print('\n Clés générées et stockées avec succès \n')