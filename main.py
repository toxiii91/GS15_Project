import random

def charger_cle_publique():
    """Charge la clé publique à partir du fichier."""
    try:
        with open("cle_publique.txt", "r") as f:
            n, e = map(int, f.read().strip().split(","))  # Lire n et e comme des entiers
        return (n, e)
    except FileNotFoundError:
        print("Erreur : Le fichier de la clé publique est introuvable.")
        return None
    except ValueError:
        print("Erreur : Format de la clé publique invalide.")
        return None

def charger_cle_privee():
    """Charge la clé privée à partir du fichier."""
    try:
        with open("cle_privee_chiffree.txt", "r") as f:
            n, d = map(int, f.read().strip().split(","))  # Lire n et d comme des entiers
        return (n, d)
    except FileNotFoundError:
        print("Erreur : Le fichier de la clé privée est introuvable.")
        return None
    except ValueError:
        print("Erreur : Format de la clé privée invalide.")
        return None


def preuve_divulgation_nulle():
    """
    Preuve à divulgation nulle pour vérifier si la clé publique correspond à la clé privée.
    Les clés sont chargées depuis les fichiers 'cle_publique.txt' et 'cle_privee_chiffree.txt'.
    """
    # Charger les clés
    public_key = charger_cle_publique()
    private_key = charger_cle_privee()

    if public_key is None or private_key is None:
        print("Erreur : Impossible de charger les clés.")
        return

    n, e = public_key
    _, d = private_key  # On peut écrire n, d pour être explicite

    # Étape 1 : Générer un message aléatoire m
    m = random.randint(2, n - 2)  # m dans [2, n-2] pour éviter les cas limites
    E = pow(m, e, n)  # Calcul de l'engagement E = m^e mod n
    print(f"Message aléatoire m : {m}")
    print(f"Engagement E envoyé au vérificateur : {E}")

    # Étape 2 : Vérificateur envoie un challenge c (0 ou 1)
    c = random.randint(0, 1)  # Challenge aléatoire
    print(f"Challenge reçu du vérificateur : {c}")

    # Étape 3 : Répondre au challenge
    if c == 0:
        # Réponse pour c = 0 : m
        print(f"Réponse envoyée (c=0) : {m}")
        is_valid = (E == pow(m, e, n))
        print(f"Vérification (c=0) : {is_valid}")
        return is_valid
    elif c == 1:
        # Réponse pour c = 1 : s = m^d mod n
        s = pow(m, d, n)  # Calcul de la réponse pour c = 1
        print(f"Réponse envoyée (c=1) : {s}")
        is_valid = (E == pow(s, e, n))
        print(f"Vérification (c=1) : {is_valid}")
        return is_valid

        return E == pow(s, e, n)  # Vérification côté vérificateur

def verifier_correspondance():
    """Vérifie si une clé publique correspond à une clé privée avec une preuve à divulgation nulle."""
    print("Vérification de la correspondance des clés publique et privée...")
    
    # Appel de la preuve à divulgation nulle
    resultat = preuve_divulgation_nulle()
    if resultat:
        print("Succès : La clé publique correspond bien à la clé privée.")
    else:
        print("Échec : La clé publique ne correspond pas à la clé privée.")

# Fonction pour tester la primalité (Algorithme de Miller-Rabin)
def is_prime(n, k=10):
    """Teste si n est premier avec le test de Miller-Rabin."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Écriture de n-1 sous la forme 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Test de primalité k fois
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)  # a^d % n
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)  # x^2 % n
            if x == n - 1:
                break
        else:
            return False
    return True

# Fonction pour générer un grand nombre premier
def generate_large_prime(bits):
    """Génère un grand nombre premier de 'bits' bits."""
    while True:
        prime_candidate = random.getrandbits(bits) | (1 << bits - 1) | 1  # Assure que le nombre est impair et de taille correcte
        if is_prime(prime_candidate):
            return prime_candidate

# Calcul de l'inverse modulaire (Algorithme d'Euclide étendu)
def mod_inverse(e, phi):
    """Calcule l'inverse modulaire de e modulo phi."""
    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        gcd, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y

    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("e et phi ne sont pas premiers entre eux")
    return x % phi

# Fonction principale pour générer un couple de clés publique/privée
def generer_couple_cles():
    """Génère une paire de clés RSA (publique et privée) d'au moins 1024 bits."""
    # Étape 1 : Générer deux grands nombres premiers p et q
    p = generate_large_prime(512)
    q = generate_large_prime(512)

    # Étape 2 : Calculer n et phi(n)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Étape 3 : Trouver un e valide
    e = 65537  # e standard pour RSA
    if phi % e == 0:  # Assurer que e est premier avec phi
        e = 3
        while True:
            if is_prime(e) and phi % e != 0:
                break
            e += 2

    # Étape 4 : Calculer d, l'inverse modulaire de e
    d = mod_inverse(e, phi)

    # Retourner les clés publique (n, e) et privée (n, d)
    return (n, e), (n, d)


def creer_compte():
    """Crée un compte utilisateur en générant un couple de clés RSA."""
    print("Création de compte...")
    public_key, private_key = generer_couple_cles()
    print(f"Clé publique : {public_key}")
    print(f"Clé privée : {private_key}")

    # Stockage des clés dans des fichiers
    with open("cle_publique.txt", "w") as f:
        # Sauvegarder la clé publique dans le format : n,e
        f.write(f"{public_key[0]},{public_key[1]}\n")

    with open("cle_privee_chiffree.txt", "w") as f:
        # Sauvegarder la clé privée dans le format : n,d
        f.write(f"{private_key[0]},{private_key[1]}\n")

    print("Clés générées et stockées avec succès !")


def menu_principal():
    """Affiche le menu principal du programme."""
    while True:
        print("Bienvenue dans le coffre-fort numérique !")
        print("1. Créer un compte")
        print("2. Quitter")
        print("3. Vérifier une clé publique avec une preuve à divulgation nulle")
        choix = input("Choisissez une option : ")

        if choix == "1":
            creer_compte()
        elif choix == "2":
            print("Au revoir !")
            break
        elif choix == "3":
            verifier_correspondance()
        else:
            print("Option invalide, veuillez réessayer.")

if __name__ == "__main__":
    menu_principal()
