from test_Rabin_miller import rabin_miller
import tools_crypto

# Fonction de génération d'un hash rudimentaire
def simple_hash_long(data, output_size=1024):
    """Génère un hash étendu en concaténant des itérations du hachage."""
    hash_value = 0
    result = ""
    for i in range(output_size // 32):  # Génère assez de blocs pour atteindre la taille demandée
        for char in data:
            hash_value = (hash_value * 31 + ord(char) + i) % (2**32)
        result += format(hash_value, "08x")  # Représentation hexadécimale sur 8 caractères
    return int(result[:output_size // 4], 16)  # Truncate pour respecter output_size

# Fonction éponge rudimentaire
def fonction_eponge(data, rounds=100):
    state = 0
    for _ in range(rounds):
        state = (state + simple_hash_long(data)) % (2**64)
        data = str(state) + data[::-1]
    return state

# Fonction KDF pour dériver d à partir du mot de passe et phi
def KDF(mdp, phi):
    d = simple_hash_long(mdp, output_size=1024) % phi  # Générer un hash plus long
    if d < 2:
        d += 2

    # Vérifier que d est premier avec phi et ajuster si nécessaire
    while True:
        if rabin_miller(d) and phi % d != 0:
            break
        d += 1
    return d

# Fonction principale pour générer un couple de clés publique/privée
def generer_couple_cles(mdp):
    """Génère une paire de clés RSA (publique et privée) d'au moins 1024 bits."""
    # Étape 1 : Générer deux grands nombres premiers p et q
    p = tools_crypto.generer_nombre_premier(512)
    
    q = tools_crypto.generer_nombre_premier(512)
    
    
    # Étape 2 : Calculer n et phi(n)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Étape 3 : Utiliser KDF pour dériver d à partir du mot de passe
    d = KDF(mdp, phi)
    
    # Étape 4 : Calculer e, l'inverse modulaire de d
    e = tools_crypto.mod_inverse(d, phi)
    
    # Retourner les clés publique (n, e) et privée (n, d)
    return (n, e), (n, d)

def creer_compte():
    """Crée un compte utilisateur en générant un couple de clés RSA."""
    print('\n Création de compte... \n')
    # Demander le mot de passe à l'utilisateur
    mdp = input("Entrez votre mot de passe : ")

    public_key, private_key = generer_couple_cles(mdp)
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