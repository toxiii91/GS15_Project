from test_Rabin_miller import rabin_miller
import tools_crypto
import os

def obtenir_identifiant():
    # Répertoire où les dossiers utilisateurs sont stockés
    repertoire_coffre_fort = "coffre_fort"

    # Répertoire où des users côté client
    repertoire_user = "users"
    
    # Créer le répertoire s'il n'existe pas déjà
    if not os.path.exists(repertoire_coffre_fort):
        os.makedirs(repertoire_coffre_fort)

    while True:
        # Demander à l'utilisateur de saisir un identifiant
        identifiant = input("Entrez votre identifiant : ").strip()
        
        # Chemin complet du dossier utilisateur côte coffre
        chemin_dossier_coffre = os.path.join(repertoire_coffre_fort, identifiant)

        # Chemin complet du dossier utilisateur côte client
        chemin_dossier_user = os.path.join(repertoire_user, identifiant)
        
        # Vérifier si le dossier existe déjà
        if os.path.exists(chemin_dossier_coffre) or os.path.exists(chemin_dossier_user):
            print(f"Un utilisateur avec l'identifiant '{identifiant}' existe déjà. Veuillez en choisir un autre.")
        else:
            # Créer le dossier pour cet identifiant
            os.makedirs(chemin_dossier_coffre)
            os.makedirs(chemin_dossier_user)
            print(f"Dossier créé pour l'identifiant '{identifiant}'.")
            break  # Sortir de la boucle si tout est OK

    return identifiant, chemin_dossier_coffre, chemin_dossier_user

def enregistrer_fichier(chemin_dossier, nom_fichier, contenu):
    # Construire le chemin complet pour le fichier
    chemin_fichier = os.path.join(chemin_dossier, nom_fichier)
    
    # Enregistrer le contenu dans le fichier
    with open(chemin_fichier, "w") as f:
    # Sauvegarder la clé publique dans le format : n,e
        f.write(f"{contenu[0]},{contenu[1]}\n")
    
    print(f"Fichier '{nom_fichier}' enregistré dans : {chemin_dossier}")

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
    # Appel des fonctions
    id_utilisateur, dossier_utilisateur_coffre, dossier_utilisateur_client  = obtenir_identifiant()
    print(f"Identifiant final : {id_utilisateur}")
    
    mdp = input("Entrez votre mot de passe permettant de générer une paire clé RSA : ")

    public_key, private_key = generer_couple_cles(mdp)
    #print(f"Clé publique : {public_key}")
    #print(f"Clé privée : {private_key}")

    enregistrer_fichier(dossier_utilisateur_coffre, "public_key.key", public_key)
    enregistrer_fichier(dossier_utilisateur_client, "private_key.key", private_key)
    # Stockage des clés dans des fichiers

    print('\n Clés générées et stockées avec succès \n')