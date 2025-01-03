import os

TAILLE_BLOC = 127

def chiffrer_fichier_par_blocs(chemin_fichier, public_key, chemin_sortie=None):
    """
    Chiffre un fichier par blocs RSA (sans padding).
    Gère l'erreur si le fichier n'existe pas.
    """

    # Vérifier que le fichier existe
    if not os.path.exists(chemin_fichier):
        print("[ERREUR] Le fichier à chiffrer n'existe pas ou le chemin est invalide.")
        return None

    n, e = public_key

    # 1. Lecture du fichier d'entrée (binaire)
    with open(chemin_fichier, "rb") as f_in:
        data = f_in.read()

    # 2. Nom du fichier de sortie (ex: "monfichier.txt" -> "monfichier.txt.enc")
    if chemin_sortie is None:
        chemin_sortie = chemin_fichier + ".enc"

    blocs_chiffres = []

    # 3. Parcourir les données par paquets de TAILLE_BLOC octets
    for i in range(0, len(data), TAILLE_BLOC):
        bloc = data[i : i + TAILLE_BLOC]

        # Convertir le bloc (octets) en entier
        bloc_int = int.from_bytes(bloc, byteorder='big')

        # Chiffrer l'entier
        bloc_chiffre_int = pow(bloc_int, e, n)

        # Convertir l'entier chiffré en octets (de taille fixe = taille clé RSA)
        bloc_chiffre_bytes = bloc_chiffre_int.to_bytes((n.bit_length() + 7) // 8, 'big')

        blocs_chiffres.append(bloc_chiffre_bytes)

    # 4. Écrire tous les blocs chiffrés dans le fichier de sortie
    with open(chemin_sortie, "wb") as f_out:
        for bloc_chiffre in blocs_chiffres:
            # Stocker la taille sur 2 octets (big-endian)
            size_bytes = len(bloc_chiffre).to_bytes(2, 'big')
            f_out.write(size_bytes)
            f_out.write(bloc_chiffre)

    print(f"Fichier chiffré par blocs : {chemin_sortie}")
    return chemin_sortie


def dechiffrer_fichier_par_blocs(chemin_fichier_chiffre, private_key, chemin_sortie=None):
    """
    Déchiffre un fichier .enc par blocs RSA (sans padding).
    Gère les cas où le fichier .enc n'existe pas ou n'a pas la bonne extension.
    """

    # Vérifier que le fichier .enc existe
    if not os.path.exists(chemin_fichier_chiffre):
        print("[ERREUR] Le fichier à déchiffrer n'existe pas ou le chemin est invalide.")
        return None

    # Vérifier l'extension .enc
    if not chemin_fichier_chiffre.lower().endswith(".enc"):
        print("[ERREUR] Le fichier fourni n'est pas un fichier .enc.")
        return None

    n, d = private_key

    # Déterminer le fichier d'origine (ex: "fichier_test.txt.enc" -> "fichier_test.txt")
    base_name, ext_enc = os.path.splitext(chemin_fichier_chiffre)  # ("fichier_test.txt", ".enc")
    original_ext = os.path.splitext(base_name)[1] 

    # Par défaut, on renomme en fonction de l'extension d'origine
    if chemin_sortie is None:
        if original_ext == ".txt":
            chemin_sortie = base_name + "_dechiffre.txt"
        else:
            chemin_sortie = base_name + "_dechiffre.bin"

    data_dechiffree = bytearray()

    with open(chemin_fichier_chiffre, "rb") as f_in:
        while True:
            # Lire la taille du bloc
            size_bytes = f_in.read(2)
            if not size_bytes:
                # plus de données, on sort
                break
            bloc_size = int.from_bytes(size_bytes, 'big')

            # Lire le bloc chiffré
            bloc_chiffre = f_in.read(bloc_size)
            if len(bloc_chiffre) < bloc_size:
                print("Fichier .enc corrompu (fin prématurée).")
                break

            # Convertir en entier
            bloc_chiffre_int = int.from_bytes(bloc_chiffre, 'big')

            # Déchiffrer
            bloc_dechiffre_int = pow(bloc_chiffre_int, d, n)

            # Repasser en bytes
            bloc_clair = bloc_dechiffre_int.to_bytes((n.bit_length() + 7) // 8, 'big')

            # Accumuler dans data_dechiffree
            data_dechiffree.extend(bloc_clair)

    with open(chemin_sortie, "wb") as f_out:
        f_out.write(data_dechiffree)

    print(f"Fichier déchiffré et reconstitué : {chemin_sortie}")
    return chemin_sortie


# --- GESTION DES CLÉS ---

def charger_cle_privee(chemin_cle_privee):
    """Charge une clé privée à partir d'un fichier (texte)."""
    with open(chemin_cle_privee, "r") as fichier:
        cle_privee = fichier.read().strip().split(",")
        return int(cle_privee[0]), int(cle_privee[1])

def charger_cle_publique(chemin_cle_publique):
    """Charge une clé publique à partir d'un fichier (texte)."""
    with open(chemin_cle_publique, "r") as fichier:
        cle_publique = fichier.read().strip().split(",")
        return int(cle_publique[0]), int(cle_publique[1])


# --- GESTION DU COFFRE ---

def ajouter_fichier_au_coffre(chemin_fichier, id_utilisateur):
    """
    Ajoute un fichier (chiffré) dans le répertoire coffre_fort/<id_utilisateur>.
    Gère la clé publique de l'utilisateur s'il existe.
    """

    chemin_cle_publique_utilisateur = f"coffre_fort/{id_utilisateur}/public_key.key"
    if not os.path.exists(chemin_cle_publique_utilisateur):
        print("La clé publique de l'utilisateur est introuvable.")
        return

    # Vérifier que le fichier à chiffrer existe
    if not os.path.exists(chemin_fichier):
        print("[ERREUR] Le fichier à chiffrer n'existe pas ou le chemin est invalide.")
        return

    public_key = charger_cle_publique(chemin_cle_publique_utilisateur)

    # -- On appelle le chiffrement par blocs
    fichier_chiffre = chiffrer_fichier_par_blocs(chemin_fichier, public_key)
    
    # Si chiffrer_fichier_par_blocs a retourné None, on arrête (le fichier était invalide)
    if fichier_chiffre is None:
        return

    # On place le .enc dans le répertoire de l'utilisateur
    chemin_destination = os.path.join("coffre_fort", id_utilisateur)
    if not os.path.exists(chemin_destination):
        os.makedirs(chemin_destination)

    fichier_final = os.path.join(chemin_destination, os.path.basename(fichier_chiffre))
    os.rename(fichier_chiffre, fichier_final)

    print(f"Fichier ajouté au coffre pour l'utilisateur '{id_utilisateur}': {fichier_final}")
