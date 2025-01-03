import os

# =========================
# 1) FONCTIONS DE PADDING
# =========================

def pkcs1_v1_5_pad(message: bytes, block_size: int) -> bytes:
    """
    Ajoute un padding PKCS#1 v1.5 pour le chiffrement RSA.
    Format : 0x00 | 0x02 | [octets aléatoires != 0] | 0x00 | message
    
    :param message: le bloc de données à chiffrer (bytes)
    :param block_size: taille en octets de la clé RSA (ex : 128 pour 1024 bits)
    :return: le bloc paddé de longueur block_size
    """
    # Vérifier la taille : message <= block_size - 11
    if len(message) > block_size - 11:
        raise ValueError("Le bloc à chiffrer est trop grand pour du PKCS#1 v1.5 (RSA).")

    # Nombre d'octets aléatoires non-nuls
    padding_len = block_size - len(message) - 3  # (3 = 0x00 + 0x02 + 0x00)
    random_bytes = bytearray()

    # Génération d'octets aléatoires non-nuls à l’aide d’os.urandom
    while len(random_bytes) < padding_len:
        rb = os.urandom(1)
        if rb != b'\x00':  # on écarte les octets nuls
            random_bytes.append(rb[0])

    # Construction du bloc final
    #  0x00 | 0x02 | random non-nuls | 0x00 | message
    return b"\x00\x02" + random_bytes + b"\x00" + message


def pkcs1_v1_5_unpad(padded_message: bytes) -> bytes:
    """
    Retire le padding PKCS#1 v1.5 d'un bloc déchiffré.
    On s'attend à : 0x00 | 0x02 | ...random non-nuls... | 0x00 | message

    :param padded_message: le bloc complet (déjà déchiffré)
    :return: le message original (bytes), sans le padding
    """
    if len(padded_message) < 11:
        raise ValueError("Bloc trop court pour du PKCS#1 v1.5.")

    # Les deux premiers octets doivent être 0x00, 0x02
    if padded_message[0] != 0x00 or padded_message[1] != 0x02:
        raise ValueError("En-tête PKCS#1 v1.5 invalide (pas 0x00, 0x02).")

    # On cherche l'octet 0x00 séparateur, après au moins 8 octets non-nuls
    # => index minimal = 2 + 8 = 10
    try:
        sep_index = padded_message.index(b"\x00", 2)
    except ValueError:
        raise ValueError("Pas de délimiteur 0x00 trouvé dans le bloc paddé (PKCS#1 v1.5).")

    if sep_index < 10:
        raise ValueError("Pas assez d'octets aléatoires dans le padding.")

    # Tout ce qui suit le 0x00 est le vrai message
    return padded_message[sep_index + 1:]


# =========================
# 2) CHIFFREMENT / DÉCHIFFREMENT RSA
# =========================

def chiffrer_fichier_par_blocs(chemin_fichier, public_key, chemin_sortie=None):
    """
    Chiffre un fichier par blocs, en appliquant le padding PKCS#1 v1.5
    puis la fonction RSA (pow(..., e, n)).
    """

    n, e = public_key
    # Taille de clé en octets (ex : 128 pour RSA 1024 bits)
    key_size = (n.bit_length() + 7) // 8
    # PKCS#1 v1.5 => On ne peut chiffrer que (key_size - 11) octets par bloc
    TAILLE_BLOC = key_size - 11

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

        # 3.1 Ajouter le padding PKCS#1 v1.5
        bloc_avec_padding = pkcs1_v1_5_pad(bloc, key_size)

        # 3.2 Convertir le bloc paddé en entier
        bloc_int = int.from_bytes(bloc_avec_padding, byteorder="big")

        # 3.3 Chiffrer (exponentiation modulaire)
        bloc_chiffre_int = pow(bloc_int, e, n)

        # 3.4 Convertir l'entier chiffré en octets (taille fixe = key_size)
        bloc_chiffre_bytes = bloc_chiffre_int.to_bytes(key_size, "big")

        blocs_chiffres.append(bloc_chiffre_bytes)

    # 4. Écrire tous les blocs chiffrés dans le fichier de sortie
    with open(chemin_sortie, "wb") as f_out:
        for bloc_chiffre in blocs_chiffres:
            # Stocker la taille sur 2 octets (big-endian)
            size_bytes = len(bloc_chiffre).to_bytes(2, "big")
            f_out.write(size_bytes)
            f_out.write(bloc_chiffre)

    print(f"[OK] Fichier chiffré par blocs (PKCS#1 v1.5) : {chemin_sortie}")
    return chemin_sortie


def dechiffrer_fichier_par_blocs(chemin_fichier_chiffre, private_key, chemin_sortie=None):
    # 1) Vérifier que le fichier existe
    if not os.path.exists(chemin_fichier_chiffre):
        print("[ERREUR] Le fichier à déchiffrer n'existe pas ou le chemin est invalide.")
        return

    # 2) Vérifier l'extension .enc
    if not chemin_fichier_chiffre.lower().endswith(".enc"):
        print("[ERREUR] Le fichier fourni n'est pas un fichier .enc.")
        return

    n, d = private_key
    key_size = (n.bit_length() + 7) // 8

    # Déterminer le fichier d'origine
    base_name, ext_enc = os.path.splitext(chemin_fichier_chiffre)
    original_ext = os.path.splitext(base_name)[1]

    if chemin_sortie is None:
        if original_ext == ".txt":
            chemin_sortie = base_name + "_dechiffre.txt"
        else:
            chemin_sortie = base_name + "_dechiffre.bin"

    data_dechiffree = bytearray()

    with open(chemin_fichier_chiffre, "rb") as f_in:
        while True:
            size_bytes = f_in.read(2)
            if not size_bytes:
                # plus de données => on sort
                break
            bloc_size = int.from_bytes(size_bytes, "big")

            bloc_chiffre = f_in.read(bloc_size)
            if len(bloc_chiffre) < bloc_size:
                print("[ERREUR] Fichier .enc corrompu (fin prématurée).")
                break

            bloc_chiffre_int = int.from_bytes(bloc_chiffre, "big")
            bloc_dechiffre_int = pow(bloc_chiffre_int, d, n)

            bloc_clair_padded = bloc_dechiffre_int.to_bytes(key_size, "big")
            try:
                bloc_clair = pkcs1_v1_5_unpad(bloc_clair_padded)
            except ValueError as e:
                print(f"[ERREUR] Padding invalide ou bloc corrompu : {e}")
                break

            data_dechiffree.extend(bloc_clair)

    with open(chemin_sortie, "wb") as f_out:
        f_out.write(data_dechiffree)

    print(f"[OK] Fichier déchiffré et reconstitué : {chemin_sortie}")
    return chemin_sortie



# =========================
# 3) GESTION DES CLÉS
# =========================

def charger_cle_privee(chemin_cle_privee):
    """
    Charge une clé privée (n, d) à partir d'un fichier texte.
    Le fichier doit contenir : "n,d" (sans guillemets).
    """
    with open(chemin_cle_privee, "r") as fichier:
        cle_privee = fichier.read().strip().split(",")
        return int(cle_privee[0]), int(cle_privee[1])


def charger_cle_publique(chemin_cle_publique):
    """
    Charge une clé publique (n, e) à partir d'un fichier texte.
    Le fichier doit contenir : "n,e" (sans guillemets).
    """
    with open(chemin_cle_publique, "r") as fichier:
        cle_publique = fichier.read().strip().split(",")
        return int(cle_publique[0]), int(cle_publique[1])


# =========================
# 4) GESTION DU "COFFRE"
# =========================

def ajouter_fichier_au_coffre(chemin_fichier, id_utilisateur):
    # Vérifier que le fichier existe
    if not os.path.exists(chemin_fichier):
        print("[ERREUR] Le fichier à chiffrer n'existe pas ou le chemin est invalide.")
        return

    chemin_cle_publique_utilisateur = f"coffre_fort/{id_utilisateur}/public_key.key"
    if not os.path.exists(chemin_cle_publique_utilisateur):
        print("[ERREUR] La clé publique de l'utilisateur est introuvable.")
        return

    public_key = charger_cle_publique(chemin_cle_publique_utilisateur)

    # -- On appelle le chiffrement par blocs
    fichier_chiffre = chiffrer_fichier_par_blocs(chemin_fichier, public_key)

    # On place le fichier .enc dans le répertoire de l'utilisateur
    chemin_destination = os.path.join("coffre_fort", id_utilisateur)
    if not os.path.exists(chemin_destination):
        os.makedirs(chemin_destination)

    fichier_final = os.path.join(chemin_destination, os.path.basename(fichier_chiffre))
    os.rename(fichier_chiffre, fichier_final)

    print(f"[OK] Fichier ajouté au coffre pour l'utilisateur '{id_utilisateur}': {fichier_final}")
