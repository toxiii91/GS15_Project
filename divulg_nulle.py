import random

def preuve_divulgation_nulle_guillou_quisquater(public_key, private_key):
    """
    Implémente le protocole de Guillou-Quisquater basé sur RSA.
    :param public_key: Tuple (n, e) représentant la clé publique.
    :param private_key: Tuple (n, d) représentant la clé privée.
    """
    n, e = public_key
    _, d = private_key

    # Étape 1 : Nicolas choisit un message H à signer
    H = random.randint(2, n - 2)  # H choisi dans [2, n-2]
    print(f"Message H choisi : {H}")

    # Calcul de la signature S = H^e mod n
    S = pow(H, e, n)
    print(f"Signature calculée S : {S}")

    # Nicolas choisit m aléatoire et calcule M
    m = random.randint(2, n - 2)  # m choisi dans [2, n-2]
    alpha = random.randint(2, n - 2)  # Générateur aléatoire
    M = pow(alpha, m, n)  # M = alpha^m mod n
    print(f"Valeur calculée M : {M}")

    # Rémi génère un challenge r
    r = random.randint(1, e - 1)  # r < e
    print(f"Challenge r choisi par Rémi : {r}")

    # Nicolas calcule la preuve
    try:
        H_r_inverse = pow(pow(H, r, n), -1, n)  # H^-r mod n
    except ValueError:
        print("Erreur : Impossible de calculer l'inverse modulaire.")
        return

    Preuve = (m * H_r_inverse) % n  # Preuve = m * H^-r mod n
    print(f"Preuve calculée : {Preuve}")

    # Rémi vérifie la preuve
    Sr = pow(S, r, n)  # S^r mod n
    Preuve_e = pow(Preuve, e, n)  # Preuve^e mod n
    M_verifie = (Sr * Preuve_e) % n  # Vérification finale
    print(f"Valeur vérifiée M : {M_verifie}")

    is_valid = (M_verifie == M)
    print(f"Résultat de la vérification : {'Succès' if is_valid else 'Échec'}")
    return is_valid


# Exemple d'utilisation
def exemple_utilisation():
    # Génération de clés simplifiées pour l'exemple
    p = 61  # Exemple de petit nombre premier
    q = 53  # Exemple de petit nombre premier
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17  # Exposant public
    d = pow(e, -1, phi)  # Exposant privé (inverse modulaire de e)

    public_key = (n, e)
    private_key = (n, d)

    print("Clé publique :", public_key)
    print("Clé privée :", private_key)

    # Lancer le protocole
    preuve_divulgation_nulle_guillou_quisquater(public_key, private_key)

# Tester l'exemple
exemple_utilisation()
