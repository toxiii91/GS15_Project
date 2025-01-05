import os
import time


def coffre_generer_certificat(cle_pub_coffre):
    """
    Génère un certificat principal pour le coffre-fort.
    """
    nom_coffre = "CoffreFort"
    date_expiration = int(time.time()) + (365 * 24 * 60 * 60)  # Expire dans un an

    # Contenu à signer
    contenu_certificat = f"{nom_coffre}{cle_pub_coffre}{date_expiration}"
    signature = sum(ord(c) for c in contenu_certificat)  # Simulation de signature

    # Certificat principal
    certificat = {
        "nom": nom_coffre,
        "cle_publique": cle_pub_coffre,
        "date_expiration": date_expiration,
        "signature": signature
    }

    # Enregistrer le certificat principal dans le coffre
    with open("coffre_fort/Config/coffre_certificat.txt", "w") as fichier:
        for cle, valeur in certificat.items():
            fichier.write(f"{cle}:{valeur}\n")

    print("Certificat principal généré pour le coffre-fort.")
    return certificat


def utilisateur_generer_certificat(username):
    """
    Génère un certificat pour un utilisateur spécifique en récupérant la clé publique depuis /coffre_fort/<utilisateur>/public_key.key.
    """
    # Chemin vers le certificat principal du coffre
    if not os.path.exists("coffre_fort/Config/coffre_certificat.txt"):
        print("Erreur : Certificat principal non trouvé dans le coffre.")
        return

    # Charger le certificat principal
    with open("coffre_fort/Config/coffre_certificat.txt", "r") as fichier:
        lignes = fichier.readlines()

    certificat_coffre = {}
    for ligne in lignes:
        cle, valeur = ligne.strip().split(":")
        certificat_coffre[cle] = int(valeur) if valeur.isdigit() else valeur

    # Chemin vers la clé publique de l'utilisateur
    public_key_path = f"coffre_fort/{username}/public_key.key"
    if not os.path.exists(public_key_path):
        print(f"Erreur : Clé publique introuvable pour l'utilisateur '{username}'.")
        return

    # Charger la clé publique
    with open(public_key_path, "r") as fichier:
        public_key = fichier.read().strip()
        cle_pub_user = public_key.split(",")[0]  # Extraire la première partie de la clé publique (n)

    # Générer le certificat utilisateur
    contenu_certificat_user = f"{username}{cle_pub_user}{certificat_coffre['date_expiration']}"
    signature_user = sum(ord(c) for c in contenu_certificat_user)  # Simulation de signature

    certificat_user = {
        "nom": username,
        "cle_publique": cle_pub_user,
        "date_expiration": certificat_coffre['date_expiration'],
        "signature": signature_user
    }

    # Enregistrer le certificat utilisateur dans son répertoire personnel
    user_cert_path = f"users/{username}/certificat.txt"
    os.makedirs(os.path.dirname(user_cert_path), exist_ok=True)
    with open(user_cert_path, "w") as fichier:
        for cle, valeur in certificat_user.items():
            fichier.write(f"{cle}:{valeur}\n")

    print(f"Certificat généré et stocké pour l'utilisateur '{username}'.")
    return certificat_user



def utilisateur_verifier_certificat(username):
    """
    Vérifie l'intégrité et la validité du certificat utilisateur.
    """
    user_cert_path = f"users/{username}/certificat.txt"
    if not os.path.exists(user_cert_path):
        print(f"Erreur : Certificat non trouvé pour l'utilisateur {username}.")
        return False

    # Charger le certificat utilisateur
    with open(user_cert_path, "r") as fichier:
        lignes = fichier.readlines()

    certificat_user = {}
    for ligne in lignes:
        cle, valeur = ligne.strip().split(":")
        certificat_user[cle] = int(valeur) if valeur.isdigit() else valeur

    # Vérification de l'intégrité
    contenu_certificat = f"{certificat_user['nom']}{certificat_user['cle_publique']}{certificat_user['date_expiration']}"
    signature_attendue = sum(ord(c) for c in contenu_certificat)

    if certificat_user["signature"] != signature_attendue:
        print("Certificat invalide : signature incorrecte.")
        return False

    # Vérification de la date d'expiration
    if time.time() > certificat_user["date_expiration"]:
        print("Certificat invalide : certificat expiré.")
        return False

    print(f"Certificat valide pour l'utilisateur {username}.")
    return True


# Exemple d'intégration
def creer_compte(username, cle_pub_user, cle_pub_coffre):
    """
    Création d'un compte utilisateur avec génération de certificat utilisateur.
    """
    # Générer le certificat principal si nécessaire
    if not os.path.exists("coffre_fort/Config/coffre_certificat.txt"):
        coffre_generer_certificat(cle_pub_coffre)

    # Générer et stocker le certificat pour l'utilisateur
    utilisateur_generer_certificat(username, cle_pub_user)

