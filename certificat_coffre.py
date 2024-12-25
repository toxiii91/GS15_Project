import os
import time

def coffre_generer_certificat(cle_pub_coffre):
    """
    Génère un certificat pour le coffre-fort.
    """
    nom_coffre = "CoffreFort"
    date_expiration = int(time.time()) + (365 * 24 * 60 * 60)  # Expire dans un an

    # Contenu à signer
    contenu_certificat = f"{nom_coffre}{cle_pub_coffre}{date_expiration}"
    signature = sum(ord(c) for c in contenu_certificat)  # Simulation de signature

    # Certificat
    certificat = {
        "nom": nom_coffre,
        "cle_publique": cle_pub_coffre,
        "date_expiration": date_expiration,
        "signature": signature
    }

    # Enregistrer dans un fichier simulé
    with open("coffre_certificat.txt", "w") as fichier:
        for cle, valeur in certificat.items():
            fichier.write(f"{cle}:{valeur}\n")

    print("Certificat généré et transmis à l'utilisateur.")
    return certificat


# Étape 2 : Récupération et stockage côté utilisateur
def utilisateur_recevoir_certificat():
    """
    Récupère et enregistre le certificat reçu du coffre-fort.
    """
    if not os.path.exists("coffre_certificat.txt"):
        print("Erreur : Certificat non trouvé chez le coffre.")
        return

    with open("coffre_certificat.txt", "r") as fichier:
        certificat = fichier.read()

    # Stocker dans l'espace utilisateur
    with open("utilisateur_certificat.txt", "w") as fichier:
        fichier.write(certificat)

    print("Certificat stocké côté utilisateur.")

# Étape 3 : Vérification du certificat côté utilisateur
def utilisateur_verifier_certificat():
    """
    Vérifie l'intégrité et la validité du certificat stocké.
    """
    if not os.path.exists("utilisateur_certificat.txt"):
        print("Erreur : Certificat non trouvé chez l'utilisateur.")
        return False

    # Charger le certificat
    with open("utilisateur_certificat.txt", "r") as fichier:
        lignes = fichier.readlines()

    certificat = {}
    for ligne in lignes:
        cle, valeur = ligne.strip().split(":")
        certificat[cle] = int(valeur) if valeur.isdigit() else valeur

    # Vérification de l'intégrité
    contenu_certificat = f"{certificat['nom']}{certificat['cle_publique']}{certificat['date_expiration']}"
    signature_attendue = sum(ord(c) for c in contenu_certificat)

    if certificat["signature"] != signature_attendue:
        print("Certificat invalide : signature incorrecte.")
        return False

    # Vérification de la date d'expiration
    if time.time() > certificat["date_expiration"]:
        print("Certificat invalide : certificat expiré.")
        return False

    print("Certificat valide.")
    return True

# Étape 4 : Validation côté coffre-fort
def coffre_valider_requete(cle_pub_coffre, contenu_a_verifier, signature_a_verifier):
    """
    Simule la validation d'une requête signée côté coffre-fort.
    """
    signature_calculée = sum(ord(c) for c in contenu_a_verifier)
    if signature_calculée != signature_a_verifier:
        print("Validation échouée : signature invalide.")
        return False

    print("Requête validée avec succès.")
    return True


# Utilisation : 
cle_pub_coffre = 98765432109876543210  # Exemple de clé publique du coffre

# Étape 1 : Le coffre génère le certificat
coffre_generer_certificat(cle_pub_coffre)

# Étape 2 : L'utilisateur récupère et stocke le certificat
utilisateur_recevoir_certificat()

# Étape 3 : L'utilisateur vérifie le certificat
if utilisateur_verifier_certificat():
    # Étape 4 : Simulation de validation d'une requête côté coffre
    contenu = "Données de l'utilisateur"
    signature = sum(ord(c) for c in contenu)  # Simulation de signature
    coffre_valider_requete(cle_pub_coffre, contenu, signature)

