from Guillou_Quisquater import ZKP
from generation_cle import creer_compte
from Diffie_Hellman import diffie_hellman
from test_cobra import cobra_encrypt_message, cobra_decrypt_message, generate_keys
from test_Merkle import custom_hash, hmac
import os

def ZKP(username):
    """Validation par preuve à divulgation nulle pour la connexion d'un utilisateur"""
    try:
        private_key_path = f"users/{username}/private_key.key"

        # Vérifier si le fichier de clé privée existe
        if not os.path.exists(private_key_path):
            print(f"Erreur : Le fichier de la clé privée est introuvable dans {private_key_path}.")
            return False

        # Charger et vérifier la clé privée
        with open(private_key_path, "r") as key_file:
            private_key = key_file.read()

        if not private_key.strip():  # Vérifier que la clé n'est pas vide
            print("Erreur : La clé privée est vide ou invalide.")
            return False

        print("Clé privée chargée avec succès.")
        return True

    except Exception as e:
        print(f"Erreur : Impossible de charger les clés. Détails : {e}")
        return False

def menu_principal():
    """Affiche le menu principal du programme"""
    while True:
        print("\nBienvenue dans le coffre-fort numérique !")
        print("1. Créer un compte")
        print("2. Se connecter")
        print("3. Quitter")

        choix = input("Choisissez une option : ")

        if choix == "1":
            creer_compte()
        elif choix == "2":
            username = input("Entrez votre nom d'utilisateur : ")
            if ZKP(username):
                print(f"Connexion réussie, bienvenue {username} !")
                menu_utilisateur(username)  # Redirige vers le menu utilisateur
            else:
                print("Connexion échouée. Veuillez réessayer.")
        elif choix == "3":
            print("Au revoir !")
            break
        else:
            print("Option invalide, veuillez réessayer.")

def menu_utilisateur(username):
    """Affiche le menu utilisateur après connexion réussie"""
    while True:
        print(f"\nQue voulez-vous faire, {username} ?")
        print("1. Chiffrer un fichier ou un message")
        print("2. Déchiffrer un fichier ou un message")
        print("3. Supprimer un fichier")
        print("4. Afficher les hachages des fichiers")
        print("5. Calculer un HMAC pour un message")
        print("6. Établir une clé de session avec le coffre (Diffie-Hellman)")
        print("7. Déconnexion")

        choix = input("Choisissez une option : ")

        if choix == "1":
            chiffrement_interface()
        elif choix == "2":
            dechiffrement_interface()
        elif choix == "3":
            retirer_fichier()
        elif choix == "4":
            afficher_hachages()
        elif choix == "5":
            calculer_hmac()
        elif choix == "6":
            diffie_hellman(username)
        elif choix == "7":
            print(f"Déconnexion réussie. À bientôt, {username} !")
            break
        else:
            print("Option invalide, veuillez réessayer.")

def chiffrement_interface():
    cle_initiale_dh = input("Entrez une clé initiale Diffie-Hellman (binaire) : ")
    round_keys = generate_keys(cle_initiale_dh)

    choix = input("Voulez-vous chiffrer un message ou un fichier ? (message/fichier) : ").strip().lower()
    if choix == "message":
        message = input("Entrez votre message : ")
        encrypted = cobra_encrypt_message(message, round_keys)
        print("Message chiffré (hexadécimal) :", encrypted.hex())
    elif choix == "fichier":
        chemin_fichier = input("Entrez le chemin du fichier : ").strip()
        try:
            with open(chemin_fichier, 'r', encoding='utf-8') as fichier:
                contenu = fichier.read()
                encrypted = cobra_encrypt_message(contenu, round_keys)
                with open(chemin_fichier + ".enc", 'wb') as fichier_chiffre:
                    fichier_chiffre.write(encrypted)
                print(f"Fichier chiffré enregistré sous : {chemin_fichier}.enc")
        except Exception as e:
            print("Erreur lors du chiffrement :", e)
    else:
        print("Choix invalide.")

def dechiffrement_interface():
    cle_initiale_dh = input("Entrez une clé initiale Diffie-Hellman (binaire) : ")
    round_keys = generate_keys(cle_initiale_dh)

    choix = input("Voulez-vous déchiffrer un message ou un fichier ? (message/fichier) : ").strip().lower()
    if choix == "message":
        encrypted_hex = input("Entrez le message chiffré (hexadécimal) : ")
        try:
            encrypted = bytes.fromhex(encrypted_hex)
            decrypted = cobra_decrypt_message(encrypted, round_keys)
            print("Message déchiffré :", decrypted)
        except Exception as e:
            print("Erreur lors du déchiffrement :", e)
    elif choix == "fichier":
        chemin_fichier = input("Entrez le chemin du fichier chiffré : ").strip()
        try:
            with open(chemin_fichier, 'rb') as fichier_chiffre:
                encrypted = fichier_chiffre.read()
                decrypted = cobra_decrypt_message(encrypted, round_keys)
                with open(chemin_fichier.replace(".enc", ""), 'w', encoding='utf-8') as fichier_dechiffre:
                    fichier_dechiffre.write(decrypted)
                print(f"Fichier déchiffré enregistré sous : {chemin_fichier.replace('.enc', '')}")
        except Exception as e:
            print("Erreur lors du déchiffrement :", e)
    else:
        print("Choix invalide.")

def retirer_fichier():
    chemin_fichier = input("Entrez le chemin du fichier à supprimer : ")
    try:
        os.remove(chemin_fichier)
        print(f"Fichier supprimé : {chemin_fichier}")
    except FileNotFoundError:
        print("Fichier introuvable.")
    except Exception as e:
        print("Erreur lors de la suppression :", e)

def afficher_hachages():
    dossier = "coffre_fort"
    for root, dirs, files in os.walk(dossier):
        for file in files:
            chemin_fichier = os.path.join(root, file)
            hash_valeur = hash_fichier(chemin_fichier)
            print(f"Fichier : {file} | Hash : {hash_valeur}")

def hash_fichier(filepath):
    """Calcule le hash personnalisé d'un fichier"""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        return custom_hash(data).hex()
    except Exception as e:
        print("Erreur lors du calcul du hash :", e)
        return None

def calculer_hmac():
    key = input("Entrez la clé secrète : ").encode('utf-8')
    message = input("Entrez le message : ").encode('utf-8')
    hmac_result = hmac(key, message)
    print(f"HMAC : {hmac_result.hex()}")

if __name__ == "__main__":
    menu_principal()
