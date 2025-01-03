import os
from datetime import datetime

# Chemin vers le fichier de log
LOG_FILE_PATH = "./coffre_fort/config/log.txt"

def ecrire_log(nom_fonction, utilisateur, nom_fichier=None):
    """
    Écrit un message dans le fichier de log en fonction de l'opération effectuée.
    
    :param nom_fonction: Nom de la fonction qui a appelé le log.
    :param utilisateur: Nom de l'utilisateur concerné.
    :param nom_fichier: Nom du fichier, si applicable (par défaut, None).
    """
    # Dictionnaire des messages correspondant aux opérations
    messages = {
        "creer_utilisateur": f"Création de l'utilisateur {utilisateur}",
        "ajouter_cle_publique": f"Ajout de la clé publique de l'utilisateur {utilisateur} dans le coffre-fort",
        "ajouter_cle_privee": f"Ajout de la clé privée de l'utilisateur {utilisateur} dans son répertoire personnel",
        "connexion_utilisateur": f"Connexion de l'utilisateur {utilisateur}",
        "verifier_certificat": f"Vérification du certificat du coffre par l'utilisateur {utilisateur}",
        "zkp": f"ZKP entre l'utilisateur {utilisateur} et le coffre",
        "ajouter_cle_session_coffre": f"Ajout de la clé de session de l'utilisateur {utilisateur} dans le coffre-fort",
        "ajouter_cle_session_utilisateur": f"Ajout de la clé de session de l'utilisateur {utilisateur} dans son répertoire personnel",
        "supprimer_cle_session_coffre": f"Suppression de la clé de session de l'utilisateur {utilisateur} dans le coffre-fort",
        "supprimer_cle_session_utilisateur": f"Suppression de la clé de session de l'utilisateur {utilisateur} dans son répertoire personnel",
        "depot_fichier": f"Dépot du fichier \"{nom_fichier}\" de l'utilisateur {utilisateur}",
        "recuperation_fichier": f"Récupération du fichier \"{nom_fichier}\" de l'utilisateur {utilisateur}",
        "cobra_message": f"Utilisation de Cobra pour un simple message par utilisateur {utilisateur}",
        "chiffrement_cobra+rsa": f"Utilisationde COBRA et RSA pour chiffrer le fichier \"{nom_fichier}\" de l'utilisateur {utilisateur} dans le coffre",
        "dechiffrement_cobra+rsa": f"Utilisation de COBRA et RSA pour dechiffrer le fichier \"{nom_fichier}\" de l'utilisateur {utilisateur} dans le coffre"
    }

    # Récupération du message à partir du nom de la fonction
    message = messages.get(nom_fonction, f"Action inconnue pour l'utilisateur {utilisateur}")
    
    # Ajout de la date et heure au message
    date_heure = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message_complet = f"{message}, {date_heure}\n"
    
    # Création du dossier de log si nécessaire
    os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
    
    # Écriture dans le fichier de log
    try:
        with open(LOG_FILE_PATH, 'a', encoding='utf-8') as log_file:
            log_file.write(message_complet)
    except Exception as e:
        print(f"Erreur lors de l'écriture du log : {e}")


