import random
import os
from cobra import message_encryption
from log import ecrire_log

def diffie_hellman(username):
    # Le client et le coffre fort se mettent d'accord sur deux paramètres publiques p (un très grand nombre premier) et
    # g (un générateur appartenant à Zp premier), g<p et sont transmis en clair
    # Voir les recommandations RFC3526
    hexa = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
    )
    p = int(hexa, 16)  # hexa to dec
    g = 2
    User(p, g, username)
    print("La connexion est établie. La clé de session est créee !")
    ecrire_log("connexion_utilisateur", username)
    print("Que souhaitez-vous faire maintenant : ")

    while True:
        print("1. Retourner au menu principal")
        print("2. Utiliser Cobra pour chiffrer")
        choix = input("Choisissez une option : ")

        if choix == "1":
            chemin_user = os.path.join("users", username)
            chemin_cle_session_user = os.path.join(chemin_user, "keya.key")
            chemin_coffre = os.path.join("coffre_fort", username)
            chemin_cle_session_coffre = os.path.join(chemin_coffre, "keyb.key")
            print('\n Au revoir ! \n')
            # supprimer les clés
            try:
                # Vérifie si le fichier existe
                if os.path.exists(chemin_cle_session_user):
                    os.remove(chemin_cle_session_user)  # Supprime le fichier
                    print(f"Fichier supprimé avec succès : {chemin_cle_session_user}")
                    ecrire_log("supprimer_cle_session_utilisateur", username)
                    # Ajout du log
                else:
                    print(f"Le fichier n'existe pas : {chemin_cle_session_user}")
            except Exception as e:
                print(f"Erreur lors de la suppression du fichier : {e}")

            try:
                # Vérifie si le fichier existe
                if os.path.exists(chemin_cle_session_coffre):
                    os.remove(chemin_cle_session_coffre)  # Supprime le fichier
                    ecrire_log("supprimer_cle_session_coffre", username)

                    print(f"Fichier supprimé avec succès : {chemin_cle_session_coffre}")
                    # Ajout du log
                else:
                    print(f"Le fichier n'existe pas : {chemin_cle_session_coffre}")
            except Exception as e:
                print(f"Erreur lors de la suppression du fichier : {e}")
            break
        elif choix == "2":
            message_encryption(username)            
        else:
            print("Option invalide, veuillez réessayer.")

def User(p, g, username):
    """
    Génère la clé secrète côté utilisateur et la stocke dans 'coffre_fort/<username>'.
    """
    # Clés privées aléatoires de l'utilisateur
    a = random.randint(2, p - 1)
    A = pow(g, a, p)

    # Envoie de A à Coffre, et on reçoit B
    B = Coffre(p, g, A, username)

    # Reçoit B, on peut alors calculer la clé secrète ka
    ka = pow(B, a, p)

    # Réduction de la clé à 256 bits
    ka_binary = bin(ka)[2:]  # Convertir en binaire sans le préfixe '0b'
    ka_256_bit = ka_binary[:256]  # Garder seulement les 256 premiers bits
    ka_final = int(ka_256_bit, 2)  # Reconversion en entier

    chemin_dossier = os.path.join("users", username)

    # Sauvegarder la clé dans le fichier dans le repertoire de l'user côté client
    chemin_fichier = os.path.join(chemin_dossier, "keya.key")
    with open(chemin_fichier, "w") as f:
        f.write(f"{ka_final}\n")
    ecrire_log("ajouter_cle_session_utilisateur", username)



def Coffre(p, g, A, username):
    """
    Génère la clé secrète côté coffre et la stocke dans 'users/<username>'.
    """
    # Clés privées aléatoires du coffre
    b = random.randint(2, p - 1)
    B = pow(g, b, p)

    # Reçoit A, on peut alors calculer la clé secrète kb
    kb = pow(A, b, p)

    # Réduction de la clé à 256 bits
    kb_binary = bin(kb)[2:]  # Convertir en binaire sans le préfixe '0b'
    kb_256_bit = kb_binary[:256]  # Garder seulement les 256 premiers bits
    kb_final = int(kb_256_bit, 2)  # Reconversion en entier

    chemin_dossier = os.path.join("coffre_fort", username)

    # Sauvegarder la clé dans le fichier
    chemin_fichier = os.path.join(chemin_dossier, "keyb.key")
    with open(chemin_fichier, "w") as f:
        f.write(f"{kb_final}\n")
    ecrire_log("ajouter_cle_session_coffre", username)

    return B

