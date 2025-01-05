import os
from Guillou_Quisquater import ZKP 
from generation_cle import creer_compte  
from Diffie_Hellman import diffie_hellman
from certificat_coffre import utilisateur_verifier_certificat
import rsa_avec_padding
import cobra
from log import ecrire_log


def menu_principal():
    """Affiche le menu principal du programme"""
    while True:
        print("\nBienvenue dans le coffre-fort numérique !")
        print("1. Créer un compte")
        print("2. Se connecter")
        print("3. Quitter")
        choix = input("Choisissez une option : ").strip()

        if choix == "1":
            creer_compte()
        elif choix == "2":
            username = input("Entrer votre nom d'utilisateur : ").strip()
            # Vérification du certificat avant ZKP
            if utilisateur_verifier_certificat(username):
                ecrire_log("verifier_certificat", username)
                print("Certificat valide. Vérification ZKP en cours...")
                connexion = ZKP(username)
                ecrire_log("zkp", username)
                if connexion:
                    while True:
                        print("Connexion réussie, Que voulez vous faire maintenant")
                        print("1. Créer une clé de session avec le coffre")
                        print("2. Quitter")
                        choix = input("Choisissez une option : ")
                        if choix == "1":
                            diffie_hellman(username)
                        elif choix == "2":
                            break
                else:
                    print("Option invalide, veuillez réessayer.")

        elif choix == "3":
            print('\nAu revoir !\n')
            break
        else:
            print("Option invalide, veuillez réessayer.")

if __name__ == "__main__":
    menu_principal()
