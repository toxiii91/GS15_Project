from Guillou_Quisquater import ZKP
from generation_cle import creer_compte  
from Diffie_Hellman import diffie_hellman
from certificat_coffre import utilisateur_verifier_certificat

def menu_principal():
    """Affiche le menu principal du program"""
    while True:
        print("Bienvenue dans le coffre-fort numérique !")
        print("1. Créer un compte")
        print("2. Se connecter")
        print("3. Quitter")
        print("4. Vérifier une clé publique avec une preuve à divulgation nulle")
        print("5. Etablir une connection avec le coffre (DH)")
        choix = input("Choisissez une option : ")

        if choix == "1":
            creer_compte()
        elif choix == "2":
            username = input("Entrez votre nom d'utilisateur : ")

            # Vérification du certificat avant ZKP
            if utilisateur_verifier_certificat(username):
                print("Certificat valide. Vérification ZKP en cours...")
                connexion = ZKP(username)
                if connexion:
                    while True:
                        print("Connexion réussie, que voulez-vous faire maintenant ?")
                        print("1. Créer une clé de session avec le coffre")
                        print("2. Quitter")
                        choix = input("Choisissez une option : ")
                        if choix == "1":
                            diffie_hellman(username)
                        elif choix == "2":
                            break
                        else:
                            print("Option invalide, veuillez réessayer.")
                else:
                    print("Connexion échouée (échec ZKP).")
            else:
                print("Connexion échouée (certificat invalide).")

        elif choix == "3":
            print('\nAu revoir !\n')
            break
        elif choix == "4":
            print("Vous avez sélectionné l'option 4 !")
            ZKP()
        elif choix == "5":
            print("Vous avez sélectionné l'option 5 !")
            diffie_hellman()
        else:
            print("Option invalide, veuillez réessayer.")


if __name__ == "__main__":
    menu_principal()