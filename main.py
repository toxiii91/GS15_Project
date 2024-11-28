from Guillou_Quisquater import ZKP
from generation_cle import creer_compte  

def menu_principal():
    """Affiche le menu principal du program"""
    while True:
        print("Bienvenue dans le coffre-fort numérique !")
        print("1. Créer un compte")
        print("2. Se connecter")
        print("3. Quitter")
        print("4. Vérifier une clé publique avec une preuve à divulgation nulle")
        choix = input("Choisissez une option : ")

        if choix == "1":
            creer_compte()
        elif choix == "2":
            print("Se connecter ...")
            """Ajout de la fonction de connection"""
        elif choix == "3":
            print('\n Au revoir ! \n')
            break
        elif choix == "4":
            print("Vous avez selectionne l'option 4 !")
            ZKP()
        else:
            print("Option invalide, veuillez réessayer.")

if __name__ == "__main__":
    menu_principal()