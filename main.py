from Guillou_Quisquater import ZKP
from generation_cle import creer_compte  
from Diffie_Hellman import diffie_hellman
from certificat_coffre import utilisateur_verifier_certificat
import rsa_avec_padding
import test_cobra
from log import ecrire_log

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
                ecrire_log("verifier_certificat", username) 
                print("Certificat valide. Vérification ZKP en cours...")
                connexion = ZKP(username)
                if connexion:
                    while True:
                        print("Connexion réussie, que voulez-vous faire maintenant ?")
                        print("1. Créer une clé de session avec le coffre")
                        print("2. Chiffrer un fichier avec RSA et l'ajouter au coffre")
                        print("3. Déchiffrer un fichier RSA du coffre")
                        print("4. Quitter")
                        choix = input("Choisissez une option : ")
                        if choix == "1":
                            diffie_hellman(username)
                        elif choix == "2":
                                # On te demande le fichier à chiffrer
                            chemin_fichier = input("Entrez le chemin du fichier à chiffrer/ajouter (Cobra+RSA) : ")

                            # 1) On chiffre d'abord avec Cobra (en supposant que tu as round_keys quelque part)
                            cle_initiale_dh = "11011010101101001010101101101010101010101010101010101010101010101111"
                            round_keys =  test_cobra.generate_keys(cle_initiale_dh)

                            fichier_cobra =  test_cobra.cobra_encrypt_file(chemin_fichier, round_keys)
                            if not fichier_cobra:
                                print("[ERREUR] Échec du chiffrement Cobra.")
                                continue

                            # 2) Puis on chiffre ce fichier Cobra avec RSA pour l'ajouter au coffre
                            rsa_avec_padding.ajouter_fichier_au_coffre(fichier_cobra, username)
                            ecrire_log("chiffrement_cobra+rsa",username)
                        elif choix == "3":
                             # Fichier RSA
                            chemin_fichier_chiffre = input("Entrez le chemin du fichier chiffré en RSA (.enc) : ")
                            chemin_cle_privee = f"users/{username}/private_key.key"
                            private_key = rsa_avec_padding.charger_cle_privee(chemin_cle_privee)

                            # 1) Déchiffrer RSA => donne un fichier .cobra
                            fichier_cobra_dechiffre = rsa_avec_padding.dechiffrer_fichier_par_blocs(chemin_fichier_chiffre, private_key)
                            if not fichier_cobra_dechiffre:
                                print("[ERREUR] Le déchiffrement RSA a échoué.")
                                continue

                            # 2) Déchiffrer Cobra => donne le fichier final en clair
                            cle_initiale_dh = "11011010101101001010101101101010101010101010101010101010101010101111"
                            round_keys = test_cobra.generate_keys(cle_initiale_dh)

                            fichier_final = test_cobra.cobra_decrypt_file(fichier_cobra_dechiffre, round_keys)
                            ecrire_log("dechiffrement_rsa+cobrz",username)
                            if fichier_final is None:
                                print("[ERREUR] Le déchiffrement Cobra a échoué.")
                            else:
                                print(f"[OK] Fichier final reconstitué : {fichier_final}")
                        elif choix == "4":
                            print("Déconnexion...")
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