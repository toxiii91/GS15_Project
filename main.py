import os
from Guillou_Quisquater import ZKP 
from generation_cle import creer_compte  
from Diffie_Hellman import diffie_hellman
from certificat_coffre import utilisateur_verifier_certificat
import rsa_avec_padding
import test_cobra
from log import ecrire_log

def menu_principal():
    """Affiche le menu principal du programme"""
    while True:
        print("\nBienvenue dans le coffre-fort numérique !")
        print("1. Créer un compte")
        print("2. Se connecter")
        print("3. Quitter")
        print("4. Vérifier une clé publique avec une preuve à divulgation nulle")
        print("5. Etablir une connection avec le coffre (DH)")
        choix = input("Choisissez une option : ").strip()

        if choix == "1":
            creer_compte()
        elif choix == "2":
            username = input("Entrer votre nom d'utilisateur : ").strip()
            # Vérification du certificat avant ZKP
            if utilisateur_verifier_certificat(username):
                ecrire_log("verifier_certificat", username)
                print("Certificat valide. Vérification ZKP en cours...")
                ecrire_log("verifier_certificat", username)
                connexion = ZKP(username)
                ecrire_log("zkp", username)
                if connexion:
                    while True:
                        print("\nConnexion réussie, que voulez-vous faire maintenant ?")
                        print("1. Créer une clé de session avec le coffre")
                        print("2. Chiffrer un fichier avec Cobra et RSA et l'ajouter au coffre")
                        print("3. Déchiffrer un fichier Cobra et RSA du coffre")
                        print("4. Quitter")
                        choix = input("Choisissez une option : ").strip()
                        
                        if choix == "1":
                            diffie_hellman(username)
                        
                        elif choix == "2":
                            # Option de Chiffrement
                            # Répertoire contenant les fichiers à chiffrer
                            chemin_fichier_base = os.path.join("users", username)
                            
                            # Demander le nom du fichier à chiffrer
                            nom_fichier = input("Entrez le nom du fichier à chiffrer/ajouter (Cobra+RSA) : ").strip()
                            
                            # Chemin complet du fichier à chiffrer
                            chemin_complet = os.path.join(chemin_fichier_base, nom_fichier)
                            
                            # Vérifier si le fichier existe
                            if not os.path.exists(chemin_complet):
                                print("[ERREUR] Le fichier à chiffrer n'existe pas ou le chemin est invalide.")
                                ecrire_log("erreur_fichier_inexistant", username, nom_fichier)
                                continue
                            
                            # Définir le nom et le chemin du fichier chiffré
                            nom_fichier_cobra_enc = f"{nom_fichier}.cobra.enc"
                            chemin_fichier_cobra_enc = os.path.join("coffre_fort", username, nom_fichier_cobra_enc)
                            
                            # Vérifier si le fichier chiffré existe déjà
                            if os.path.exists(chemin_fichier_cobra_enc):
                                print(f"[ERREUR] Le fichier '{nom_fichier_cobra_enc}' est déjà chiffré.")
                                ecrire_log("erreur_fichier_deja_chiffre", username, nom_fichier_cobra_enc)
                                continue
                            
                            # 1) Chiffrer avec Cobra
                            cle_initiale_dh = "11011010101101001010101101101010101010101010101010101010101010101111"
                            round_keys = test_cobra.generate_keys(cle_initiale_dh)
            
                            fichier_cobra = test_cobra.cobra_encrypt_file(chemin_complet, round_keys)
                            if not fichier_cobra:
                                print("[ERREUR] Échec du chiffrement Cobra.")
                                ecrire_log("erreur_chiffrement_cobra", username, nom_fichier)
                                continue
            
                            # 2) Chiffrer avec RSA et ajouter au coffre
                            rsa_avec_padding.ajouter_fichier_au_coffre(fichier_cobra, username)
                            ecrire_log("chiffrement_cobra+rsa", username, nom_fichier_cobra_enc)
                            print(f"[OK] Fichier chiffré et ajouté au coffre : {nom_fichier_cobra_enc}")
                            
                            # 3) Supprimer le fichier intermédiaire .cobra
                            try:
                                os.remove(fichier_cobra)
                                ecrire_log("suppression_fichier_cobra", username, fichier_cobra)
                            except Exception as e:
                                print(f"[ERREUR] Impossible de supprimer le fichier intermédiaire '{fichier_cobra}' : {e}")
                                ecrire_log("erreur_suppression_fichier_cobra", username, fichier_cobra)
                        
                        elif choix == "3":
                            # Option de Déchiffrement
                            # Répertoire contenant les fichiers chiffrés
                            chemin_fichier_base = os.path.join("coffre_fort", username)
                            
                            # Demander le nom du fichier chiffré
                            nom_fichier_enc = input("Entrez le nom du fichier chiffré en RSA (.enc) : ").strip()
                            
                            # Chemin complet du fichier chiffré
                            chemin_fichier_chiffre = os.path.join(chemin_fichier_base, nom_fichier_enc)
            
                            print(f"Chemin complet du fichier à déchiffrer : {chemin_fichier_chiffre}")
            
                            # Vérifier si le fichier chiffré existe
                            if not os.path.exists(chemin_fichier_chiffre):
                                print("[ERREUR] Le fichier à déchiffrer n'existe pas ou le chemin est invalide.")
                                ecrire_log("erreur_fichier_dechiffrement_inexistant", username, nom_fichier_enc)
                                continue
            
                            # Chemin de la clé privée
                            chemin_cle_privee = os.path.join("users", username, "private_key.key")
            
                            # Vérifier si la clé privée existe
                            if not os.path.exists(chemin_cle_privee):
                                print("[ERREUR] La clé privée est introuvable.")
                                ecrire_log("erreur_cle_privee_manquante", username)
                                continue
            
                            # Charger la clé privée
                            private_key = rsa_avec_padding.charger_cle_privee(chemin_cle_privee)
            
                            # 1) Déchiffrer RSA => donne un fichier .cobra
                            fichier_cobra_dechiffre = rsa_avec_padding.dechiffrer_fichier_par_blocs(chemin_fichier_chiffre, private_key)
                            if not fichier_cobra_dechiffre:
                                print("[ERREUR] Le déchiffrement RSA a échoué.")
                                ecrire_log("erreur_dechiffrement_rsa", username, nom_fichier_enc)
                                continue
            
                            # 2) Déchiffrer Cobra => donne le fichier final en clair avec l'extension restaurée
                            cle_initiale_dh = "11011010101101001010101101101010101010101010101010101010101010101111"
                            round_keys = test_cobra.generate_keys(cle_initiale_dh)
            
                            fichier_final = test_cobra.cobra_decrypt_file(fichier_cobra_dechiffre, round_keys)
                            ecrire_log("dechiffrement_cobra+rsa", username, nom_fichier_enc)
                            if fichier_final is None:
                                print("[ERREUR] Le déchiffrement Cobra a échoué.")
                                ecrire_log("erreur_dechiffrement_cobra", username, nom_fichier_enc)
                            else:
                                # Chemin du fichier déchiffré dans /users/{username}/
                                chemin_fichier_final = os.path.join("users", username, nom_fichier)
                                
                                # Vérifier si le fichier déchiffré existe déjà
                                if os.path.exists(chemin_fichier_final):
                                    print(f"[ERREUR] Le fichier '{chemin_fichier_final}' est déjà déchiffré.")
                                    ecrire_log("erreur_fichier_deja_dechiffre", username, chemin_fichier_final)
                                else:
                                    # Renommer le fichier déchiffré en le plaçant directement dans users/{username}/
                                    try:
                                        # Supposons que 'fichier_final' est le chemin du fichier déchiffré
                                        # Déplace et renomme le fichier directement dans users/{username}/
                                        os.rename(fichier_final, chemin_fichier_final)
                                        print(f"[OK] Fichier final reconstitué : {chemin_fichier_final}")
                                        ecrire_log("dechiffrement_reussi", username, chemin_fichier_final)
                                    except Exception as e:
                                        print(f"[ERREUR] Impossible de déplacer le fichier déchiffré : {e}")
                                        ecrire_log("erreur_deplacement_dechiffre", username, fichier_final)
                        
                        elif choix == "4":
                            print("Déconnexion...")
                            break
                        else:
                            print("Option invalide, veuillez réessayer.")
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
