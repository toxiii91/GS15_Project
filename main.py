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
                connexion = ZKP(username)
                ecrire_log("zkp", username)
                if connexion:
                    # Initialiser la clé de session à None
                    session_key = None
                    while True:
                        print("\nConnexion réussie, que voulez-vous faire maintenant ?")
                        print("1. Créer une clé de session avec le coffre")
                        print("2. Déposer un fichier dans le coffre")
                        print("3. Récupérer un fichier du coffre")
                        print("4. Quitter")
                        choix = input("Choisissez une option : ").strip()
                        
                        if choix == "1":
                            # Option de Création de Clé de Session
                            session_key = diffie_hellman(username)
                            if session_key:
                                print("[OK] Clé de session générée avec succès.")
                                ecrire_log("creation_cle_session", username)
                            else:
                                print("[ERREUR] Échec de la génération de la clé de session.")
                                ecrire_log("erreur_creation_cle_session", username)
                        
                        elif choix == "2":
                            # Option de Dépôt de Fichier
                            if not session_key:
                                print("[ERREUR] Vous devez d'abord créer une clé de session (Option 1).")
                                continue
                            
                            chemin_dossier_client = os.path.join("users", username)
                            chemin_dossier_coffre = os.path.join("coffre_fort", username)
                            
                            # Assurer que le répertoire coffre_fort/{username}/ existe
                            os.makedirs(chemin_dossier_coffre, exist_ok=True)
                            
                            # Demander le nom du fichier à déposer
                            nom_fichier = input("Entrez le nom du fichier à déposer dans le coffre : ").strip()
                            
                            # Chemin complet du fichier à déposer
                            chemin_complet = os.path.join(chemin_dossier_client, nom_fichier)
                            
                            # Vérifier si le fichier existe
                            if not os.path.exists(chemin_complet):
                                print("[ERREUR] Le fichier à déposer n'existe pas ou le chemin est invalide.")
                                ecrire_log("erreur_fichier_inexistant", username, nom_fichier)
                                continue
                            
                            # Génération des clés Cobra à partir de la clé de session
                            cle_initiale_dh = cobra.key_to_binary(session_key)
                            round_keys = cobra.generate_keys(cle_initiale_dh)
                            
                            # 3) Utiliser Cobra pour chiffrer le fichier
                            try:
                                with open(chemin_complet, 'rb') as f:
                                    contenu = f.read()
                                message = contenu.decode('utf-8')
                            except Exception as e:
                                print(f"[ERREUR] Impossible de lire le fichier : {e}")
                                ecrire_log("erreur_lecture_fichier", username, chemin_complet)
                                continue

                            encrypted_hex, _ = cobra.cobra_encrypt_message(message, round_keys)
                            if not encrypted_hex:
                                print("[ERREUR] Échec du chiffrement Cobra.")
                                ecrire_log("erreur_chiffrement_cobra", username, nom_fichier)
                                continue

                            # 4) Sauvegarder le contenu chiffré dans un fichier temporaire
                            fichier_temp_enc = f"{chemin_complet}.cobra.enc.temp"
                            try:
                                with open(fichier_temp_enc, 'w', encoding='utf-8') as f:
                                    f.write(encrypted_hex)
                                ecrire_log("chiffrement_cobra", username, fichier_temp_enc)
                            except Exception as e:
                                print(f"[ERREUR] Impossible d'écrire le fichier chiffré temporaire : {e}")
                                ecrire_log("erreur_ecriture_temp_enc", username, fichier_temp_enc)
                                continue

                            # 5) Déplacer le fichier chiffré temporaire vers coffre_fort/{username}/
                            chemin_fichier_coffre_temp = os.path.join(chemin_dossier_coffre, f"{nom_fichier}.cobra.enc.temp")
                            success = cobra.deplacer_fichier(fichier_temp_enc, chemin_fichier_coffre_temp)
                            if success:
                                print(f"[OK] Fichier chiffré déplacé vers le coffre : {chemin_fichier_coffre_temp}")
                            else:
                                print("[ERREUR] Impossible de déplacer le fichier chiffré vers le coffre.")
                                continue

                            # 6) Déchiffrer le fichier dans coffre_fort avec Cobra
                            try:
                                with open(chemin_fichier_coffre_temp, 'r', encoding='utf-8') as f:
                                    encrypted_hex_coffre = f.read()
                                decrypted_message = cobra.cobra_decrypt_message(encrypted_hex_coffre, round_keys)
                                ecrire_log("dechiffrement_cobra_coffre", username, chemin_fichier_coffre_temp)
                            except Exception as e:
                                print(f"[ERREUR] Le déchiffrement Cobra a échoué dans le coffre : {e}")
                                ecrire_log("erreur_dechiffrement_cobra_coffre", username, chemin_fichier_coffre_temp)
                                continue

                            # 7) Chiffrer le fichier avec RSA
                            try:
                                # Sauvegarder le contenu déchiffré dans un fichier temporaire
                                fichier_temp_dechiffre = f"{chemin_fichier_coffre_temp}.dechiffre.temp"
                                with open(fichier_temp_dechiffre, 'w', encoding='utf-8') as f:
                                    f.write(decrypted_message)
                                ecrire_log("sauvegarde_dechiffre_temp", username, fichier_temp_dechiffre)

                                # Chiffrer le fichier temporaire avec RSA et ajouter au coffre
                                rsa_avec_padding.ajouter_fichier_au_coffre(fichier_temp_dechiffre, username)
                                ecrire_log("chiffrement_rsa", username, fichier_temp_dechiffre)

                                # Renommer le fichier chiffré RSA
                                chemin_fichier_rsa_enc = os.path.join(chemin_dossier_coffre, f"{nom_fichier}.rsa.enc")
                                fichier_chiffre_rsa = os.path.join("coffre_fort", username, f"{nom_fichier}.rsa.enc")
                                
                                # Vérifier si le chiffrement RSA a réussi
                                if os.path.exists(fichier_chiffre_rsa):
                                    # Supprimer le fichier temporaire déchiffré
                                    os.remove(fichier_temp_dechiffre)
                                    ecrire_log("suppression_dechiffre_temp", username, fichier_temp_dechiffre)
                                    print(f"[OK] Fichier chiffré avec RSA et stocké dans le coffre : {chemin_fichier_rsa_enc}")
                                else:
                                    print("[ERREUR] Le chiffrement RSA a échoué.")
                                    ecrire_log("erreur_chiffrement_rsa", username, fichier_temp_dechiffre)
                                    continue
                            except Exception as e:
                                print(f"[ERREUR] Échec du chiffrement RSA : {e}")
                                ecrire_log("erreur_chiffrement_rsa", username, fichier_temp_dechiffre)
                                continue

                        elif choix == "3":
                            # Option de Récupération de Fichier
                            if not session_key:
                                print("[ERREUR] Vous devez d'abord créer une clé de session (Option 1).")
                                continue

                            chemin_dossier_coffre = os.path.join("coffre_fort", username)
                            
                            # Demander le nom du fichier chiffré RSA à récupérer
                            nom_fichier_enc = input("Entrez le nom du fichier chiffré RSA à récupérer (.rsa.enc) : ").strip()
                            
                            # Chemin complet du fichier chiffré RSA
                            chemin_fichier_rsa_enc = os.path.join(chemin_dossier_coffre, nom_fichier_enc)
                            
                            # Vérifier si le fichier chiffré RSA existe
                            if not os.path.exists(chemin_fichier_rsa_enc):
                                print("[ERREUR] Le fichier chiffré RSA n'existe pas ou le chemin est invalide.")
                                ecrire_log("erreur_fichier_rsa_inexistant", username, nom_fichier_enc)
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
                            
                            # Déchiffrer RSA => obtenir le fichier déchiffré temporaire
                            try:
                                fichier_temp_dechiffre = f"{chemin_fichier_rsa_enc}.dechiffre.temp"
                                rsa_avec_padding.dechiffrer_fichier_par_blocs(chemin_fichier_rsa_enc, private_key, fichier_temp_dechiffre)
                                ecrire_log("dechiffrement_rsa", username, chemin_fichier_rsa_enc)
                            except Exception as e:
                                print(f"[ERREUR] Le déchiffrement RSA a échoué : {e}")
                                ecrire_log("erreur_dechiffrement_rsa", username, nom_fichier_enc)
                                continue
                            
                            # Génération des clés Cobra à partir de la clé de session
                            cle_initiale_dh = cobra.key_to_binary(session_key)
                            round_keys = cobra.generate_keys(cle_initiale_dh)
                            
                            # Déchiffrer avec Cobra
                            try:
                                with open(fichier_temp_dechiffre, 'r', encoding='utf-8') as f:
                                    encrypted_hex_coffre = f.read()
                                decrypted_message = cobra.cobra_decrypt_message(encrypted_hex_coffre, round_keys)
                                ecrire_log("dechiffrement_cobra", username, fichier_temp_dechiffre)
                            except Exception as e:
                                print(f"[ERREUR] Le déchiffrement Cobra a échoué : {e}")
                                ecrire_log("erreur_dechiffrement_cobra", username, nom_fichier_enc)
                                os.remove(fichier_temp_dechiffre)
                                continue
                            
                            # Définir le chemin du fichier déchiffré dans /users/{username}/
                            nom_fichier_original = nom_fichier_enc.replace('.rsa.enc', '')
                            chemin_fichier_final = os.path.join("users", username, nom_fichier_original)
                            
                            # Vérifier si le fichier déchiffré existe déjà
                            if os.path.exists(chemin_fichier_final):
                                print(f"[ERREUR] Le fichier '{chemin_fichier_final}' existe déjà.")
                                ecrire_log("erreur_fichier_deja_existant", username, chemin_fichier_final)
                                os.remove(fichier_temp_dechiffre)
                                continue
                            
                            # Écrire le contenu déchiffré dans le fichier final
                            try:
                                decrypted_bytes = decrypted_message.encode('utf-8')
                                with open(chemin_fichier_final, 'wb') as f:
                                    f.write(decrypted_bytes)
                                print(f"[OK] Fichier final reconstitué : {chemin_fichier_final}")
                                ecrire_log("dechiffrement_reussi", username, chemin_fichier_final)
                            except Exception as e:
                                print(f"[ERREUR] Impossible d'écrire le fichier déchiffré : {e}")
                                ecrire_log("erreur_ecriture_fichier_dechiffre", username, chemin_fichier_final)
                            
                            # Supprimer le fichier temporaire déchiffré
                            os.remove(fichier_temp_dechiffre)
                            ecrire_log("suppression_dechiffre_temp", username, fichier_temp_dechiffre)
                            
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
