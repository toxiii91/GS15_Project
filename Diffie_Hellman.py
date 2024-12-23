import random
from cobra_test import test_message_encryption
def diffie_hellman():
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

    User(p, g)
    print("La connexion est établie. La clé de session est créee !")
    print("Que souhaitez-vous faire maintenant : ")

    while True:
        print("1. Retourner au menu principal")
        print("2. Utiliser Cobra pour chiffrer")
        choix = input("Choisissez une option : ")

        if choix == "1":
            print('\n Au revoir ! \n')
            break
        elif choix == "2":
            test_message_encryption()            
        else:
            print("Option invalide, veuillez réessayer.")



def User(p, g):
    # Clés privées aléatoires du client et du coffre
    a = random.randint(2, p - 1)
    A = pow(g, a, p)
    # Envoie de A à Coffre, et on reçoit B
    B = Coffre(p, g, A)

    # Reçoit B, on peut alors calculer la clé secrète ka
    ka = pow(B, a, p)

    # Réduction de la clé à 256 bits en utilisant une simple troncature
    ka_binary = bin(ka)[2:]  # Convertir en binaire sans le préfixe '0b'
    ka_256_bit = ka_binary[:256]  # Garder seulement les 256 premiers bits
    ka_final = int(ka_256_bit, 2)  # Reconversion en entier

    with open("ka.key", "w") as f:
        # Sauvegarder la clé privée tronquée
        f.write(f"{ka_final}\n")


def Coffre(p, g, A):
    b = random.randint(2, p - 1)
    B = pow(g, b, p)
    # Envoie de B à Alice  

    # Reçoit A, on peut alors calculer la clé secrète kb
    kb = pow(A, b, p)

    # Réduction de la clé à 256 bits en utilisant une simple troncature
    kb_binary = bin(kb)[2:]  # Convertir en binaire sans le préfixe '0b'
    kb_256_bit = kb_binary[:256]  # Garder seulement les 256 premiers bits
    kb_final = int(kb_256_bit, 2)  # Reconversion en entier

    with open("kb.key", "w") as f:
        # Sauvegarder la clé privée tronquée
        f.write(f"{kb_final}\n")

    return B
