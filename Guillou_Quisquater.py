import random
import os
# Bob est le verificateur
# Alice est celle qui doit prouver sa connaissance de la clé privée
def pgcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generer_premier(n):
    while True:
        # Générez un nombre aléatoire entre 1 et n-1
        B = random.randint(1, n-1)
        # Vérifiez que B est premier avec n (PGCD(B, n) == 1)
        if pgcd(B, n) == 1:
            return B

def charger_cle_privee(username): 
    """Charge la clé privée à partir du fichier dans le répertoire de l'utilisateur."""
    chemin_fichier = os.path.join("users", username, "private_key.key")  # Construire le chemin complet
    try:
        with open(chemin_fichier, "r") as f:
            n, d = map(int, f.read().strip().split(","))  # Lire n et d comme des entiers
        return (n, d)
    except FileNotFoundError:
        print(f"Erreur : Le fichier de la clé privée est introuvable dans {chemin_fichier}.")
        return None
    except ValueError:
        print("Erreur : Format de la clé privée invalide.")
        return None
    
def charger_cle_publique(username):
    """Charge la clé privée à partir du fichier dans le répertoire de l'utilisateur."""
    chemin_fichier = os.path.join("coffre_fort", username, "public_key.key")  # Construire le chemin complet
    try:
        with open(chemin_fichier, "r") as f:
            n, e = map(int, f.read().strip().split(","))  # Lire n et e comme des entiers
        return (n, e)
    except FileNotFoundError:
        print("Erreur : Le fichier de la clé publique est introuvable.")
        return None
    except ValueError:
        print("Erreur : Format de la clé publique invalide.")
        return None
    
def prouveur(username):   

    private_key = charger_cle_privee(username)
    if private_key is None:
        print("Erreur : Impossible de charger les clés.")
        return 1  # Retourne une erreur explicite si les clés ne sont pas chargées
    n_prouv, _ = private_key

    # Génération d'un B aléatoire premier avec n_prouv
    B = generer_premier(n_prouv)
    e = verificateur(2, 0, 0, 0, 0, username) # récupération de e auprès du vérificateur

    # print("B: ",B)

    # Calcul de J
    J = pow(B, -1, n_prouv)  # Calcul de l'inverse de B mod n
    J = pow(J, e, n_prouv)   # J = (B^-1)^e mod n
    #print("J: ", J)

    # Génération d'un r aléatoire tel que r ∈ {1, 2, ..., n_prouv − 1}
    r = random.randint(1, n_prouv - 1)  # Choisir r dans [1, n_prouv - 1]

    # Calcul de T
    T = pow(r, e, n_prouv)

    # Alice envoie T à Bob
    d = verificateur(0, T, 0, J, e, username)

    # Calcul de t
    t = (r * pow(B, d, n_prouv)) % n_prouv
    #print("t: ", t)

    # Alice envoie t
    value = verificateur(1, 0, t, J, e, username)

    if value == 0:
        print('\n Valid \n')
        return True
    else:
        print('\n different \n') 
        return False



    
def verificateur(i, T, t, J, v, username):


    public_key = charger_cle_publique(username)
    

    if public_key is None:
        print("Erreur : Impossible de charger les clés.")
        return

    n_verif, e = public_key

    # Utilisation de variables globales pour partager T_n et d
    if i == 0:  # Première étape, Bob reçoit T et génère d
        global T_n, d  # T_n et d doivent être accessibles dans les deux étapes
        T_n = T
        # Génération de d aléatoire (d ∈ {0, 1, ..., e-1})
        d = random.randint(0, e - 1)  # Choisir e dans [1, e - 1]
        return d

    elif i == 1:  # Deuxième étape, Bob vérifie la réponse
        global t_n  # Pour conserver t entre les étapes
        t_n = t
        # Calcul de la vérification P
        P = (pow(t_n, e, n_verif) * pow(J, d, n_verif)) % n_verif
        #print("P: ", P)
        #print("T_n: ", T_n)
        if P == T_n:
            return 0  # Validation réussie
        else:
            return 1  # Échec de la validation 
    elif i == 2:  # Bob envoie e
        return e     


def ZKP(username):
    connexion = prouveur(username)
    return connexion