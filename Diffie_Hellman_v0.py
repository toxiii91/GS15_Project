import random
from test_Rabin_miller import rabin_miller

def diffie_hellman():
    # Le client et le coffre fort se mettent d'accord sur deux paramètres publiques p (un très grand nombre premier) et
    # g (un générateur appartenant à Zp premier), g<p et sont transmis en clair
    #Voire les recommandations RFC3526
    hexa = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
    )
    p = int(hexa, 16) # hexa to dec
    g = 2

    User(p,g)
    print("Connexion etablie")


def User(p,g):
    # Clés privées aléatoires du client et du coffre
    a = random.randint(2, p - 1)
    A = pow(g, a, p)
    # Envoie de A à Coffre, et on reçoit B
    B = Coffre(p,g,A)

    # Recoit B, on peut alors calculer la clé secrete ka
    ka = pow(B, a, p)

    with open("ka.key", "w") as f:
        # Sauvegarder la clé privée dans le format : n,d
        f.write(f"{ka}\n")




def Coffre(p,g,A):
    b = random.randint(2, p - 1)
    B = pow(g, b, p)
    # Envoie de B à Alice  

    # Recoit A, on peut alors calculer la clé secrete kb
    kb = pow(A, b, p) 
    with open("kb.key", "w") as f:
        # Sauvegarder la clé privée dans le format : n,d
        f.write(f"{kb}\n")

    return B





