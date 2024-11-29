import random
def diffie_hellman():
    # Le client et le coffre fort se mettent d'accord sur deux paramètres publiques p (un très grand nombre premier) et
    # g (un générateur appartenant à Zp premier), g<p et sont transmis en clair
    #Voire les recommandations RFC3526
    p = 103728854681275058600906879797352391038768446844980887802954076620280446673730482774142180964312927979979335404075456950962688034962711908887035704848006333067173725138975667968627741285104076284914795266001358228416813871340130307214227929594900405301811227482098519874676629067279933426557615190972786352641
    g = 2

    # Clés privées aléatoires du client et du coffre
    a = random.randint(2, p - 1)
    b = random.randint(2, p - 1)

    # Clés publiques calculées à partir de la base g
    A = pow(g, a, p)
    B = pow(g, b, p)

    # Clé secrète partagée
    ka = pow(B, a, p)
    kb = pow(A, b, p) 

    assert ka == kb, "Les clés partagées doivent être identiques."
    return ka

if __name__ == "__main__":
    shared_key = diffie_hellman()
    print(shared_key)