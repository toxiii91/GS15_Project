import random
def rabin_miller(n, k=20):
    """
    Test de primalité de Rabin-Miller.
    n : Nombre à tester (doit être un entier >= 2)
    k : Nombre de tests (plus k est grand, plus la probabilité d'erreur diminue)
    Retourne True si n est probablement premier, False sinon.
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Étape 1 : Écrire n - 1 comme 2^r * d avec d impair
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
  
    # Étape 2 : Effectuer k tests
    for _ in range(k):
        a = random.randint(2, n - 2)  # Choisir un témoin aléatoire
        x = pow(a, d, n)  # Calcul de a^d % n (pow(base, exp, mod))

        if x == 1 or x == n - 1:  # Passe le test immédiatement
            continue

        # Tester les puissances successives de x
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:  # Si x atteint n - 1, n passe ce test
                break
        else:
            return False  # Si aucune puissance n'atteint n - 1, n n'est pas premier

    return True  # Si tous les tests passent, n est probablement premier
