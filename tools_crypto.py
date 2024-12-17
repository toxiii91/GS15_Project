from test_Rabin_miller import rabin_miller
import random

def Euclide_etendu(a, b):
        if b == 0:
            return a, 1, 0
        pgcd, x1, y1 = Euclide_etendu(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return pgcd, x, y


def generer_nombre_premier(bits):
    """Génère un grand nombre premier de 'bits' bits."""
    while True:
        nombre_candidat = random.getrandbits(bits) | (1 << bits - 1) | 1  # Assure que le nombre est impair et de taille correcte
        if rabin_miller(nombre_candidat):
            return nombre_candidat
        
# Calcul de l'inverse modulaire
def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1