def sponge_function(input_data: bytes, output_size: int, rate: int = 8, rounds: int = 12) -> bytes:
    """
    Fonction éponge simplifiée avec absorption et essorage.
    input_data : entrée à absorber (bytes)
    output_size : taille de sortie souhaitée (en octets)
    rate : nombre d'octets traités à chaque tour d'absorption
    rounds : nombre de tours d'essorage pour diffusion
    """
    # Taille de l'état interne (plus grand que le rate)
    state_size = 32  # 256 bits
    state = bytearray(state_size)  # Initialisation de l'état interne
    
    # Absorption : Intègre les blocs d'entrée dans l'état interne
    for i in range(0, len(input_data), rate):
        block = input_data[i:i+rate]  # Extraire un bloc de taille rate
        for j in range(len(block)):
            state[j] ^= block[j]  # XOR avec l'état interne
        
        # Phase de permutation (essorage partiel)
        for _ in range(rounds):
            state = permutation(state)
    
    # Essorage : Produire la sortie en plusieurs étapes
    output = bytearray()
    while len(output) < output_size:
        for _ in range(rounds):
            state = permutation(state)  # Appliquer des tours de permutation
        output += state[:rate]  # Récupérer les premiers octets de l'état
    
    return bytes(output[:output_size])


def permutation(state: bytearray) -> bytearray:
    """
    Fonction de permutation (simple diffusion).
    """
    # Exemple : Rotation circulaire et XOR pour la diffusion
    for i in range(len(state)):
        state[i] ^= (state[-(i+1)] >> 1) & 0xFF
    state = state[::-1]  # Inversion totale
    state = bytearray((b << 1) & 0xFF | (b >> 7) for b in state)  # Rotation à gauche de 1 bit
    return state


def kdf(password: str, phi_n: int, key_size: int = 32) -> bytes:
    """
    Fonction de dérivation de clé (KDF) utilisant la fonction éponge.
    password : mot de passe utilisateur
    phi_n : valeur phi(n) utilisée dans la dérivation
    key_size : taille de la clé souhaitée (32 octets par défaut)
    """
    # Conversion des données en bytes
    input_data = password.encode() + phi_n.to_bytes((phi_n.bit_length() + 7) // 8, 'big')
    key = sponge_function(input_data, key_size, rate=8, rounds=12)
    return key


# Exemple de test
if __name__ == "__main__":
    password = "monMotDePasse"
    phi_n = 3120  # Exemple de valeur phi(n)
    derived_key = kdf(password, phi_n)
    print("Clé dérivée:", derived_key.hex())
