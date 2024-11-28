p = 47
q = 59
n = p * q
phi_n = (p-1) * (q-1)
v = 157 #Doit être premier avec phi_n => PGCD(v,phi_n) = 1
# Alice genere un B (prive)
B = 920 #Doit être premier avec n => PGCD(B),n) = 1
# calcul de J
J = pow(B,-v,n) # J1 = pow(B,v,n) puis J = pow(J1,-1,n)
print("J: ",J)

# Alice choisit un r tel que r ∈ {1, 2, ..., n − 1}
r = 1874

# Calcul de T = r**v mod n
T = pow(r,v,n)

# Alice envoie T a Bob
# Bob choisit un d ∈ {0, 1, .., v − 1} 
d = 135
# Il envoie d a Alice

# Alice calcul t 
t = (r * pow(B,d,n)) % n
print("t: ",t)
# Alice envoie t 

# Bob check la validite de la reponse avec l'equation : 
P = (pow(t,v,n) * pow(J,d,n)) % n
print("P: ",P)
if P == T:
    print("Valid")
