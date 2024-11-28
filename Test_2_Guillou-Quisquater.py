# Bob est le verificateur
# Alice est celle qui doit prouver sa connaissance de la clé privée
# debut cote alice
n_Alice = 109533351850456359814508155795293304516430905208808849638150962223886949498199836452193801782968812210361976417518903425419594060121024271280124693681100031408325968675530788368861959257531856126715707089191886183368705262945962850196212720471583271759619771978188615282203430380485565368798958812207734173371
#phi_n = (p-1) * (q-1)
v = 65537 #Doit être premier avec phi_n => PGCD(v,phi_n) = 1
# Alice genere un B (prive)
B = 3124 #Doit être premier avec n => PGCD(B,n) = 1
# calcul de J
J = pow(B,-v,n_Alice) # J1 = pow(B,v,n) p3uis J = pow(J1,-1,n)
print("J: ",J)

# Alice choisit un r tel que r ∈ {1, 2, ..., n_Alice − 1}
r = 1874

# Calcul de T = r**v mod n
T = pow(r,v,n_Alice)
# Alice envoie T a Bob
# fin cote alice

# debut cote Bob
n_Bob = 109533351850456359814508155795293304516430905208808849638150962223886949498199836452193801782968812210361976417518903425419594060121024271280124693681100031408325968675530788368861959257531856126715707089191886183368705262945962850196212720471583271759619771978188615282203430380485565368798958812207734173371
# Bob choisit un d ∈ {0, 1, .., v − 1} 
d = 135
# Il envoie d a Alice
# fin cote Bob

# debut cote alice
# Alice calcul t 
t = (r * pow(B,d,n_Alice)) % n_Alice
print("t: ",t)
# Alice envoie t 
# fin cote alice

# debut cote Bob
# Bob check la validite de la reponse avec l'equation : 
P = (pow(t,v,n_Bob) * pow(J,d,n_Bob)) % n_Bob
print("P: ",P)
if P == T:
    print("Valid")
else:
    print("different")

print("fin")

# fin cote Bob
