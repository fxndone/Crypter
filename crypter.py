import os
import sys
import rsa

lang = {
    "error.no_key_file": "Erreur : Le fichier de clef est absent !",

    "helper.reset_keys": """Vos clefs de chiffrements on subits des domages !
Nous allons les reinitialiser avec votre clef USB de secours !
Veuillez ejecter votre clef usuelle, et inserer la clef USB de sauvegarde.""",
    "helper.reset_complet": "Vos clefs de chiffrement sont maintenant reinitialisees. Vous pouvez relancer ce logiciel pour acceder a votre contenue comme d'habitude.",

    "input.null": "Pressez entre",
    "input.usb_path": "Entrez le chemin d'access a votre clef USB : ",
    "input.usual_usb": "Veuillez inserer votre clef usuelle, et entrer son chemin d'access : "
}

config = {
    "pub.enclen": 117,
}

def SaveKeys(public_key: bytes, private_key: bytes):
    with open("pub.key", 'wb+') as f:
        f.write(encrypt(public_key, rsa.PublicKey.load_pkcs1(public_key), config["pub.enclen"]))
        f.close()
    filepath = input(lang["input.usual_usb"])
    while not os.path.isdir(filepath):
        filepath = input(lang["input.usual_usb"])
    with open(os.path.join(filepath, "priv.key"), 'wb+') as f:
        f.write(private_key)
    print(lang["helper.reset_complet"])
    input(lang["input.null"])
    sys.exit(0)

def ResetKeys():
    print(lang["helper.reset_keys"])
    input(lang["input.null"])
    filepath = input(lang["input.usb_path"])
    while not (os.path.isdir(filepath) and "pub.key" in os.listdir(filepath) and "priv.key" in os.listdir(filepath)):
        filepath = input(lang["input.usb_path"])

    with open(os.path.join(filepath, "pub.key"), 'rb') as f:
        public_key = f.read()
    with open(os.path.join(filepath, "priv.key"), 'rb') as f:
        private_key = f.read()
    
    SaveKeys(public_key, private_key)

def encrypt(data: bytes, pubkey, max_length: int):
    datas = [data[i:i+max_length] for i in range(0, len(data), max_length)]
    encrypted = [rsa.encrypt(s, pubkey) for s in datas]
    return b''.join(encrypted)

def decrypt(data: bytes, privkey, part_length: int):
    datas = [data[i:i+part_length] for i in range(0, len(data), part_length)]
    decrypted = [rsa.decrypt(s, privkey) for s in datas]
    return b''.join(decrypted)

if not os.path.isfile("pub.key"):
    print(lang["error.no_key_file"])
    input(lang["input.null"])

    ResetKeys()
else:
    pass