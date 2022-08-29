import os
import sys
import json
import shutil

try:
    import rsa
except:
    os.system(f"{sys.executable} -m pip install rsa")

LANG = input("Language : ").lower()
while not os.path.isfile(f"lang.{LANG}.json"):
    LANG = input("Language : ").lower()

lang = json.load(open(f"lang.{LANG}.json", 'r'))

encryptions = [
    {
        "name": lang["weak"],
        "keygen": 512,
        "enclen": 53,
        "declen": 64
    },
    {
        "name": lang["basic"],
        "keygen": 1024,
        "enclen": 117,
        "declen": 128
    },
    {
        "name": lang["strong"],
        "keygen": 2048,
        "enclen": 245,
        "declen": 256
    }
]

def encrypt(data: bytes, pubkey, max_length: int):
    datas = [data[i:i+max_length] for i in range(0, len(data), max_length)]
    encrypted = [rsa.encrypt(s, pubkey) for s in datas]
    return b''.join(encrypted)

def decrypt(data: bytes, privkey, part_length: int):
    datas = [data[i:i+part_length] for i in range(0, len(data), part_length)]
    decrypted = [rsa.decrypt(s, privkey) for s in datas]
    return b''.join(decrypted)

print(lang["helper.encriptions"])
for i in range(len(encryptions)):
    print(f"({i+1}) : {encryptions[i]['name']}")

chx = input(">> ")
good = False
while not good:
    try:
        chx = int(chx)
    except:
        chx = input(">> ")
    else:
        if chx >= 1 and chx <= len(encryptions):
            good = True

encription = encryptions[chx-1]

dirpath = input(lang["input.crypt_dir"])
while not os.path.isdir(dirpath):
    dirpath = input(lang["input.crypt_dir"])

dirpath = os.path.abspath(dirpath)

config = """{
    "enclen": """ + str(encription['enclen']) + """,
    "declen": """ + str(encription['declen']) + """,
    "dirpath": """ + '"' + dirpath + '"' + """,
    "lang": """ + '"' + LANG + '"' + """
}"""

with open("config.json", 'w+') as f:
    f.write(config)


print(lang["helper.generating"])

public_key, private_key = rsa.newkeys(encription["keygen"])

print(lang["helper.generated"])

print(lang["helper.backup_key"])

filepath = input(lang["input.usb_path"])
while not os.path.isdir(filepath):
    filepath = input(lang["input.usb_path"])

with open(os.path.join(filepath, "pub.key"), 'wb+') as f:
    f.write(public_key.save_pkcs1())

with open(os.path.join(filepath, "priv.key"), 'wb+') as f:
    f.write(private_key.save_pkcs1())

print(lang["helper.eject"])

filepath = input(lang["input.usual_usb"])
while not os.path.isdir(filepath):
    filepath = input(lang["input.usual_usb"])

with open(os.path.join(filepath, "priv.key"), 'wb+') as f:
    f.write(private_key.save_pkcs1())

with open("pub.key", 'wb+') as f:
    f.write(encrypt(public_key.save_pkcs1(), public_key, encription["enclen"]))


shutil.make_archive(dirpath, format='zip', root_dir=dirpath)
shutil.rmtree(dirpath)

with open(dirpath+'.zip', 'rb') as f:
    decoded = f.read()

with open(dirpath+'.zip', 'wb+') as f:
    f.write(encrypt(decoded, public_key, encription["enclen"]))

print(lang["helper.goodbye"])

os.remove(sys.argv[0])

shutil.move("crypter.py", sys.argv[0])
