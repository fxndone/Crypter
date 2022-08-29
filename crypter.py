import os
import shutil
import sys
import rsa
import json
import tempfile

config = json.load(open("config.json", 'r'))

lang = json.load(open(f"lang.{config['lang']}.json", 'r'))

def SaveKeys(public_key: bytes, private_key: bytes):
    with open("pub.key", 'wb+') as f:
        f.write(encrypt(public_key, rsa.PublicKey.load_pkcs1(public_key), config["enclen"]))
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
    while not (os.path.isdir(filepath) and os.path.isfile(os.path.join(filepath, "pub.key")) and os.path.isfile(os.path.join(filepath, "priv.key"))):
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
    print(lang["helper.hello"])
    filepath = input(lang["input.usb_path"])
    while not (os.path.isdir(filepath) and os.path.isfile(os.path.join(filepath, "priv.key"))):
        filepath = input(lang["input.usb_path"])

    with open(os.path.join(filepath, "priv.key"), 'rb') as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())

    with open("pub.key", 'rb') as f:
        try:
            public_key = rsa.PublicKey.load_pkcs1(decrypt(f.read(), private_key, config["declen"]))
        except rsa.pkcs1.DecryptionError:
            ResetKeys()
    
    dirpath = config["dirpath"]
    zippath = dirpath + '.zip'

    decpath = tempfile.mkstemp()[1]

    with open(zippath, 'rb') as f:
        encoded = f.read()
    
    decoded = decrypt(encoded, private_key, config["declen"])

    with open(decpath, 'wb+') as f:
        f.write(decoded)
    
    shutil.unpack_archive(decpath, dirpath, "zip")
    os.remove(zippath)
    os.remove(decpath)

    input(lang["helper.stop_and_crypt"])

    shutil.make_archive(dirpath, format='zip', root_dir=dirpath)

    shutil.rmtree(dirpath)

    with open(zippath, 'rb') as f:
        decoded = f.read()
    
    with open(zippath, 'wb+') as f:
        f.write(encrypt(decoded, public_key, config["enclen"]))
    
    print(lang["helper.goodbye"])
    sys.exit(0)