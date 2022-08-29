import os
import rsa

lang = {
    "weak": "Faible",
    "basic": "Moyenne",
    "strong": "Forte"
}

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
    }
    {
        "name": lang["strong"],
        "keygen": 2048,
        "enclen": 245,
        "declen": 256
    }
]