import cv2
import numpy as np
from PIL import Image
from stegano import lsb
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def menu():
    while True:
        print("\nMenu de Opções:")
        print("(1) Embutir texto em uma imagem usando Steganography")
        print("(2) Recuperar texto de uma imagem alterada pela técnica Steganography")
        print("(3) Gerar hash das imagens original e alterada")
        print("(4) Encriptar a mensagem usando criptografia de chave pública e privada")
        print("(5) Decriptar o texto encriptado de uma imagem alterada")
        print("(S ou s) Sair do Menu de opções")

        opcao = input("Escolha uma opção: ")

        if opcao == "1":
            embutir_texto()
        elif opcao == "2":
            recuperar_texto()
        elif opcao == "3":
            gerar_hash()
        elif opcao == "4":
            encriptar_mensagem()
        elif opcao == "5":
            decriptar_mensagem()
        elif opcao.lower() == "s":
            print("Encerrando a aplicação.")
            break
        else:
            print("Opção inválida! Tente novamente.")

def embutir_texto():
    imagem_caminho = input("Digite o caminho da imagem (exemplo: imagem.png): ")
    texto = input("Digite o texto a ser embutido: ")
    imagem_embutida = lsb.hide(imagem_caminho, texto)
    imagem_embutida.save("imagem_embutida.png")
    print("Texto embutido com sucesso! A imagem foi salva como 'imagem_embutida.png'.")

def recuperar_texto():
    imagem_caminho = input("Digite o caminho da imagem com texto embutido (exemplo: imagem_embutida.png): ")
    texto = lsb.reveal(imagem_caminho)
    if texto:
        print(f"Texto recuperado: {texto}")
    else:
        print("Nenhum texto encontrado na imagem.")

def gerar_hash():
    imagem_original = input("Digite o caminho da imagem original (exemplo: imagem.png): ")
    imagem_alterada = input("Digite o caminho da imagem alterada (exemplo: imagem_embutida.png): ")

    with open(imagem_original, 'rb') as f:
        hash_original = sha256(f.read()).hexdigest()
    with open(imagem_alterada, 'rb') as f:
        hash_alterada = sha256(f.read()).hexdigest()

    print(f"Hash da imagem original: {hash_original}")
    print(f"Hash da imagem alterada: {hash_alterada}")

def encriptar_mensagem():
    texto = input("Digite a mensagem a ser encriptada: ")

    # Gerando chave privada e chave pública
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    chave_publica = chave_privada.public_key()

    # Encriptando a mensagem
    texto_bytes = texto.encode()
    texto_encriptado = chave_publica.encrypt(
        texto_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Texto encriptado (base64): {base64.b64encode(texto_encriptado).decode()}")

    # Salvando as chaves
    with open("chave_privada.pem", "wb") as f:
        f.write(
            chave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    with open("chave_publica.pem", "wb") as f:
        f.write(
            chave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print("As chaves foram geradas e salvas em 'chave_privada.pem' e 'chave_publica.pem'.")

def decriptar_mensagem():
    caminho_imagem = input("Digite o caminho da imagem com texto embutido: ")
    texto_encriptado = lsb.reveal(caminho_imagem)
    if texto_encriptado:
        texto_encriptado_bytes = base64.b64decode(texto_encriptado)
        
        # Carregando a chave privada
        with open("chave_privada.pem", "rb") as f:
            chave_privada = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        
        # Decriptando a mensagem
        texto_decriptado = chave_privada.decrypt(
            texto_encriptado_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Texto decriptado: {texto_decriptado.decode()}")
    else:
        print("Nenhum texto encriptado encontrado na imagem.")

# Executar o menu
menu()
