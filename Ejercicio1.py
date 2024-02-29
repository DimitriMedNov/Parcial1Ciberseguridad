from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64

# Función para generar las claves RSA
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Función para cifrar el mensaje
def encrypt_message(message, public_key):
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    return [cipher.encrypt(message[i:i + 128].encode()) for i in range(0, len(message), 128)]

# Función para descifrar el mensaje
def decrypt_message(encrypted_message, private_key):
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    return ''.join([cipher.decrypt(chunk).decode() for chunk in encrypted_message])

# Función para generar el hash de un mensaje
def hash_message(message):
    hash_object = SHA256.new(data=message.encode())
    return base64.b64encode(hash_object.digest()).decode()

if __name__ == "__main__":
    # Alice y Bob generan sus claves
    private_key, public_key = generate_keys()

    # Alice tiene un mensaje para Bob
    message_M = "En un lugar de la Mancha, de cuyo nombre no quiero acordarme, no ha mucho tiempo que vivía un hidalgo de los de lanza en astillero, adarga antigua, rocín flaco y galgo corredor. Una olla de algo más vaca que carnero, salpicón las más noches, duelos y quebrantos los sábados, lentejas los viernes, algún palomino de añadidura los domingos, consumían las tres partes de su hacienda. El resto della concluían sayo de velarte, calzas de velludo para las fiestas, con sus pantuflos de lo mismo, y los días de entresemana se honraba con su vellorí de lo más fino. Tenía en su casa una ama que pasaba de los cuarenta, y una sobrina que no llegaba a los veinte, y un mozo de campo y plaza, que así ensillaba el rocín como tomaba la podadera. Frisaba la edad de nuestro hidalgo con los cincuenta años; era de complexión recia, seco de carnes, enjuto de rostro, gran madrugador y amigo de la caza. Quieren decir que tenía el sobrenombre de Quijada, o Quesada, que en esto hay alguna diferencia en los autores que deste caso escriben; aunque, por conjeturas ve"  # Un mensaje de 1050 caracteres 'M'

    # Alice cifra el mensaje para Bob
    encrypted_message = encrypt_message(message_M, public_key)

    # Bob descifra el mensaje
    message_reconstructed = decrypt_message(encrypted_message, private_key)

    # Verificar si el mensaje reconstruido es el mismo que el original
    message_is_same = message_M == message_reconstructed

    # Alice y Bob generan el hash del mensaje
    hash_original = hash_message(message_M)
    hash_reconstructed = hash_message(message_reconstructed)

    # Comprobación de la integridad del mensaje
    hashes_match = hash_original == hash_reconstructed

    # Resultados
    print("-----------------------------------------------------------------")
    print("Ejercicio 1")
    print("-----------------------------------------------------------------")
    print(f"Mensaje original: {message_M}")
    print(f"Mensaje reconstruido: {message_reconstructed}")
    print(f"Los mensajes son iguales: {message_is_same}")
    print("-----------------------------------------------------------------")
    print(f"Hash del mensaje original: {hash_original}")
    print(f"Hash del mensaje reconstruido: {hash_reconstructed}")
    print(f"Los hashes coinciden: {hashes_match}")
    print("-----------------------------------------------------------------")
