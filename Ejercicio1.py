from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import textwrap


# Función para dividir el mensaje en bloques de 128 caracteres sin cortar palabras
def correct_split_message(message, block_size=128):
    blocks = textwrap.wrap(message, block_size, break_long_words=False)
    for i in range(len(blocks) - 1):
        if not blocks[i].endswith(' ') and not blocks[i+1].startswith(' '):
            last_space_index = blocks[i].rfind(' ')
            blocks[i+1] = blocks[i][last_space_index+1:] + ' ' + blocks[i+1]
            blocks[i] = blocks[i][:last_space_index]
    return blocks


# Función para reconstruir el mensaje a partir de bloques descifrados
def reconstruct_message(blocks):
    reconstructed = ''
    for block in blocks:
        reconstructed += block if block.endswith(' ') or block.endswith('.') else block + ' '
    return reconstructed.strip()


# Generar un par de claves RSA
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Mensaje original
message_M = """En un lugar de la Mancha, de cuyo nombre no quiero acordarme, no ha mucho tiempo que vivía un hidalgo de los de lanza en astillero, adarga antigua, rocín flaco y galgo corredor. Una olla de algo más vaca que carnero, salpicón las más noches, duelos y quebrantos los sábados, lentejas los viernes, algún palomino de añadidura los domingos, consumían las tres partes de su hacienda. El resto della concluían sayo de velarte, calzas de velludo para las fiestas, con sus pantuflos de lo mismo, y los días de entresemana se honraba con su vellorí de lo más fino. Tenía en su casa una ama que pasaba de los cuarenta, y una sobrina que no llegaba a los veinte, y un mozo de campo y plaza, que así ensillaba el rocín como tomaba la podadera. Frisaba la edad de nuestro hidalgo con los cincuenta años; era de complexión recia, seco de carnes, enjuto de rostro, gran madrugador y amigo de la caza. Quieren decir que tenía el sobrenombre de Quijada, o Quesada, que en esto hay alguna diferencia en los autores que deste caso escriben; aunque, por conjeturas ve"""

# Dividir el mensaje en bloques
message_blocks = correct_split_message(message_M)

# Cifrar cada bloque con la clave pública
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
encrypted_blocks = [cipher_rsa.encrypt(block.encode('utf-8')) for block in message_blocks]

# Descifrar cada bloque con la clave privada
decrypt_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
decrypted_blocks = [decrypt_rsa.decrypt(block).decode('utf-8') for block in encrypted_blocks]

# Reconstruir el mensaje descifrado
message_reconstructed = reconstruct_message(decrypted_blocks)

# Verificar que el mensaje reconstruido coincide con el mensaje original
message_is_same = message_M == message_reconstructed

# Generar el hash del mensaje original y del reconstruido
hash_original = SHA256.new(message_M.encode('utf-8')).hexdigest()
hash_reconstructed = SHA256.new(message_reconstructed.encode('utf-8')).hexdigest()

# Verificar que los hashes coinciden
hashes_match = hash_original == hash_reconstructed

# Resultados
print("-----------------------------------------------------------------")
print("Ejercicio 1")
print("-----------------------------------------------------------------")
print(f"Mensaje original: {message_M}")
print(f"Mensaje reconstruido: {message_reconstructed}")
print()
print(f"Los mensajes son iguales: {message_is_same}")
print("-----------------------------------------------------------------")
print(f"Hash del mensaje original: {hash_original}")
print(f"Hash del mensaje reconstruido: {hash_reconstructed}")
print()
print(f"Los hashes coinciden: {hashes_match}")
print("-----------------------------------------------------------------")
