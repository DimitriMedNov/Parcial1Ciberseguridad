import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import PyPDF2

# Generar claves RSA para Alice y la Autoridad Certificadora
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


# Guardar las claves en archivos
def save_keys_to_file(private_key, public_key, filename_prefix):
    with open(f'{filename_prefix}_private.pem', 'wb') as priv_file:
        priv_file.write(private_key)
    with open(f'{filename_prefix}_public.pem', 'wb') as pub_file:
        pub_file.write(public_key)

# Generar las claves para Alice
alice_private_key, alice_public_key = generate_rsa_keys()
save_keys_to_file(alice_private_key, alice_public_key, 'alice')

# Generar las claves para la Autoridad Certificadora
ac_private_key, ac_public_key = generate_rsa_keys()
save_keys_to_file(ac_private_key, ac_public_key, 'ac')

# Función para generar el hash de un PDF
def hash_pdf(file_path):
    with open(file_path, 'rb') as f:
        reader = PyPDF2.PdfReader(f)
        contents = ''.join([page.extract_text() for page in reader.pages])
        hash_object = SHA256.new(contents.encode('utf-8'))
    return hash_object

# Función para firmar el hash del PDF con la clave privada
def sign_document(hash_object, private_key):
    signer = pkcs1_15.new(RSA.import_key(private_key))
    return signer.sign(hash_object)


# Función para verificar la firma con la clave pública
def verify_signature(public_key, signature, hash_object):
    try:
        pkcs1_15.new(RSA.import_key(public_key)).verify(hash_object, signature)
        return True
    except (ValueError, TypeError):
        return False

# Función para añadir la firma a un PDF
# Función para añadir la firma a un PDF
def add_signature_to_pdf(file_path, signature):
    with open(file_path, 'rb') as f:
        reader = PyPDF2.PdfReader(f)
        writer = PyPDF2.PdfWriter()
        for i in range(len(reader.pages)):
            writer.add_page(reader.pages[i])
        # Añadir la firma como metadato
        metadata = reader.trailer["/Info"]
        new_metadata = {key: metadata[key] for key in metadata} if metadata else {}
        new_metadata['/AliceSignature'] = str(signature)
        writer.add_metadata(new_metadata)

        output_file_path = os.path.basename(file_path)  # Eliminar "signed_" de aquí
        with open('signed_' + output_file_path, 'wb') as f_out:
            writer.write(f_out)
    return 'signed_' + output_file_path


# Alice firma el contrato NDA.pdf
original_pdf_path = 'NDA.pdf'
pdf_hash = hash_pdf(original_pdf_path)
alice_signature = sign_document(pdf_hash, alice_private_key)

# Alice añade su firma al PDF y lo envía a AC
signed_pdf_path = add_signature_to_pdf(original_pdf_path, alice_signature)


print("-----------------------------------------------------------------")
print("Ejercicio 2")
print("-----------------------------------------------------------------")
# La AC verifica la firma de Alice
if verify_signature(alice_public_key, alice_signature, pdf_hash):
    print("La firma de Alice es válida.")
    print("-----------------------------------------------------------------")
    # AC firma el documento con su clave privada
    ac_signature = sign_document(pdf_hash, ac_private_key)
    # Añadir la firma de la AC al PDF
    ac_signed_pdf_path = add_signature_to_pdf(signed_pdf_path, ac_signature)
    print("La AC ha firmado el documento.")
    print("-----------------------------------------------------------------")
else:
    print("La firma de Alice NO es válida.")
    print("-----------------------------------------------------------------")
if verify_signature(ac_public_key, ac_signature, pdf_hash):
    print("La firma AC es válida.")
    print("-----------------------------------------------------------------")
else:
    print("La firma AC NO es válida.")
    print("-----------------------------------------------------------------")
