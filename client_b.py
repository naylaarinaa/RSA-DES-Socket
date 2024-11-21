import socket
import des
import rsa

def register_with_pka(identifier, public_key):
    host = socket.gethostname()
    port = 6060

    with socket.socket() as pka_socket:
        pka_socket.connect((host, port))
        message = f"REGISTER;{identifier};{public_key[0]},{public_key[1]}"
        pka_socket.sendall(message.encode())
        response = pka_socket.recv(1024).decode('utf-8')
        return response

def request_key_from_pka(identifier):
    host = socket.gethostname()
    port = 6060

    with socket.socket() as pka_socket:
        pka_socket.connect((host, port))
        message = f"REQUEST;{identifier};"
        pka_socket.sendall(message.encode())
        response = pka_socket.recv(1024).decode('utf-8')
        return response

def B_program():
    host = socket.gethostname()
    port = 5050

    # Generate RSA keys for B
    (B_public_key, B_private_key) = rsa.generate_keys(bits=32)
    print(f"🔑 B RSA Public Key: (e={B_public_key[0]}, N={B_public_key[1]})")
    print(f"🔒 B RSA Private Key: (d={B_private_key[0]}, N={B_private_key[1]})\n")

    # Register public key with PKA
    register_with_pka("B", B_public_key)
    print("Registered public key with PKA.\n")

    # Request A's public key from PKA
    a_public_key = request_key_from_pka("A")
    if a_public_key == "NOT_FOUND":
        print("A's public key not found in PKA.\n")
        return

    e, N = map(int, a_public_key.split(','))
    print(f"Received A's public key from PKA: (e={e}, N={N})\n")

    # Create a socket to connect to A
    B_socket = socket.socket()
    B_socket.connect((host, port))
    print(f"Connected to A at {host}:{port}\n")

    # Generate DES key
    des_key = "ABCD1234"
    print(f"🔑 DES key: {des_key}")

    # Encrypt DES key using RSA
    encrypted_des_key = ','.join(map(str, rsa.encrypt_rsa(des_key, e, N)))
    B_socket.sendall(encrypted_des_key.encode())
    print(f"🔑 Sent encrypted DES key to A: {encrypted_des_key}\n")

    while True:
        message_to_send = input("➡️  Send message to A: ")
        if message_to_send.lower().strip() == 'bye':
            break

        encrypted_message = des.encrypt_message(des_key, message_to_send)
        print(f"🔒 Encrypted message (hex): {encrypted_message}\n")
        B_socket.sendall(encrypted_message.encode())

        data = B_socket.recv(1024)
        if not data:
            break
        encrypted_response = data.decode('utf-8')
        print(f"✉️  Received from A (encrypted hex): {encrypted_response}")

        decrypted_response = des.decrypt_message(des_key, encrypted_response)
        print(f"🔓 Decrypted message from A: {decrypted_response}\n")

    B_socket.close()

if __name__ == '__main__':
    B_program()
