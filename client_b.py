import socket
import rsa
import des

def register_with_pka(identifier, public_key):
    host = socket.gethostname()
    port = 6060

    with socket.socket() as pka_socket:
        pka_socket.connect((host, port))
        message = f"REGISTER;{identifier};{public_key[0]},{public_key[1]}"
        pka_socket.sendall(message.encode())
        response = pka_socket.recv(1024).decode('utf-8')
        status, pka_public_key = response.split(';')
        e, N = map(int, pka_public_key.split(','))
        print(f"🔒 Received PKA public key: (e={e}, N={N})")
        return status, (e, N)

def request_key_from_pka(identifier, pka_public_key):
    host = socket.gethostname()
    port = 6060

    with socket.socket() as pka_socket:
        pka_socket.connect((host, port))
        message = f"REQUEST;{identifier};"
        pka_socket.sendall(message.encode())
        encrypted_response = pka_socket.recv(1024).decode('utf-8')
        print(f"🔒 Received encrypted public key for {identifier}: {encrypted_response}")
        encrypted_key = [int(x) for x in encrypted_response.split(',')]
        decrypted_key = rsa.decrypt_rsa(encrypted_key, pka_public_key[0], pka_public_key[1])
        print(f"🔓 Decrypted public key for {identifier}: {decrypted_key}")
        return decrypted_key

def B_program():
    host = socket.gethostname()
    port = 5050

    # Generate RSA keys for B
    (public_key, private_key) = rsa.generate_keys(bits=16)
    print(f"🔑 B RSA Public Key: (e={public_key[0]}, N={public_key[1]})")
    print(f"🔒 B RSA Private Key: (d={private_key[0]}, N={private_key[1]})\n")

    # Register public key with PKA
    status, pka_public_key = register_with_pka("B", public_key)
    print(f"✅ Registered with PKA: {status}\n")

    # Request A's public key from PKA
    a_public_key = request_key_from_pka("A", pka_public_key)
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
    print(f"🔒 Encrypted DES key to send: {encrypted_des_key}")
    B_socket.sendall(encrypted_des_key.encode())
    print(f"✅ Sent encrypted DES key to A.\n")

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
