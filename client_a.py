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

def A_program():
    host = socket.gethostname()
    port = 5050

    A_socket = socket.socket()
    A_socket.bind((host, port))
    A_socket.listen(1)
    print(f"A listening on {host}:{port}...")

    # Generate RSA keys
    (public_key, private_key) = rsa.generate_keys(bits=16)
    print(f"🔑 A RSA Public Key: (e={public_key[0]}, N={public_key[1]})")
    print(f"🔒 A RSA Private Key: (d={private_key[0]}, N={private_key[1]})\n")

    # Register public key with PKA
    status, pka_public_key = register_with_pka("A", public_key)
    print(f"✅ Registered with PKA: {status}\n")

    print("Waiting for connection...")
    conn, addr = A_socket.accept()
    print(f"Got connection from: {addr}\n")

    # Request B's public key from PKA
    b_public_key = request_key_from_pka("B", pka_public_key)
    if b_public_key == "NOT_FOUND":
        print("B's public key not found in PKA.\n")
        conn.close()
        return

    b_e, b_N = map(int, b_public_key.split(','))
    print(f"Received B's public key from PKA: (e={b_e}, N={b_N})\n")

    # Receive encrypted DES key
    encrypted_des_key = conn.recv(1024).decode('utf-8')
    print(f"🔒 Received encrypted DES key: {encrypted_des_key}\n")
    des_key = rsa.decrypt_rsa([int(x) for x in encrypted_des_key.split(',')], private_key[0], private_key[1])
    print(f"🔓 Decrypted DES key: {des_key}\n")

    while True:
        data = conn.recv(1024)
        if not data:
            break
        encrypted_message = data.decode('utf-8')
        print(f"✉️  Received from B (encrypted hex): {encrypted_message}")

        decrypted_message = des.decrypt_message(des_key, encrypted_message)
        print(f"🔓 Decrypted message from B: {decrypted_message}\n")

        message_to_send = input("➡️  Send message to B: ")
        encrypted_response = des.encrypt_message(des_key, message_to_send)
        print(f"🔒 Encrypted message to send (hex): {encrypted_response}\n")
        conn.sendall(encrypted_response.encode())

    conn.close()

if __name__ == '__main__':
    A_program()
