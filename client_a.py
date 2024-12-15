import socket
import rsa
import des
import random

def generate_random_nonce():
    return random.randint(100000, 999999)

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
        print(f"\U0001F512 Received PKA public key: (e={e}, N={N})")
        return status, (e, N)

def request_key_from_pka(identifier, pka_public_key):
    host = socket.gethostname()
    port = 6060

    with socket.socket() as pka_socket:
        pka_socket.connect((host, port))
        message = f"REQUEST;{identifier};"
        pka_socket.sendall(message.encode())
        encrypted_response = pka_socket.recv(1024).decode('utf-8')
        print(f"\U0001F512 Received encrypted public key for {identifier}: {encrypted_response}")
        encrypted_key = [int(x) for x in encrypted_response.split(',')]
        decrypted_key = rsa.decrypt_rsa(encrypted_key, pka_public_key[0], pka_public_key[1])
        print(f"\U0001F513 Decrypted public key for {identifier}: {decrypted_key}")
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
    print(f"\U0001F511 A RSA Public Key: (e={public_key[0]}, N={public_key[1]})")
    print(f"\U0001F512 A RSA Private Key: (d={private_key[0]}, N={private_key[1]})\n")

    # Register public key with PKA
    status, pka_public_key = register_with_pka("A", public_key)
    print(f"\u2705 Registered with PKA: {status}\n")

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

    # Step 1: Generate and send nonce N1 to B
    N1 = generate_random_nonce()
    handshake_message = f"A;{N1}"
    encrypted_handshake_message = rsa.encrypt_rsa(handshake_message, b_e, b_N)
    conn.sendall(",".join(map(str, encrypted_handshake_message)).encode())

    print(f"\U0001F512 Sent handshake message (N1): {N1}\n")

    # Step 2: Receive and validate N1 and N2 from B
    encrypted_response = conn.recv(1024).decode('utf-8')
    decrypted_response = rsa.decrypt_rsa([int(x) for x in encrypted_response.split(',')], private_key[0], private_key[1])
    received_N1, N2 = map(int, decrypted_response.split(';'))

    if received_N1 != N1:
        print("\u274C Handshake failed: N1 mismatch.")
        conn.close()
        return

    print(f"\u2705 Received N1={received_N1}, N2={N2}\n")

    # Step 3: Send back N2 to B for final handshake verification
    handshake_final = f"{N2}"
    encrypted_handshake_final = rsa.encrypt_rsa(handshake_final, b_e, b_N)
    conn.sendall(",".join(map(str, encrypted_handshake_final)).encode())
    print(f"\U0001F512 Sent second handshake message (N2): {handshake_final}\n")

    # Step 4: Receive encrypted DES key
    encrypted_des_key = conn.recv(1024).decode('utf-8')
    print(f"🔒 Received double-encrypted DES key: {encrypted_des_key}")

    # Step 4.1: Decrypt with A's private key
    decrypted_once = rsa.decrypt_rsa(
        [int(x) for x in encrypted_des_key.split(',')], private_key[0], private_key[1]
    )
    print(f"🔓 DES key after decrypting with A's private key: {decrypted_once}")

    # Step 4.2: Decrypt with B's public key
    decrypted_twice = rsa.decrypt_rsa(
        [int(x) for x in decrypted_once.split(',')], b_e, b_N
    )
    des_key = decrypted_twice
    print(f"🔓 Fully decrypted DES key: {des_key}\n")

    while True:
        data = conn.recv(1024)
        if not data:
            break
        encrypted_message = data.decode('utf-8')
        print(f"\u2709\uFE0F  Received from B (encrypted hex): {encrypted_message}")

        decrypted_message = des.decrypt_message(des_key, encrypted_message)
        print(f"\U0001F513 Decrypted message from B: {decrypted_message}\n")

        message_to_send = input("\u27A1\uFE0F  Send message to B: ")
        encrypted_response = des.encrypt_message(des_key, message_to_send)
        print(f"\U0001F512 Encrypted message to send (hex): {encrypted_response}\n")
        conn.sendall(encrypted_response.encode())

    conn.close()

if __name__ == '__main__':
    A_program()
