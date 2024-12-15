import socket
import threading
import rsa  # Import rsa functions from rsa.py

class PKA:
    def __init__(self):
        self.public_keys = {}  # Dictionary to store public keys
        self.connected_clients = set()  # Track connected clients
        self.clients_connected = {'A': False, 'B': False}  # Track whether A and B are connected
        self.clients_requested = {'A': False, 'B': False}  # Track if A and B have requested each other's keys
        self.stop_event = threading.Event()  # Event to signal server stop

        # Generate RSA key pair for PKA itself
        self.pka_public_key, self.pka_private_key = rsa.generate_keys(bits=16)  # Generate small key for demonstration
        print(f"🔑 PKA Public Key: {self.pka_public_key}")
        print(f"🔒 PKA Private Key: {self.pka_private_key}")

    def handle_client(self, conn, addr):
        identifier = None  # Track which client is connecting
        try:
            data = conn.recv(1024).decode('utf-8')
            if not data:
                return

            action, identifier, key = data.split(';')

            if action == 'REGISTER':
                self.public_keys[identifier] = key
                e, N = key.split(',')
                response = f"REGISTERED;{self.pka_public_key[0]},{self.pka_public_key[1]}"
                print(f"✅ {identifier}'s public key registered.")
                print(f"🔑 {identifier}'s Public Key: (e={e}, N={N})")

                # Check if the public key matches any other client
                for other_id, other_key in self.public_keys.items():
                    if identifier != other_id and other_key == key:
                        print(f"⚠ WARNING: {identifier}'s public key matches {other_id}'s public key! (e={e}, N={N})")

            elif action == 'REQUEST':
                target_key = self.public_keys.get(identifier, "NOT_FOUND")
                if target_key == "NOT_FOUND":
                    print(f"❌ {identifier}'s public key not found.")
                    response = "NOT_FOUND"
                else:
                    print(f"🔑 {identifier}'s public key provided.")
                    encrypted_key = rsa.encrypt_rsa(target_key, self.pka_private_key[0], self.pka_private_key[1])
                    response = ','.join(map(str, encrypted_key))

            conn.sendall(response.encode())

            # Add client to the connected set
            self.connected_clients.add(identifier)
            self.clients_connected[identifier] = True  # Mark the client as connected

            # Check if both clients A and B have requested each other's keys
            if self.clients_requested['A'] and self.clients_requested['B']:
                print("✅ Both clients A and B have requested and received each other's public key.")

        except Exception as e:
            print(f"Error handling client {addr}: {e}")

    def start_server(self):
        host = socket.gethostname()
        port = 6060

        server_socket = socket.socket()
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"🏁 PKA listening on {host}:{port}...")

        try:
            while not self.stop_event.is_set():
                server_socket.settimeout(1.0)  # Adjust this timeout if necessary
                try:
                    conn, addr = server_socket.accept()
                    print(f"📞 Connection from {addr}")
                    threading.Thread(target=self.handle_client, args=(conn, addr)).start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            print("\n⚠ Server interrupted by user. Shutting down...")
        finally:
            server_socket.close()
            print("🏁 PKA server stopped.")

if __name__ == '__main__':
    pka = PKA()
    pka.start_server()
