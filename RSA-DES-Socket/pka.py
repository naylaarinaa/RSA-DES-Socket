import socket
import threading

class PKA:
    def __init__(self):
        self.public_keys = {}  # Dictionary to store public keys
        self.connected_clients = set()  # Track connected clients
        self.clients_connected = {'A': False, 'B': False}  # Track whether A and B are connected

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
                response = "REGISTERED"
                print(f"✅ {identifier}'s public key registered.")
                print(f"🔑 {identifier}'s Public Key: (e={e}, N={N})")

                # Check if the public key matches any other client
                for other_id, other_key in self.public_keys.items():
                    if identifier != other_id and other_key == key:
                        print(f"⚠️ WARNING: {identifier}'s public key matches {other_id}'s public key! (e={e}, N={N})")

            elif action == 'REQUEST':
                response = self.public_keys.get(identifier, "NOT_FOUND")
                if response == "NOT_FOUND":
                    print(f"❌ {identifier}'s public key not found.")
                else:
                    print(f"🔑 {identifier}'s public key provided.")

            conn.sendall(response.encode())

            # Add client to the connected set
            self.connected_clients.add(identifier)
            self.clients_connected[identifier] = True  # Mark the client as connected
            
            # Check if both clients A and B are connected
            if self.clients_connected['A'] and self.clients_connected['B']:
                print("✅ Both clients A and B are connected.")
                self.stop_server()  # Stop server after both are connected

        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            if identifier:
                # Remove client from connected set and mark as disconnected
                self.connected_clients.discard(identifier)
                self.clients_connected[identifier] = False  # Mark the client as disconnected
            conn.close()

    def stop_server(self):
        print("⚠️ Stopping PKA server because both clients are connected...")
        exit(0)

    def start_server(self):
        host = socket.gethostname()
        port = 6060

        server_socket = socket.socket()
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"🏁 PKA listening on {host}:{port}...")

        while True:
            conn, addr = server_socket.accept()
            print(f"📞 Connection from {addr}")
            threading.Thread(target=self.handle_client, args=(conn, addr)).start()

if __name__ == '__main__':
    pka = PKA()
    pka.start_server()
