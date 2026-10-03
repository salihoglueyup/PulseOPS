import socket
from typing import Optional
from models.ports import ListeningPort

def is_port_bindable(port: int, host: str = "127.0.0.1") -> bool:
    """Checks if a TCP port can be bound locally without errors."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except OSError:
        return False

def find_available_ports(
    listening_ports: list[ListeningPort],
    start_port: int = 3000,
    end_port: int = 3999,
    limit: int = 5,
    verify_socket: bool = True
) -> list[int]:
    """Finds next available free ports in a given range."""
    used_set = {p.port for p in listening_ports}
    available: list[int] = []

    for port in range(start_port, end_port + 1):
        if port in used_set:
            continue
            
        if verify_socket and not is_port_bindable(port):
            continue
            
        available.append(port)
        if len(available) >= limit:
            break

    return available
