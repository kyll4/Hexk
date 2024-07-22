import sys
import struct
import socket
import subprocess
import re
from typing import Optional
from colorama import Fore, Style, init


init(autoreset=True)


k = 0xdeaddaad

def x(data: bytes) -> bytes:
    k1 = k & 0xff
    k2 = (k >> 8) & 0xff
    k3 = (k >> 16) & 0xff
    k4 = (k >> 24) & 0xff

    out = bytearray(len(data))
    for i in range(len(data)):
        tmp = data[i] ^ k1
        tmp ^= k2
        tmp ^= k3
        tmp ^= k4
        out[i] = tmp

    return bytes(out)

def h_to_d(hex_str: str, t: str) -> Optional[bytes]:
    hex_values = re.findall(r'\\x([0-9a-fA-F]{2})', hex_str)
    d = [int(hv, 16) for hv in hex_values]
    data = None

    if t == "string":
        data = bytes(d)
    elif t == "ip":
        if len(d) != 4:
            print(Fore.RED + "Longitud de datos hex de IP inválida.")
            return None
        data = struct.pack('!I', (d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3])
    elif t == "uint32":
        if len(d) != 4:
            print(Fore.RED + "Longitud de datos hex uint32 inválida.")
            return None
        data = struct.pack('!I', (d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3])
    elif t == "uint16":
        if len(d) != 2:
            print(Fore.RED + "Longitud de datos hex uint16 inválida.")
            return None
        data = struct.pack('!H', (d[0] << 8) | d[1])
    elif t == "uint8":
        if len(d) != 1:
            print(Fore.RED + "Longitud de datos hex uint8 inválida.")
            return None
        data = struct.pack('!B', d[0])
    elif t == "bool":
        if len(d) != 1:
            print(Fore.RED + "Longitud de datos hex bool inválida.")
            return None
        data = struct.pack('!B', d[0])
    else:
        print(Fore.RED + f"¡Tipo de dato `{t}` desconocido!")
        return None
    
    return data

def p_data(t: str, v: str) -> Optional[bytes]:
    if t == "hex":
        return h_to_d(v, t)
    elif t in ["string", "ip", "uint32", "uint16", "uint8", "bool"]:
        if t == "ip":
            try:
                data = struct.pack('!I', int.from_bytes(socket.inet_aton(v), 'big'))
            except socket.error:
                print(Fore.RED + "Formato de dirección IP inválido.")
                return None
        elif t == "uint32":
            data = struct.pack('!I', int(v))
        elif t == "uint16":
            data = struct.pack('!H', int(v))
        elif t == "uint8":
            data = struct.pack('!B', int(v))
        elif t == "bool":
            data = struct.pack('!B', 0 if v == "false" else 1)
        elif t == "string":
            data = v.encode('utf-8')
        else:
            print(Fore.RED + f"¡Tipo de dato `{t}` desconocido!")
            return None
        return data
    else:
        print(Fore.RED + f"¡Tipo de dato `{t}` desconocido!")
        return None

def ping(ip: str) -> bool:
    try:
        output = subprocess.check_output(['ping', '-c', '1', ip], stderr=subprocess.STDOUT, text=True)
        return '1 packets transmitted, 1 received' in output
    except subprocess.CalledProcessError:
        return False

def main():
    if len(sys.argv) != 3:
        print(Fore.RED + f"Uso: {sys.argv[0]} <string | ip | uint32 | uint16 | uint8 | bool | hex> <data>")
        return

    t = sys.argv[1]
    v = sys.argv[2]

    # Procesar los datos según el tipo
    data = p_data(t, v)
    if data is None:
        return

    print(Fore.YELLOW + f"XOR'ing {len(data)} bytes de datos...")
    r = x(data)
    print(''.join(f'\\x{byte:02X}' for byte in r))


    if t == "ip":
        ip_converted_back = socket.inet_ntoa(r)
        print(Fore.YELLOW + f"Formato binario convertido de vuelta a IP: {ip_converted_back}")


        is_up = ping(ip_converted_back)
        status = Fore.GREEN + "ON" if is_up else Fore.RED + "OFF"
        print(Fore.YELLOW + f"Estado de la IP {ip_converted_back}: {status}")


    print(Fore.YELLOW + "\nDecodificando los datos cifrados...")
    deciphered_data = x(r)
    if t == "ip":
        deciphered_ip = socket.inet_ntoa(deciphered_data)
        print(Fore.YELLOW + f"IP descifrada: {deciphered_ip}")

if __name__ == "__main__":
    main()
