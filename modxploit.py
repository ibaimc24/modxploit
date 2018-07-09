from system.core import Modbus
import sys


def main():
    global ip
    global port

    cnx = Modbus.connect_to_target(ip, port)
    print("Connected to " + str(ip))
    Modbus.get_supported_function_codes(cnx)
    Modbus.get_registered_addresses(cnx)
    Modbus.close_connection_to_target(cnx)


if __name__ == "__main__":
    global ip
    global port
    ip = sys.argv[1]
    port = sys.argv[2]
    main()
