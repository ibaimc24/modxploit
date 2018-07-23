from system.core import Modbus
from system.core.Modbus import Results
import sys


def main():
    global ip
    global port
    cnx = Modbus.connect_to_target(ip, port)
    if cnx:
        print("Connected to " + str(ip))
        results = Results()
        Modbus.get_supported_function_codes(cnx, results)
        Modbus.get_coils_addresses(cnx, results)
        Modbus.get_discrete_inputs_addresses(cnx, results)
        Modbus.get_holding_registers_addresses(cnx, results)
        Modbus.get_input_registers_addresses(cnx, results)
        Modbus.close_connection_to_target(cnx)
        results.show()
    else:
        print("Connection Error")


if __name__ == "__main__":
    global ip
    global port
    ip = sys.argv[1]
    port = sys.argv[2]
    main() 
