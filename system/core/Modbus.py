from scapy.all import *
import binascii

# own constant definitions
transId = 1
connection = None
timeout = 5
modport = 502

function_code_name = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Multiple Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Holding Register",
    7: "Read Exception Status",
    8: "Diagnostic",
    11: "Get Com Event Counter",
    12: "Get Com Event Log",
    15: "Write Multiple Coils",
    16: "Write Multiple Holding Registers",
    17: "Report Slave ID",
    20: "Read File Record",
    21: "Write File Record",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    24: "Read FIFO Queue",
    43: "Read Device Identification"}

_modbus_exceptions = {
    1: "Illegal function",
    2: "Illegal data address",
    3: "Illegal data value",
    4: "Slave device failure",
    5: "Acknowledge",
    6: "Slave device busy",
    8: "Memory parity error",
    10: "Gateway path unavailable",
    11: "Gateway target device failed to respond"}


class ModbusADU(Packet):

    name = "ModbusADU"
    fields_desc = [

        # needs to be unique
        XShortField("transId", 0x0000),

        # needs to be zero (Modbus)
        XShortField("protoId", 0x0000),

        # is calculated with payload
        XShortField("len", None),

        # 0xFF or 0x00 should be used for Modbus over TCP/IP
        XByteField("unitId", 0x0)
    ]

    def guess_payload_type(self, payload):
        # First byte of the payload is Modbus function code (254 available function codes)
        function_code = int(payload[0].encode("hex"), 16)

        if function_code == 0x01:
            return ModbusPDU01ReadCoils
        elif function_code == 0x81:
            return ModbusPDU01ReadCoilsException

        elif function_code == 0x02:
            return ModbusPDU02ReadDiscreteInputs
        elif function_code == 0x82:
            return ModbusPDU02ReadDiscreteInputsException

        elif function_code == 0x03:
            return ModbusPDU03ReadHoldingRegisters
        elif function_code == 0x83:
            return ModbusPDU03ReadHoldingRegistersException

        elif function_code == 0x04:
            return ModbusPDU04ReadInputRegisters
        elif function_code == 0x84:
            return ModbusPDU04ReadInputRegistersException

        elif function_code == 0x05:
            return ModbusPDU05WriteSingleCoil

        elif function_code == 0x85:
            return ModbusPDU05WriteSingleCoilException

        elif function_code == 0x06:
            return ModbusPDU06WriteSingleRegister
        elif function_code == 0x86:
            return ModbusPDU06WriteSingleRegisterException

        elif function_code == 0x07:
            return ModbusPDU07ReadExceptionStatus
        elif function_code == 0x87:
            return ModbusPDU07ReadExceptionStatusException

        elif function_code == 0x0F:
            return ModbusPDU0FWriteMultipleCoils
        elif function_code == 0x8F:
            return ModbusPDU0FWriteMultipleCoilsException

        elif function_code == 0x10:
            return ModbusPDU10WriteMultipleRegisters
        elif function_code == 0x90:
            return ModbusPDU10WriteMultipleRegistersException

        elif function_code == 0x11:
            return ModbusPDU11ReportSlaveId
        elif function_code == 0x91:
            return ModbusPDU11ReportSlaveIdException

        else:
            return Packet.guess_payload_class(self, payload)


# Can be used to replace all Modbus read
class ModbusPDUReadGeneric(Packet):
    name = "Read Generic"
    fields_desc = [
        XByteField("funcCode", 0x01),
        XShortField("startAddr", 0x0000),
        XShortField("quantity", 0x0001)
    ]


# 0x01 - Read Coils
class ModbusPDU01ReadCoils(Packet):
    name = "Read Coils Request"
    fields_desc = [
        XByteField("funcCode", 0x01),
        # 0x0000 to 0xFFFF
        XShortField("startAddr", 0x0000),
        XShortField("quantity", 0x0001)
    ]


class ModbusPDU01ReadCoilsAnswer(Packet):
    name = "Read Coils Answer"
    fields_desc = [
        XByteField("funcCode", 0x01),
        BitFieldLenField("byteCount", None, 8, count_of="coilStatus"),
        FieldListField("coilStatus", [0x00], ByteField("", 0x00), count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU01ReadCoilsException(Packet):
    name = "Read Coils Exception"
    fields_desc = [
        XByteField("funcCode", 0x81),
        ByteEnumField("exceptCode", 1, _modbus_exceptions)]


# 0x02 - Read Discrete Inputs
class ModbusPDU02ReadDiscreteInputs(Packet):
    name = "Read Discrete Inputs"
    fields_desc = [
        XByteField("funcCode", 0x02),
        XShortField("startAddr", 0x0000),
        XShortField("quantity", 0x0001)]


class ModbusPDU02ReadDiscreteInputsAnswer(Packet):
    name = "Read Discrete Inputs Answer"
    fields_desc = [
        XByteField("funcCode", 0x02),
        BitFieldLenField("byteCount", None, 8, count_of="inputStatus"),
        FieldListField("inputStatus", [0x00], ByteField("", 0x00), count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU02ReadDiscreteInputsException(Packet):
    name = "Read Discrete Inputs Exception"
    fields_desc = [
        XByteField("funcCode", 0x82),
        ByteEnumField("exceptCode", 1, _modbus_exceptions)]


# 0x03 - Read Holding Registers
class ModbusPDU03ReadHoldingRegisters(Packet):
    name = "Read Holding Registers"
    fields_desc = [
        XByteField("funcCode", 0x03),
        XShortField("startAddr", 0x0001),

        # Quantity of 16 bit registers
        XShortField("quantity", 0x0002)]


class ModbusPDU03ReadHoldingRegistersAnswer(Packet):
    name = "Read Holding Registers Answer"
    fields_desc = [
        XByteField("funcCode", 0x03),
        BitFieldLenField("byteCount", None, 8, count_of="registerVal"),
        FieldListField("registerVal", [0x00], ByteField("", 0x00), count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU03ReadHoldingRegistersException(Packet):
    name = "Read Holding Registers Exception"
    fields_desc = [
        XByteField("funcCode", 0x83),
        ByteEnumField("exceptCode", 1, _modbus_exceptions)]


# 0x04 - Read Input Registers
class ModbusPDU04ReadInputRegisters(Packet):
    name = "Read Input Registers"
    fields_desc = [
        XByteField("funcCode", 0x04),
        XShortField("startAddr", 0x0000),
        XShortField("quantity", 0x0001)]


class ModbusPDU04ReadInputRegistersAnswer(Packet):
    name = "Read Input Registers Answer"
    fields_desc = [
        XByteField("funcCode", 0x04),
        BitFieldLenField("byteCount", None, 8, count_of="registerVal"),
        FieldListField("registerVal", [0x00], ByteField("", 0x00), count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU04ReadInputRegistersException(Packet):
    name = "Read Input Registers Exception"
    fields_desc = [
        XByteField("funcCode", 0x84),
        ByteEnumField("exceptCode", 1, _modbus_exceptions)]


# 0x05 - Write Single Coil
class ModbusPDU05WriteSingleCoil(Packet):
    name = "Write Single Coil"
    fields_desc = [
        XByteField("funcCode", 0x05),
        XShortField("outputAddr", 0x0000),   # from 0x0000 to 0xFFFF
        XShortField("outputValue", 0x0000)]  # 0x0000 == Off, 0xFF00 == On


class ModbusPDU05WriteSingleCoilAnswer(Packet):  # The answer is the same as the request if successful
    name = "Write Single Coil"
    fields_desc = [
        XByteField("funcCode", 0x05),
        XShortField("outputAddr", 0x0000),   # from 0x0000 to 0xFFFF
        XShortField("outputValue", 0x0000)]  # 0x0000 == Off, 0xFF00 == On


class ModbusPDU05WriteSingleCoilException(Packet):
    name = "Write Single Coil Exception"
    fields_desc = [
        XByteField("funcCode", 0x85),
        ByteEnumField("exceptCode", 1, _modbus_exceptions)]


# 0x06 - Write Single Register
class ModbusPDU06WriteSingleRegister(Packet):
    name = "Write Single Register"
    fields_desc = [
        XByteField("funcCode", 0x06),
        XShortField("registerAddr", 0x0000),
        XShortField("registerValue", 0x0000)]


class ModbusPDU06WriteSingleRegisterAnswer(Packet):

    name = "Write Single Register Answer"
    fields_desc = [
        XByteField("funcCode", 0x06),
        XShortField("registerAddr", 0x0000),
        XShortField("registerValue", 0x0000)]


class ModbusPDU06WriteSingleRegisterException(Packet):
    name = "Write Single Register Exception"
    fields_desc = [
        XByteField("funcCode", 0x86),
        ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusPDU08Diagnostics(Packet):
    name = "Diagnostics"
    fields_desc = [
        XByteField("funcCode", 0x08),
        XShortField("subFunction", 0x0000),
        XShortField("data", 0x0000)]


# 0x07 - Read Exception Status (Serial Line Only)
class ModbusPDU07ReadExceptionStatus(Packet):
    name = "Read Exception Status"
    fields_desc = [XByteField("funcCode", 0x07)]


class ModbusPDU07ReadExceptionStatusAnswer(Packet):
    name = "Read Exception Status Answer"
    fields_desc = [
        XByteField("funcCode", 0x07),
        XByteField("startingAddr", 0x00)]


class ModbusPDU07ReadExceptionStatusException(Packet):
    name = "Read Exception Status Exception"
    fields_desc = [
        XByteField("funcCode", 0x87),
        ByteEnumField("exceptCode", 1, _modbus_exceptions)]


# 0x0F - Write Multiple Coils
class ModbusPDU0FWriteMultipleCoils(Packet):
    name = "Write Multiple Coils"
    fields_desc = [
        XByteField("funcCode", 0x0F),
        XShortField("startingAddr", 0x0000),
        XShortField("quantityOutput", 0x0001),
        BitFieldLenField("byteCount", None, 8, count_of="outputsValue", adjust=lambda pkt, x:x),
        FieldListField("outputsValue", [0x00], XByteField("", 0x00), count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU0FWriteMultipleCoilsAnswer(Packet):
    name = "Write Multiple Coils Answer"
    fields_desc = [
        XByteField("funcCode", 0x0F),
        XShortField("startingAddr", 0x0000),
        XShortField("quantityOutput", 0x0001)]


class ModbusPDU0FWriteMultipleCoilsException(Packet):
    name = "Write Multiple Coils Exception"
    fields_desc = [
        XByteField("funcCode", 0x8F),
        ByteEnumField("exceptCode", 1, _modbus_exceptions)]


# 0x10 - Write Multiple Registers
class ModbusPDU10WriteMultipleRegisters(Packet):
    name = "Write Multiple Registers"
    fields_desc = [
        XByteField("funcCode", 0x10),
        XShortField("startingAddr", 0x0000),
        XShortField("quantityRegisters", 0x0001),
        BitFieldLenField("byteCount", None, 8, count_of="outputsValue", adjust=lambda pkt, x:x),
        FieldListField("outputsValue", [0x00], XByteField("", 0x00), count_from=lambda pkt: pkt.byteCount)]


class ModbusPDU10WriteMultipleRegistersAnswer(Packet):
    name = "Write Multiple Registers Answer"
    fields_desc = [
        XByteField("funcCode", 0x10),
        XShortField("startingAddr", 0x0000),
        XShortField("quantityRegisters", 0x0001)]


class ModbusPDU24ReadFIFOQueue(Packet):
    name = "Read FIFO Queue"
    fields_desc = [
        XByteField("funcCode", 0x18),
        XShortField("pointerAddr", 0x0000)]


class ModbusPDU10WriteMultipleRegistersException(Packet):
    name = "Write Multiple Registers Exception"
    fields_desc = [
        XByteField("funcCode", 0x90),
        ByteEnumField("exceptCode", 1, _modbus_exceptions)]


# 0x11 - Report Slave Id
class ModbusPDU11ReportSlaveId(Packet):
    name = "Report Slave Id"
    fields_desc = [XByteField("funcCode", 0x11)]


class ModbusPDU11ReportSlaveIdAnswer(Packet):
    name = "Report Slave Id Answer"
    fields_desc = [
        XByteField("funcCode", 0x11),
        BitFieldLenField("byteCount", None, 8, length_of="slaveId"),
        ConditionalField(StrLenField("slaveId", "", length_from=lambda pkt: pkt.byteCount),
                         lambda pkt: pkt.byteCount > 0),
        ConditionalField(XByteField("runIdicatorStatus", 0x00), lambda pkt: pkt.byteCount > 0)]


class ModbusPDU11ReportSlaveIdException(Packet):
    name = "Report Slave Id Exception"
    fields_desc = [
        XByteField("funcCode", 0x91),
        ByteEnumField("exceptCode", 1, _modbus_exceptions)]


def connect_to_target(ip="127.0.0.1", port=502):
    try:
        global connection
        s = socket.socket()
        s.connect((ip, int(port)))
        connection = StreamSocket(s, Raw)
        return connection
    except Exception:
        print("Connection unsuccessful due to the following error :")
        return None


def close_connection_to_target(c):
    global connection
    connection = c
    connection.close()
    connection = None


def test_modbus(cnx):
    if not cnx:
        return "Connection needs to be established first."

    for i in range(50):
        pkt = ModbusADU()/ModbusPDUReadGeneric(funcCode=i, quantity=6)
        pkt.len = len(pkt.payload)
        ans = cnx.sr1(pkt, timeout=timeout, verbose=0)

        if ans:
            # Hex encoded string
            data2 = binascii.hexlify(bytes(ans))
            return_code = int(data2[14:16], 16)
            exception_code = int(data2[17:18], 16)
            if return_code > 127 and exception_code == 0x01:
                # If return function code is > 128 --> error code
                print("Function Code "+str(i)+" not supported.")
            else:
                print("Diagnostics Code "+str(i)+" is supported.")
        else:
            print("Diagnostics Code "+str(i)+" probably supported.")


def get_supported_function_codes(cnx, results):

    supported_codes = []
    print("[*] Looking for supported function codes... From 1 to 127")
    for i in range(1, 127):
        pkt = ModbusADU() / ModbusPDUReadGeneric(funcCode=i, quantity=6)
        pkt.len = len(pkt.payload) + 1
        try:
            ans = cnx.sr1(pkt, timeout=timeout, verbose=0)
        except OSError:
            print("OSError detected with %d" % i)
            continue
        if ans:
            # Hex encoded string
            data = binascii.hexlify(bytes(ans))
            return_code = int(data[14:16], 16)
            exception_code = int(data[17:18], 16)
            if return_code is i or (return_code is i+128 and exception_code is not 1):
                #print("[*] " + str(i) + " Supported.")
                results.add_function(i)
                #supported_codes.append(i)
            else:
                pass
        else:
            print("%d no answer" % i)
    #print(supported_codes)
    return supported_codes


def get_coils_addresses(cnx, results):
    readable_addrs = []
    blocks = []
    start_in = 0
    flag = False
    print("[*] Looking for supported address' in ReadCoils function. From 0 to 65.534")
    for i in range(0, 65534):
        pkt = ModbusADU() / ModbusPDU01ReadCoils(startAddr=i, quantity=1)
        pkt.len = len(pkt.payload) + 1
        try:
            ans = cnx.sr1(pkt, timeout=timeout, verbose=0)
        except OSError:
            print("OSError detected with %d" % i)
            continue
        if ans:
            # Hex encoded string
            data = binascii.hexlify(bytes(ans))
            return_code = int(data[14:16], 16)

            if return_code is 1 and not flag:
                print("[i] Found")
                # Start of a readable block
                start_in = i
                readable_addrs.append(i)
                flag = True

            elif return_code is 1 and flag:
                # Continuation of a readable block
                readable_addrs.append(i)

            elif return_code is not 1 and flag is True:
                print("[i] Found last")
                # End of a readable block
                ends_in = i - 1
                flag = False
                print("[*] Found a readable block from %d to %d" % (start_in, ends_in))
                blocks.append((start_in, ends_in))
            else:
                pass

    results.add("COILS", blocks)
    return readable_addrs


def get_discrete_inputs_addresses(cnx, results):
    readable_addrs = []
    blocks = []
    flag = False
    start_in = 0
    print("[*] Looking for supported address' in DiscreteInputs function. From 0 to 65.534")
    for i in range(0, 65534):
        pkt = ModbusADU() / ModbusPDU02ReadDiscreteInputs(startAddr=i, quantity=1)
        pkt.len = len(pkt.payload) + 1
        ans = cnx.sr1(pkt, timeout=timeout, verbose=0)
        if ans:
            # Hex encoded string
            data = binascii.hexlify(bytes(ans))
            return_code = int(data[14:16], 16)
            if return_code is 2 and not flag:
                # Start of a readable block
                start_in = i
                readable_addrs.append(i)
                flag = True

            elif return_code is 2 and flag:
                # Continuation of a readable block
                readable_addrs.append(i)

            elif flag:
                # End of a readable block
                ends_in = i - 1
                flag = False
                print("[*] Found a readable block from %d to %d" % (start_in, ends_in))
                blocks.append((start_in, ends_in))
            else:
                pass

    results.add("DISCRETE INPUTS", blocks)
    return blocks, readable_addrs

def get_holding_registers_addresses(cnx, results):
    readable_addrs = []
    blocks = []
    flag = False
    start_in = 0
    ends_in = 0
    print("[*] Looking for supported address' in HoldingRegsiters function. From 0 to 4095")
    # TODO: Done to 65535. Expected an exception from 4095 to 65535
    for i in range(0, 65535):
        pkt = ModbusADU() / ModbusPDU03ReadHoldingRegisters(startAddr=i, quantity=1)
        pkt.len = len(pkt.payload) + 1
        ans = cnx.sr1(pkt, timeout=timeout, verbose=0)
        if ans:
            # Hex encoded string
            data = binascii.hexlify(bytes(ans))
            return_code = int(data[14:16], 16)
            if return_code is 3 and not flag:
                # Start of a readable block
                start_in = i
                readable_addrs.append(i)
                flag = True

            elif return_code is 3 and flag:
                # Continuation of a readable block
                readable_addrs.append(i)

            elif flag:
                # End of a readable block
                ends_in = i - 1
                flag = False
                print("[*] Found a readable block from %d to %d" % (start_in, ends_in))
                blocks.append((start_in, ends_in))
            else:
                pass

    results.add("HOLDING REGISTERS", blocks)
    return blocks, readable_addrs


def get_input_registers_addresses(cnx, results):
    readable_addrs = []
    blocks = []
    flag = False
    start_in = 0
    ends_in = 0
    print("[*] Looking for supported address' in InputRegsiters function. From 0 to 4095")
    # TODO: Done to 65535. Expected an exception from 4095 to 65535
    for i in range(0, 65535):
        pkt = ModbusADU() / ModbusPDU04ReadInputRegisters(startAddr=i, quantity=1)
        pkt.len = len(pkt.payload) + 1
        ans = cnx.sr1(pkt, timeout=timeout, verbose=0)
        if ans:
            # Hex encoded string
            data = binascii.hexlify(bytes(ans))
            return_code = int(data[14:16], 16)
            if return_code is 4 and not flag:
                # Start of a readable block
                start_in = i
                readable_addrs.append(i)
                flag = True

            elif return_code is 4 and flag:
                # Continuation of a readable block
                readable_addrs.append(i)

            elif flag:
                # End of a readable block
                ends_in = i - 1
                flag = False
                print("[*] Found a readable block from %d to %d" % (start_in, ends_in))
                blocks.append((start_in, ends_in))
            else:
                pass

    results.add("INPUT REGISTERS", blocks)
    return blocks, readable_addrs


def restart_communications(cnx):
    # 0xFF00 restarts Communication event log. 0x0000 doesn't
    pkt = ModbusADU() / ModbusPDU08Diagnostics(subFunction=1, data=0xFF00)
    pkt.len = len(pkt.payload) + 1
    ans = cnx.sr1(pkt, timeout=timeout, verbose=0)
    if ans:
        # Hex encoded string
        data = binascii.hexlify(bytes(ans))
        return_code = int(data[14:16], 16)
        if return_code is 8:
            print("[*] Restarting device...")
        else:
            print('\033[41m' + "Not supported function. Could not restart" + '\033[0m')


def read_queues(cnx):
    pkt = ModbusADU() / ModbusPDU24ReadFIFOQueue(pointerAddr=0x0000)
    pkt.len = len(pkt.payload) + 1
    ans = cnx.sr1(pkt, timeout=timeout, verbose=0)
    if ans:
        # Hex encoded string
        data = binascii.hexlify(bytes(ans))
        return_code = int(data[14:16], 16)
        if return_code is 8:
            print("[*] Supported function. Looking for queues...")
            for i in range(0, 65535):
                pkt = ModbusADU() / ModbusPDU24ReadFIFOQueue(pointerAddr=0x0000)
                pkt.len = len(pkt.payload) + 1
                print(i)
                ans = cnx.sr1(pkt, timeout=timeout, verbose=0)

                data = binascii.hexlify(bytes(ans))
                return_code = int(data[14:16], 16)
                if return_code is 24:
                    try:
                        byte_count = int(data[17:21], 16)
                        fifo_count = int(data[21:25], 16)
                        if fifo_count is 0:
                            continue
                        else:
                            print("[*] Found Queue in %d register of length %d." % (i, fifo_count))
                    except Exception:
                        continue

        else:
            print('\033[41m' + "Not supported function ReadFIFOQueue." + '\033[0m')


class Results:

    SupportedFunctions = []
    Names = []

    # Each elements contains an array of tuples
    Blocks = []

    def add(self, name, block):
        self.Names.append(name)
        self.Blocks.append(block)

    def add_function(self, number):
        self.SupportedFunctions.append(number)

    def show(self):
        print(" #################################################################### ")
        print("\t SUPPORTED FUNCTION CODES")
        print("\t\t" + str(self.SupportedFunctions))
        for name, blocks in zip(self.Names, self.Blocks):
            print("\t\t"+name)
            for i in blocks:
                print("\t\tFrom \t %d \t to \t %d" % (i[0], i[1]))
        print(" #################################################################### ")