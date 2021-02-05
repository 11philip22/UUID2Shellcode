""""partially stolen from https://blog.sunggwanchoi.com/eng-uuid-shellcode-execution/"""
import sys
import uuid


def convert_to_uuid(shellcode):
    # If shellcode is not in multiples of 16, then add some nullbytes at the end
    if len(shellcode) % 16 != 0:
        print("[-] Shellcode's length not multiplies of 16 bytes")
        print("[-] Adding nullbytes at the end of shellcode, this might break your shellcode.")
        print("\n[*] Modified shellcode length: ", len(shellcode) + (16 - (len(shellcode) % 16)))

        add_nullbyte = b"\x00" * (16 - (len(shellcode) % 16))
        shellcode += add_nullbyte

    uuids = []
    for i in range(0, len(shellcode), 16):
        uuid_string = str(uuid.UUID(bytes_le=shellcode[i:i + 16]))
        uuids.append('"' + uuid_string + '"')

    return uuids


def main(file_path):
    with open(file_path, 'rb') as bin_file:
        byte_arr_file = bytearray(bin_file.read())
        uuids = convert_to_uuid(bytes(byte_arr_file))
        print(*uuids, sep=",\n")


if __name__ == "__main__":
    # bin_file_path = sys.argv[1]
    bin_file_path = 'C:\\Users\\Philip\\source\\repos\\11philip22\\DllShellSimple\\Release\\DllShellSimple.bin'
    main(bin_file_path)
