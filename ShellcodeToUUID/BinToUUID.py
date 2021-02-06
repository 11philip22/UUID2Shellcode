""""partially stolen from https://blog.sunggwanchoi.com/eng-uuid-shellcode-execution/"""
import sys
import uuid

from ShellcodeToUUID import convert_to_uuid


def main(file_path):
    with open(file_path, 'rb') as bin_file:
        byte_arr_file = bytearray(bin_file.read())
        uuids = convert_to_uuid(bytes(byte_arr_file))
        print(*uuids, sep=",\n")


if __name__ == "__main__":
    # bin_file_path = sys.argv[1]
    bin_file_path = 'C:\\Users\\Philip\\source\\repos\\11philip22\\DllShellSimple\\Release\\DllShellSimple.bin'
    main(bin_file_path)
