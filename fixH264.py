# Prepare and fix h264 file for MP4box
# "MP4Box -add stream.h264 stream.mp4"

# A h264 byte stream consists of NAL units which are prefixed with a byte sequence (see section B.1.1 in [1]).
# The structure of a NAL unit is specified in section 7.3.1 in [1].
#
# An unknown number of NAL-Units are malformed with respect to the excerpt listed below.
# Additionally, the type of corruption (encoded movement, missing reference images) suggests a
# problem with the so-called "IDR pictures".
#
# "
# nal_ref_idc shall not be equal to 0 for NAL units with nal_unit_type equal to 5.
# nal_ref_idc shall be equal to 0 for all NAL units having nal_unit_type equal to 6, 9, 10, 11, or 12.
# "
# [1] https://www.itu.int/rec/T-REC-H.264-202108-I/en
# [2] https://github.com/gpac/gpac/wiki/MP4Box
# [3] https://www.videolan.org/vlc/

import hashlib
import re

#MP4Box -add stream.h264 stream.mp4

def to_str(byte_str):
    return "".join(["{:02x}".format(b) for b in byte_str])


def get_nal_type(nal):
    binary = bin(int(nal, 16))[2:].zfill(8)
    return int(binary[3:], 2)

def get_ref_idc(nal):
    binary = bin(int(nal, 16))[2:].zfill(8)
    return int(binary[1:3], 2)


def checkNAL(nal, error = False):
    binary = bin(int(nal, 16))[2:].zfill(8)
    forbidden_zero = binary[0]
    if forbidden_zero != "0":
        print(f"Forbidden Zero not zero for {nal}")
        return checkNAL(hex(int(f"0{binary[1:]}", 2)), True)
    nal_ref_idc = int(binary[1:3], 2)
    nal_unit_type = int(binary[3:], 2)
    if nal_unit_type in [5, 7, 8, 13, 15] and nal_ref_idc == 0:
        print(f"Wrong IDC for {nal} with type {nal_unit_type}")
        ret = False, f"001{binary[4:]}"
    if nal_unit_type in [6, 9, 10, 11, 12] and nal_ref_idc != 0:
        print(f"Wrong IDC for {nal} with type {nal_unit_type}")
        return False, f"000{binary[4:]}"
    if error:
        return False, binary
    return True, None


def findNALs(filename):
    with open(filename, "rb", ) as mp4_file:
        myline = mp4_file.read()
        formatted_str = to_str(myline)
        correct = 0
        wrong = 0
        for m in re.finditer('[^0](0{5}|0{7})1(..)', formatted_str):
            #if m.end() % 2 != 0:
            #    continue
            passed, correction = checkNAL(m.group(2))
            if passed:
                print(f"{m.group(0)[1:]}: {get_nal_type(m.group(2))} - {get_ref_idc(m.group(2))}")
                correct += 1
            else:
                print(f"NAL: {m.group(0)[1:]} @ {m.start()} should be {m.group(0)[1:-2]}{hex(int(correction, 2))}")
                print()
                wrong += 1

        print(f"Correct: {correct}")
        print(f"Wrong: {wrong}")


def replace_error_nals(filename, target_filename):
    with open(target_filename, "wb") as output:
        with open(filename, "rb", ) as mp4_file:
            myline = mp4_file.read()
            formatted_str = to_str(myline)
            corrected = re.sub(r'(0{5,7}1)6a', r"\g<1>0a", formatted_str)
            output.write(bytearray.fromhex(corrected))

#[^0](0{5}|0{7})1(..)

def matthias():
    filename = "stream.h264"
    sha1_hash = "0f8ef8f4956ac57b7a84c0b6273fb7bfdc9ed96f"  # valid SHA1 for stream.h264

    m = hashlib.sha1()

    with open("gen_stream.h264", "wb") as output:

        start_found = False
        with open(filename, "rb", ) as mp4_file:
            myline = mp4_file.read(16)
            while myline:
                m.update(myline)
                formatted_str = to_str(myline)
                blocks_of_four = [formatted_str[i:i + 4] for i in range(0, len(formatted_str), 4)]

                for block in blocks_of_four:
                    if start_found:
                        print(f"{block} ")

                    if "0000" in block:
                        start_found = True

                output.write(myline)
                myline = mp4_file.read(16)

        calculated_hash = m.digest()
        print(to_str(calculated_hash))

        if sha1_hash == calculated_hash:
            print("Success")
        else:
            print("Fail")


def find_type_5(filename):
    return


if __name__ == '__main__':
    filename = "stream.h264"
    findNALs("stream.h264")
    #replace_error_nals(filename, f"1_{filename}")



