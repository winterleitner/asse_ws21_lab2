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
#
# x264 - core 160 r3011 cde9a93 - H.264/MPEG-4 AVC codec - Copyleft 2003-2020 - http://www.videolan.org/x264.html - options:
# cabac=1 ref=5 deblock=1:0:0 analyse=0x3:0x113 me=hex subme=8 psy=1 psy_rd=1.00:0.00 mixed_ref=1 me_range=16
# chroma_me=1 trellis=2 8x8dct=1 cqm=0 deadzone=21,11 fast_pskip=1 chroma_qp_offset=-2 threads=12 lookahead_threads=2
# sliced_threads=0 nr=0 decimate=1 interlaced=0 bluray_compat=0 constrained_intra=0 bframes=3 b_pyramid=2 b_adapt=1
# b_bias=0 direct=3 weightb=1 open_gop=0 weightp=2 keyint=250 keyint_min=24 scenecut=40 intra_refresh=0 rc_lookahead=50
# rc=crf mbtree=1 crf=23.0 qcomp=0.60 qpmin=0 qpmax=69 qpstep=4 ip_ratio=1.40 aq=1:1.00

import hashlib
import re


def to_str(byte_str):
    return "".join(["{:02x}".format(b) for b in byte_str])


def get_nal_type(nal):
    """Gets the NAL type as int from a hex NAL"""
    binary = bin(int(nal, 16))[2:].zfill(8)
    return int(binary[3:], 2)


def get_ref_idc(nal):
    """Gets the ref idc as in from a hex NAL"""
    binary = bin(int(nal, 16))[2:].zfill(8)
    return int(binary[1:3], 2)


def get_forbidden_zero(nal):
    binary = bin(int(nal, 16))[2:].zfill(8)
    return binary[0:1]


def to_binary(nal):
    return bin(int(nal, 16))[2:].zfill(8)


def checkNAL(nal, error = False):
    """Checks if a hex nal is valid and returns a tuple of True|False and if false a binary suggested corrected NAL, else None"""
    binary = bin(int(nal, 16))[2:].zfill(8)
    forbidden_zero = binary[0]
    if forbidden_zero != "0":
        print(f"\nForbidden Zero not zero for {nal}")
        return checkNAL(hex(int(f"0{binary[1:]}", 2)), True)
    nal_ref_idc = int(binary[1:3], 2)
    nal_unit_type = int(binary[3:], 2)
    if nal_unit_type in (5, 7, 8, 13, 15) and nal_ref_idc == 0:
        print(f"\nWrong IDC for {nal} with type {nal_unit_type}")
        return False, f"001{binary[4:]}"
    if nal_unit_type in (6, 9, 10, 11, 12) and nal_ref_idc != 0:
        print(f"\nWrong IDC for {nal} with type {nal_unit_type}")
        return False, f"000{binary[4:]}"
    if error:
        return False, binary
    return True, None


def findNALs(filename):
    """Finds all NALs and applies correction to them."""
    with open(filename, "rb", ) as h264_file:
        myline = h264_file.read()
        formatted_str = to_str(myline)
        correct = 0
        wrong = 0
        prev = 0
        for idx, m in enumerate(re.finditer('(0{5}|0{7})1(..)', formatted_str)):
            nal_unit = m.group(2)
            passed, correction = checkNAL(nal_unit)
            all = m.group(0)[1:]

            if passed:
                if get_ref_idc(nal_unit) == 3:
                    print(
                        f"{idx}\t"
                        f"{all}\t"
                        f"NAL bin: {to_binary(nal_unit)[0:1]} {to_binary(nal_unit)[1:3]} {to_binary(nal_unit)[3:]}\t"
                        f"zero: {get_forbidden_zero(nal_unit)}\t"
                        f"ref_idc: {get_ref_idc(nal_unit)}\t"
                        f"unit_type: {get_nal_type(nal_unit)}")
                correct += 1
            else:
                if get_ref_idc(nal_unit) == 3:
                    print(
                        f"{idx}\t"
                        f"{all}\t"
                        f"NAL bin: {to_binary(nal_unit)[0:1]} {to_binary(nal_unit)[1:3]} {to_binary(nal_unit)[3:]}\t"
                        f"zero: {get_forbidden_zero(nal_unit)}\t"
                        f"ref_idc: {get_ref_idc(nal_unit)}\t"
                        f"unit_type: {get_nal_type(nal_unit)}\t Wrong")
                    print(f"NAL: {m.group(0)[1:]} @ {m.start()} should be {m.group(0)[1:-2]}{int(correction, 2):02x}")
                    print()
                wrong += 1
            prev = m.start()

        print(f"Correct: {correct}")
        print(f"Wrong: {wrong}")


def replace_error_nals(filename, target_filename):
    with open(target_filename, "wb") as output:
        with open(filename, "rb", ) as h264_file:
            myline = h264_file.read()
            formatted_str = to_str(myline)
            corrected = formatted_str

            # ToDo find proper position of IDR frames
            # corrected = nth_repl_all(corrected, "000000167", "000000165", 2)  # set IDR frames every 2nd of 67

            corrected = re.sub(r'(0{5,7}1)6a', r"\g<1>65", formatted_str)  # set as IDR frame
            # corrected = re.sub(r'(0{5,7}1)6a', r"\g<1>0a", formatted_str)
            # corrected = re.sub(r'(0{5,7}1)41', r"\g<1>45", corrected)  # unit type 2 to 5
            # corrected = re.sub(r'(0{5,7}1)67', r"\g<1>65", corrected)  # unit type 7 to 5
            # corrected = re.sub(r'(0{5,7}1)67', r"\g<1>65", corrected)  # unit type 7 to 5
            corrected = re.sub(r'(0{5,7}1)80', r"\g<1>00", corrected)  # fixes forbidden zero
            corrected = re.sub(r'(0{5,7}1)d4', r"\g<1>54", corrected)
            corrected = re.sub(r'(0{5,7}1)d8', r"\g<1>58", corrected)

            output.write(bytearray.fromhex(corrected))


def nth_repl_all(s, sub, repl, nth):
    find = s.find(sub)
    # loop util we find no match
    i = 1
    while find != -1:
        # if i is equal to nth we found nth matches so replace
        if i == nth:
            s = s[: find] + repl + s[find + len(sub): ]
            i = 0
        # find + len(sub) + 1 means we start after the last match
        find = s.find(sub, find + len(sub) + 1)
        i += 1
    return s

#[^0](0{5}|0{7})1(..)


def check_hash(filename, expected_sha1):
    m = hashlib.sha1()
    with open(filename, "rb", ) as file:
        text = file.readline()
        m.update(text)
        while text:
            text = file.readline()
            m.update(text)

    calculated_hash = m.digest()
    print(f"Calculated SHA1: {to_str(calculated_hash)}")
    print(f"Expected SHA1:   {expected_sha1}")
    if calculated_hash == expected_sha1:
        print("Success")


# no type 5 present
def find_type_5(filename):
    with open(filename, "rb") as h264_file:
        myline = h264_file.read()
        formatted_str = to_str(myline)
    for m in re.finditer('(0{5}|0{7})1(..)', formatted_str):
        passed, correction = checkNAL(m.group(2))
        if passed and get_nal_type(m.group(2)) == "5":
            print(f"{m.group(0)[1:]}: {get_nal_type(m.group(2))} - {get_ref_idc(m.group(2))}")


if __name__ == '__main__':
    source_filename = "stream.h264"
    target_filename = "gen_stream.h264"

    findNALs(source_filename)
    # findNALs(target_filename)

    #find_type_5(target_filename)
    replace_error_nals(source_filename, target_filename)

    sha1_hash = "0f8ef8f4956ac57b7a84c0b6273fb7bfdc9ed96f"  # valid SHA1 for stream.h264
    check_hash(target_filename, sha1_hash)



