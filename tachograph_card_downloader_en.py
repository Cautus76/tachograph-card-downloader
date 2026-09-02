import os
import hashlib
from datetime import datetime
from smartcard.System import readers

AID_GEN1 = [0xFF, 0x54, 0x41, 0x43, 0x48, 0x4F]
AID_GEN2 = [0xFF, 0x53, 0x4D, 0x52, 0x44, 0x54]

rs = readers()
if not rs:
    raise SystemExit("❌ No smart-card reader was found")

c = rs[0].createConnection()
c.connect()

ddd = bytearray()
blocks = 0


def sw_text(sw1, sw2):
    return f"{sw1:02X}{sw2:02X}"


def select_aid(aid):
    _, sw1, sw2 = c.transmit(
        [0x00, 0xA4, 0x04, 0x0C, len(aid)] + aid
    )
    return sw1, sw2


def select_ef(fid):
    return c.transmit([
        0x00, 0xA4, 0x02, 0x0C, 0x02,
        (fid >> 8) & 0xFF,
        fid & 0xFF
    ])


def read_current_file():
    output = bytearray()
    offset = 0

    while offset < 65535:
        requested = 0x80

        while True:
            p1 = (offset >> 8) & 0x7F
            p2 = offset & 0xFF

            data, sw1, sw2 = c.transmit(
                [0x00, 0xB0, p1, p2, requested]
            )

            # The card reported the correct length
            if sw1 == 0x6C:
                requested = sw2 if sw2 else 0x80
                continue

            # Some cards reject an excessively large request
            if (sw1, sw2) == (0x67, 0x00) and requested > 1:
                requested //= 2
                continue

            break

        if data:
            output.extend(data)
            offset += len(data)

        if (sw1, sw2) == (0x90, 0x00):
            if not data or len(data) < requested:
                break
            continue

        # End of file
        if (sw1, sw2) in [
            (0x62, 0x82),
            (0x6B, 0x00),
            (0x6A, 0x86)
        ]:
            break

        if (sw1, sw2) == (0x67, 0x00) and requested == 1:
            break

        raise RuntimeError(
            "READ BINARY failed: SW=" + sw_text(sw1, sw2)
        )

    return bytes(output)


def perform_hash():
    _, sw1, sw2 = c.transmit(
        [0x80, 0x2A, 0x90, 0x00]
    )
    return sw1, sw2


def get_signature(expected_length):
    sig, sw1, sw2 = c.transmit(
        [0x00, 0x2A, 0x9E, 0x9A, expected_length]
    )

    if sw1 == 0x6C:
        correct_length = sw2 if sw2 else expected_length
        sig, sw1, sw2 = c.transmit(
            [0x00, 0x2A, 0x9E, 0x9A, correct_length]
        )

    if sw1 == 0x61:
        response_length = sw2 if sw2 else expected_length
        sig, sw1, sw2 = c.transmit(
            [0x00, 0xC0, 0x00, 0x00, response_length]
        )

    return bytes(sig), sw1, sw2


def append_tlv(fid, suffix, value):
    global blocks

    if not value:
        return

    if len(value) >= 0xFFFF:
        raise RuntimeError("The file is too large for a DDD TLV block")

    ddd.extend(fid.to_bytes(2, "big"))
    ddd.append(suffix)
    ddd.extend(len(value).to_bytes(2, "big"))
    ddd.extend(value)
    blocks += 1


def download_ef(
    fid,
    name,
    data_suffix,
    signed,
    signature_length,
    optional=False
):
    _, sw1, sw2 = select_ef(fid)

    if (sw1, sw2) != (0x90, 0x00):
        if optional:
            print(
                f"  – {name}: not present on the card "
                f"(SW={sw_text(sw1, sw2)})"
            )
            return False

        raise RuntimeError(
            f"{name}: SELECT failed, SW={sw_text(sw1, sw2)}"
        )

    try:
        if signed:
            sw1, sw2 = perform_hash()

            if (sw1, sw2) != (0x90, 0x00):
                raise RuntimeError(
                    f"HASH failed, SW={sw_text(sw1, sw2)}"
                )

        file_data = read_current_file()

        if not file_data:
            raise RuntimeError("the file contains no data")

        if signed:
            signature, sw1, sw2 = get_signature(signature_length)

            if (sw1, sw2) != (0x90, 0x00):
                raise RuntimeError(
                    f"signature failed, SW={sw_text(sw1, sw2)}"
                )

            append_tlv(fid, data_suffix, file_data)
            append_tlv(fid, data_suffix + 1, signature)

            print(
                f"  ✓ {name}: {len(file_data)} B "
                f"+ signature {len(signature)} B"
            )
        else:
            append_tlv(fid, data_suffix, file_data)
            print(f"  ✓ {name}: {len(file_data)} B")

        return True

    except Exception as error:
        if optional:
            print(f"  – {name}: skipped ({error})")
            return False
        raise


print("🔌 Reader:", rs[0])
print("💳 Card connected")
print()

try:
    # Files in the card's master directory
    print("=== MASTER FILES ===")

    download_ef(
        0x0002, "EF ICC", 0x00,
        signed=False, signature_length=0
    )

    download_ef(
        0x0005, "EF IC", 0x00,
        signed=False, signature_length=0
    )

    # Generation 1
    print()
    print("=== TACHOGRAPH GEN1 ===")

    sw1, sw2 = select_aid(AID_GEN1)

    if (sw1, sw2) != (0x90, 0x00):
        raise RuntimeError(
            "Gen1 application cannot be selected: SW=" +
            sw_text(sw1, sw2)
        )

    gen1_files = [
        (0x0501, "Application Identification", True,  False),
        (0xC100, "Card Certificate",           False, False),
        (0xC108, "CA Certificate",             False, False),
        (0x0520, "Identification",              True,  False),
        (0x0521, "Driving Licence",             True,  False),
        (0x0502, "Events Data",                 True,  False),
        (0x0503, "Faults Data",                 True,  False),
        (0x0504, "Driver Activity Data",        True,  False),
        (0x0505, "Vehicles Used",               True,  False),
        (0x0506, "Places",                      True,  False),
        (0x0507, "Current Usage",               True,  False),
        (0x0508, "Control Activity",            True,  False),
        (0x0522, "Specific Conditions",         True,  False),
        (0x050E, "Card Download",               True,  True),
    ]

    for fid, name, signed, optional in gen1_files:
        download_ef(
            fid,
            "Gen1 " + name,
            data_suffix=0x00,
            signed=signed,
            signature_length=0x80,
            optional=optional
        )

    # Generation 2
    print()
    print("=== TACHOGRAPH GEN2 ===")

    sw1, sw2 = select_aid(AID_GEN2)

    if (sw1, sw2) != (0x90, 0x00):
        raise RuntimeError(
            "Gen2 application cannot be selected: SW=" +
            sw_text(sw1, sw2)
        )

    gen2_files = [
        (0x0501, "Application Identification", True,  False),
        (0xC100, "Card MA Certificate",         False, True),
        (0xC101, "Card Sign Certificate",       False, False),
        (0xC108, "CA Certificate",              False, False),
        (0xC109, "Link Certificate",            False, True),
        (0x0520, "Identification",              True,  False),
        (0x0521, "Driving Licence",             True,  False),
        (0x0502, "Events Data",                 True,  False),
        (0x0503, "Faults Data",                 True,  False),
        (0x0504, "Driver Activity Data",        True,  False),
        (0x0505, "Vehicles Used",               True,  False),
        (0x0506, "Places",                      True,  False),
        (0x0507, "Current Usage",               True,  False),
        (0x0508, "Control Activity",            True,  False),
        (0x0522, "Specific Conditions",         True,  False),
        (0x050E, "Card Download",               True,  True),
        (0x0523, "Vehicle Units Used",           True,  True),
        (0x0524, "GNSS Places",                  True,  True),
    ]

    for fid, name, signed, optional in gen2_files:
        download_ef(
            fid,
            "Gen2 " + name,
            data_suffix=0x02,
            signed=signed,
            signature_length=0x40,
            optional=optional
        )

    if not ddd:
        raise RuntimeError("No data was downloaded")

    desktop = os.path.expanduser("~/Desktop")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"DRIVER_CARD_{timestamp}.DDD"
    output_path = os.path.join(desktop, filename)

    counter = 1
    while os.path.exists(output_path):
        filename = f"DRIVER_CARD_{timestamp}_{counter}.DDD"
        output_path = os.path.join(desktop, filename)
        counter += 1

    with open(output_path, "xb") as output_file:
        output_file.write(ddd)

    checksum = hashlib.sha256(ddd).hexdigest()

    print()
    print("======================================")
    print("✅ DDD FILE WAS CREATED")
    print("📄 File:", output_path)
    print("📦 Size:", len(ddd), "bytes")
    print("🧩 TLV block count:", blocks)
    print("🔐 SHA-256:", checksum)
    print("======================================")

except Exception as error:
    print()
    print("❌ DOWNLOAD WAS STOPPED")
    print(error)
    print("The file was not saved as a completed DDD file.")

finally:
    c.disconnect()
