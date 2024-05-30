import json
import os

QUESTION_TYPES = {
    b"\x00\x01": "a"
}
ZONES = {}


def load_zones():
    global ZONES
    json_zone = {}
    zones_path = "Zones"
    files = []
    try:
        files = os.listdir(zones_path)
    except FileNotFoundError:
        zones_path = "..\\zones"
        files = os.listdir(zones_path)
    for zone_file in os.listdir(zones_path):
        with open(os.path.join(zones_path, zone_file), "r") as f:
            data = json.load(f)
            zone_name = data["$origin"]
            json_zone[zone_name] = data
    return json_zone


ZONES = load_zones()


def get_zone(domain):
    global ZONES
    zone_name = ".".join(domain)
    zone = {}
    try:
        zone = ZONES[zone_name]
    except KeyError:
        return None
    return zone


class DNSGen(object):

    def __init__(self, data):
        self.data = data
        self.QR = "1"
        self.AA = "1"
        self.TC = "0"
        self.RD = "0"
        self.RA = "0"
        self.Z = "000"
        self.RCODE = "0000"
        self.QDCOUNT = b"\x00\01"
        self.NSCOUNT = b"\x00\x00"
        self.ARCOUNT = b"\x00\x00"
        self.format_error = 0
        self.domain = ""

    def _get_transaction_id(self):
        return self.data[0:2]

    def _get_opcode(self):
        byte1 = self.data[2:3]
        opcode = ""
        for bit in range(1, 5):
            opcode += str(ord(byte1) & (1 << bit))
        return opcode

    def _generate_flags(self):
        flags1 = int(self.QR + self._get_opcode() + self.AA + self.TC + self.RD, 2).to_bytes(1, byteorder="big")
        flags2 = int(self.RA + self.Z + self.RCODE).to_bytes(1, byteorder="big")
        return flags1 + flags2

    def _get_question_domain_type(self, data):
        self.format_error = 0
        state = 0
        expected_length = 0
        domain_string = ""
        domain_parts = []
        question_type = None
        x = 0
        y = 0
        try:
            for byte in data:
                if state == 1:
                    if byte != 0:
                        domain_string += chr(byte)
                    x += 1
                    if x == expected_length:
                        domain_parts.append(domain_string)
                        domain_string = ""
                        state = 0
                    if byte == 0:
                        domain_parts.append(domain_string)
                        break
                else:
                    state = 1
                    expected_length = byte
                y += 1
            question_type = data[y:y + 2]
            self.domain = ".".join(domain_parts)
        except IndexError:
            self.format_error = 1
        finally:
            return domain_parts, question_type

    def _get_records(self, data):
        domain, question_type = self._get_question_domain_type(data)
        if question_type is None and len(domain) == 0:
            return {}, "", ""
        qt = ""
        try:
            qt = QUESTION_TYPES[question_type]
        except KeyError:
            qt = "a"
        zone = get_zone(domain)
        if zone is None:
            return [], qt, domain
        return zone[qt], qt, domain

    @staticmethod
    def _record_to_bytes(domain_name, record_type, record_ttl, record_value):
        resp = b"\xc0\x0c"
        if record_type == "a":
            resp += b"\x00\x01"
        resp += b"\x00\x01"
        resp += int(record_ttl).to_bytes(4, byteorder="big")
        if record_type == "a":
            resp += b"\x00\x04"  # IP length
            for part in record_value.split("."):
                resp += bytes([int(part)])
        return resp

    def _make_header(self, records_length):
        transaction_id = self._get_transaction_id()
        ancount = records_length.to_bytes(2, byteorder="big")
        if self.format_error == 1:
            self.RCODE = "0001"
        elif ancount == b"\x00\x00":
            self.RCODE = "0003"
        flags = self._generate_flags()
        return transaction_id + flags + self.QDCOUNT + ancount + self.NSCOUNT + self.ARCOUNT

    def _make_question(self, records_length, record_type, domain_name):
        resp = b""
        if self.format_error == 1:
            return resp
        for part in domain_name:
            length = len(part)
            resp += bytes([length])
            for char in part:
                resp += ord(char).to_bytes(1, byteorder="big")
        resp += b"\x00"  # end labels
        if record_type == "a":
            resp += (1).to_bytes(2, byteorder="big")
        resp += (1).to_bytes(2, byteorder="big")
        return resp

    def _make_answer(self, records, record_type, domain_name):
        resp = b""
        if len(records) == 0 or self.format_error == 1:
            return resp
        for record in records:
            resp += self._record_to_bytes(domain_name, record_type, record["ttl"], record["value"])
        return resp

    def make_response(self):
        records, record_type, domain_name = self._get_records(self.data[12:])
        return self._make_header(len(records)) + self._make_question(len(records), record_type, domain_name) + \
            self._make_answer(records, record_type, domain_name)


if __name__ == "__main__":
    pass
