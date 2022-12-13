# SPDX-License-Identifier: GPL-2.0+

import struct
import uuid

from datetime import datetime, timezone
from xml.sax.saxutils import escape

_RAW_DATA_TYPECODE = 0x81


class Substitution:
    def __init__(self, buf, offset):
        (sub_token, sub_id, sub_type) = struct.unpack_from('<BHB', buf, offset)
        self.length = 4

        self._id = sub_id
        self._type = sub_type
        self._optional = sub_token == 0x0e

    def xml(self, template=None):
        value = template.values[self._id]
        if value.type == 0x0:
            return None if self._optional else ""
        if self._type == 0x1:
            return escape(value.data.decode('utf16'))
        elif self._type == 0x4:
            return str(struct.unpack('<B', value.data)[0])
        elif self._type == 0x6:
            return str(struct.unpack('<H', value.data)[0])
        elif self._type == 0x8:
            return str(struct.unpack('<I', value.data)[0])
        elif self._type == 0xa:
            return str(struct.unpack('<Q', value.data)[0])
        elif self._type == 0x11:
            # see http://integriography.wordpress.com/2010/01/16/using-phython-to-parse-and-present-windows-64-bit-timestamps/
            timestamp = struct.unpack('<Q', value.data)[0] / 1e7 - 11644473600
            dt = datetime.utcfromtimestamp(timestamp)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        elif self._type == 0x13:
            # see http://www.gossamer-threads.com/lists/apache/bugs/386930
            revision, number_of_sub_ids = struct.unpack_from('<BB', value.data)
            iav = struct.unpack_from('>Q', value.data, 2)[0]
            sub_ids = [struct.unpack('<I', value.data[8 + 4 * i:12 + 4 * i])[0] for i in range(number_of_sub_ids)]
            return 'S-{0}-{1}-{2}'.format(revision, iav, '-'.join([str(sub_id) for sub_id in sub_ids]))
        elif self._type == 0x15 or self._type == 0x10 or self._type == 0x14:
            return '0x' + value.data[::-1].hex()
        elif self._type == 0x21:
            return value.template.xml()
        elif self._type == 0xf:
            return str(uuid.UUID(bytes_le=value.data))
        else:
            print("Unknown value type", hex(value.type))

    def has_type(self, template, type_code):
        value = template.values[self._id]
        return value.type == type_code


class Value:
    def __init__(self, buf, offset):
        length = struct.unpack_from('<BBH', buf, offset)[2]
        raw_value = buf[offset + 4:offset + 4 + length * 2]
        self._val = escape(raw_value.decode("utf16"))

        self.length = 4 + length * 2

    def xml(self, template=None):
        return self._val


class Attribute:
    def __init__(self, buf, offset):
        self._name = Name(buf, offset + 1)

        (next_token) = struct.unpack_from('<B', buf, offset + 1 + self._name.length)
        if next_token[0] == 0x05 or next_token == 0x45:
            self._value = Value(buf, offset + 1 + self._name.length)
        elif next_token[0] == 0x0e:
            self._value = Substitution(buf, offset + 1 + self._name.length)
        else:
            print("Unknown attribute next_token", hex(next_token[0]), hex(offset + 1 + self._name.length))

        self.length = 1 + self._name.length + self._value.length

    def xml(self, template=None):
        val = self._value.xml(template)
        return None if val is None else '{}="{}"'.format(self._name.val, val)


class Name:
    def __init__(self, buf, offset):
        _, length = struct.unpack_from('<HH', buf, offset)

        self.val = buf[offset + 4:offset + 4 + length * 2].decode("utf16")
        self.length = 4 + (length + 1) * 2


class Element:
    def __init__(self, buf, offset):
        token, dependency_id, _ = struct.unpack_from('<BHI', buf, offset)

        self._name = Name(buf, offset + 7)
        self._dependency = dependency_id

        ofs = offset + 7 + self._name.length
        if token == 0x41:
            _ = struct.unpack_from('<I', buf, ofs)
            ofs += 4

        self._children = []
        self._attributes = []

        while True:
            next_token = buf[ofs]
            if next_token == 0x06 or next_token == 0x46:
                attr = Attribute(buf, ofs)
                self._attributes.append(attr)
                ofs += attr.length
            elif next_token == 0x02:
                self._empty = False
                ofs += 1
                while True:
                    next_token = buf[ofs]
                    if next_token == 0x01 or next_token == 0x41:
                        element = Element(buf, ofs)
                    elif next_token == 0x04:
                        ofs += 1
                        break
                    elif next_token == 0x05:
                        element = Value(buf, ofs)
                    elif next_token == 0x0e or next_token == 0x0d:
                        element = Substitution(buf, ofs)
                    else:
                        print("Unknown intern next_token", hex(next_token), hex(ofs))
                        break

                    self._children.append(element)
                    ofs += element.length

                break
            elif next_token == 0x03:
                self._empty = True
                ofs += 1
                break
            else:
                print("Unknown element next_token", hex(next_token), hex(ofs))
                break

        self.length = ofs - offset

    def xml(self, template=None):
        if self._dependency != 0xFFFF:
            if template.values[self._dependency].type == 0x00:
                return ""

        attrs = filter(lambda x: x is not None, map(lambda x: x.xml(template), self._attributes))

        attrs = " ".join(attrs)
        if len(attrs) > 0:
            attrs = " " + attrs

        if self._empty:
            return "<{}{}/>".format(self._name.val, attrs)
        elif self._is_raw_data(template):
            return self._create_raw_data_xml(template)
        children = []
        for x in self._children:
            xml = x.xml(template)
            if xml is not None:
                children.append(xml)
        return "<{}{}>{}</{}>".format(self._name.val, attrs, "".join(children), self._name.val)

    def _is_raw_data(self, template):
        if len(self._children) != 1:
            return False

        child = self._children[0]
        return isinstance(child, Substitution) and child.has_type(template, _RAW_DATA_TYPECODE)

    def _create_raw_data_xml(self, template):
        items = []
        for c in self._children:
            raw_value = template.values[c._id]
            text = escape(raw_value.data.decode('utf16'))
            items.extend(text.split("\x00"))
        tag = self._name.val
        return "".join(f"<{tag}>{x}</{tag}>" for x in items if x)


class ValueSpec:
    def __init__(self, buf, offset, value_offset):
        self.length, self.type, _ = struct.unpack_from('<HBB', buf, offset)
        self.data = buf[value_offset:value_offset + self.length]

        if self.type == 0x21:
            self.template = BinXML(buf, value_offset)


class TemplateInstance:
    def __init__(self, buf, offset):
        next_token = struct.unpack_from('<BB16sIB', buf, offset)[4]
        if next_token == 0x0F:
            self._xml = BinXML(buf, offset + 0x16)
            _, num_values = struct.unpack_from('<BI', buf, offset + 22 + self._xml.length)
            values_length = 0
            self.values = []
            for x in range(0, num_values):
                value = ValueSpec(buf, offset + 22 + self._xml.length + 5 + x * 4, offset + 22 + self._xml.length + 5 + num_values * 4 + values_length)
                self.values.append(value)
                values_length += value.length

            self.length = 22 + self._xml.length + 5 + num_values * 4 + values_length
        else:
            print("Unknown template token", hex(next_token))

    def xml(self, template=None):
        return self._xml.xml(self)


class BinXML:
    def __init__(self, buf, offset):
        next_token = struct.unpack_from('<BBBBB', buf, offset)[4]
        if next_token == 0x0C:
            self._element = TemplateInstance(buf, offset + 4)
        elif next_token == 0x01 or next_token == 0x41:
            self._element = Element(buf, offset + 4)
        else:
            print("Unknown binxml token", hex(next_token))

        self.length = 4 + self._element.length

    def xml(self, template=None):
        return self._element.xml(template)


class ResultSet:
    def __init__(self, buf):
        self._xml = BinXML(buf, 0x14)

    def xml(self):
        return self._xml.xml()
