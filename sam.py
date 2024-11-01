###################################################################################################
### python .\sam.py --reg sam.reg --jd 04f16de0 --skew1 8d2ba8db --gbg 249958ba --data a970d345 ###
###################################################################################################

##########################################
### https://hashes.com/en/decrypt/hash ###
##########################################

import argparse
import hashcat
import json
from struct import Struct
from binascii import unhexlify
from Crypto.Cipher import DES, AES
from Crypto.Hash import MD4
from datetime import datetime, UTC
import logging
import sys
from termcolor import colored

def ft2dt(ft):
    """Convert Windows FILETIME to datetime object"""
    # FILETIME is number of 100-nanosecond intervals since January 1, 1601
    EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970
    # Convert to seconds and subtract Unix epoch
    seconds_since_1970 = (ft - EPOCH_AS_FILETIME) / 10000000
    return datetime.fromtimestamp(seconds_since_1970, UTC).strftime('%Y-%m-%d %H:%M:%S UTC')

# Entry Structure (ES)
class ES:
    NAME = 0
    TYPE = 1
    OFFSET = 2
    LENGTH = 3


class Vector:
    def __init__(self, data):
        self.data = data

    def __repr__(self):
        return '(' + ', '.join(map(str, list(self.data))) + ')'

    def __len__(self):
        return len(self.data)

    def __getitem__(self, key):
        return self.data[key]


# SAM Hash
class SAMHash:
    def __init__(self, data):
        self.__entries = [
            ('PEKid', 'i', 0x00, 0x02),
            ('Version', 'i', 0x02, 0x02),
            ('DataOffset', 'i', 0x04, 0x04),
            ('IV', 'v', 0x08, 0x10),
            ('HashData', 'b', 0x18, 0x00),
        ]

        self.data = data

        for name, _, _, _ in self.__entries:
            setattr(self, name.lower(), None)

        self.parse()

    def select(self, entry):
        return self.data[entry[ES.OFFSET]:(entry[ES.OFFSET] + entry[ES.LENGTH]) if entry[ES.LENGTH] else None]

    def parse(self):
        for entry in self.__entries:
            value = None

            match entry[ES.TYPE]:
                case 'i':
                    value = int.from_bytes(
                        bytes(self.select(entry)),
                        'little'
                    )
                case 'b':
                    value = bytes(self.select(entry))
                case 'v':
                    value = Vector(self.select(entry))

            setattr(self, entry[ES.NAME].lower(), value)

    def __repr__(self):
        return colored(
            f'🔒 SAMHash [{len(self)} bytes] ↓ ↓\n', attrs=['bold']
        ) + '\n'.join(
            [
                '\t' +
                f'{'✔️ ' if getattr(self, entry[ES.NAME].lower()) is not None else '❌ '}' +
                f'{entry[ES.NAME] + ':' : <30}' +
                colored(str(getattr(self, entry[ES.NAME].lower())), attrs=['bold'])
                for entry in self.__entries
            ]
        )

    def __len__(self):
        return len(self.data)


# AES Data
class AESData:
    def __init__(self, data):
        self.__entries = [
            ('Version', 'i', 0x00, 0x04),
            ('Length', 'i', 0x04, 0x04),
            ('ChecksumLength', 'i', 0x08, 0x04),
            ('DataLength', 'i', 0x0C, 0x04),
            ('IV', 'v', 0x10, 0x10),
            ('Data', 'b', 0x20, 0x00),
        ]

        self.__data = data

        for name, _, _, _ in self.__entries:
            setattr(self, name.lower(), None)

        self.parse()

    def select(self, entry):
        return self.__data[entry[ES.OFFSET]:(entry[ES.OFFSET] + entry[ES.LENGTH]) if entry[ES.LENGTH] else None]

    def parse(self):
        for entry in self.__entries:
            value = None

            match entry[ES.TYPE]:
                case 'i':
                    value = int.from_bytes(
                        bytes(self.select(entry)),
                        'little'
                    )
                case 'b':
                    value = bytes(self.select(entry))
                case 'v':
                    value = Vector(self.select(entry))

            setattr(self, entry[ES.NAME].lower(), value)


    def __repr__(self):
        values = colored(
            f'🔒 AESData [{len(self)} bytes] ↓ ↓\n', attrs=['bold']
        )

        for entry in self.__entries:
            values += (
                '\t' +
                f'{'✔️ ' if getattr(self, entry[ES.NAME].lower()) is not None else '❌ '}' +
                f'{entry[ES.NAME] + ':' : <30}' +
                colored(str(getattr(self, entry[ES.NAME].lower())), attrs=['bold']) +
               '\n'
            )

        return values

    def __len__(self):
        return len(self.__data)

# F (domain)
class Fd:
    def __init__(self, data):
        self.__entries = [
            ('Version', 'h', 0x00, 0x04),
            ('AliasCount', 'i', 0x04, 0x04),
            ('CreationTime', 't', 0x08, 0x08),
            ('DomainModifiedCount', 'i', 0x10, 0x08),
            ('MaxPasswordAge', 'dt', 0x18, 0x08),
            ('MinPasswordAge', 'dt', 0x20, 0x08),
            ('ForceLogoff', 'dt', 0x28, 0x08),
            ('LockoutDuration', 'dt', 0x30, 0x08),
            ('LockoutObservationWindow', 'dt', 0x38, 0x08),
            ('ModifiedCountAtLastPromotion', 'i', 0x40, 0x08),
            ('NextRID', 'i', 0x48, 0x04),
            ('PasswordProperties', 'lb', 0x4C, 0x04),
            ('MinPasswordLength', 'i', 0x50, 0x02),
            ('PasswordHistoryLength', 'i', 0x52, 0x02),
            ('LockoutThreshold', 'i', 0x54, 0x02),
            ('F1', 'b', 0x56, 0x02),
            ('DomainServerState', 'i', 0x58, 0x04),
            ('DomainServerRole', 'i', 0x5C, 0x02),
            ('UASCompatibilityRequired', 'i', 0x5E, 0x02),
            ('F2', 'lb', 0x60, 0x08),
            ('Key', 'k', 0x68, 0x00),
        ]

        self.__f = data

        for name, _, _, _ in self.__entries:
            setattr(self, name.lower(), None)

        self.parse()

    def select(self, entry):
        return self.__f[entry[ES.OFFSET]:(entry[ES.OFFSET] + entry[ES.LENGTH]) if entry[ES.LENGTH] else None]

    def parse(self):
        for entry in self.__entries:
            value = None

            match entry[ES.TYPE]:
                case 'h':
                    ver = int.from_bytes(bytes(self.select(entry)), 'little').to_bytes(length=4)
                    value = f'{int.from_bytes(ver[:2])}.{int.from_bytes(ver[2:])}'
                case 't':
                    stamp = int.from_bytes(
                        bytes(self.select(entry)),
                        'little'
                    )
                    value = ft2dt(stamp)
                case 'dt':
                    binary_stamp = bytes(self.select(entry))

                    low = int.from_bytes(binary_stamp[:4], 'little', signed=False)
                    high = int.from_bytes(binary_stamp[4:], 'little', signed=True)

                    stamp = (high << 32) + low

                    value = f'Δ{abs(stamp) // 10 ** 7} seconds'
                case 's':
                    value = bytes(self.select(entry)).decode('utf-16')
                case 'b':
                    value = '0x' + bytes(self.select(entry)).hex()
                case 'lb':
                    value = '0x' + bytes(self.select(entry))[::-1].hex()
                case 'i':
                    value = int.from_bytes(
                        bytes(self.select(entry)),
                        'little'
                    )
                case 'k':
                    value = AESData(self.select(entry))

            setattr(self, entry[ES.NAME].lower(), value)

    def __repr__(self):
        values = colored(
            f'Fd [{len(self)} bytes]:\n', attrs=['bold']
        )

        for entry in self.__entries:
            values += (
                f'{'✔️ ' if getattr(self, entry[ES.NAME].lower()) is not None else '❌ '}' +
                f'{entry[ES.NAME] + ':' : <30}' +
                colored(str(getattr(self, entry[ES.NAME].lower())), attrs=['bold']) +
               '\n'
            )

        return values

    def __len__(self):
        return len(self.__f)


# V Entry Structure (VES)
class VES:
    NAME = 0
    TYPE = 1


# V Header Structure (VHS)
class VHS:
    OFFSET = 0
    LENGTH = 1
    EXTRA = 2
    SERVICE_LENGTH = 3


# V
class V:
    def __init__(self, data):
        self.__base = 0xCC
        self.__entries = [
            ('Version', 'h'),
            ('UserName', 's'),
            ('FullName', 's'),
            ('Description', 's'),
            ('UserDescription', 's'),
            ('V1', 'u'),
            ('HomeDirectory', 's'),
            ('HomeDirectoryConnect', 's'),
            ('ScriptPath', 's'),
            ('ProfilePath', 's'),
            ('Workstations', 's'),
            ('HoursAllowed', 'i'),
            ('V3', 'b'),
            ('LMHash', 'k'),
            ('NTHash', 'k'),
            ('V4', 'b'),
            ('V5', 'b'),
        ]

        self.__length = len(data)

        for name, _ in self.__entries:
            setattr(self, name.lower(), None)

        self.parse(data)

    def parse(self, data):
        for i, entry in enumerate(self.__entries):
            setattr(self, entry[0].lower(), VEntry(data, self.__base, i * 0x0C, *entry))

    def __repr__(self):
        return (
            colored(
                f'\nV [{len(self)} bytes]:\n', attrs=['bold']) +
                '\n'.join(
                    [
                        str(
                            getattr(self, entry[0].lower())
                        )
                        for entry in self.__entries
                    ]
                )
        )

    def __len__(self):
        return self.__length


# V Entry
class VEntry:
    def __init__(self, data, base, offset, name, t):
        self.__base = base

        self.name = name
        self.service = []
        self.type = t

        # Calculate data offset, length, and the extra field
        for i in range(VHS.SERVICE_LENGTH):
            self.service.append(
                int.from_bytes(bytes(data[offset + (i * 4):offset + (i + 1) * 4]), byteorder='little') +
                (self.__base if i == VHS.OFFSET else 0)
            )

        self.data = self.parse(data)

    def select(self, v):
        return v[
                   self.service[VHS.OFFSET]:
                   self.service[VHS.OFFSET] + self.service[VHS.LENGTH]
               ]

    def parse(self, v):
        if self.service[VHS.LENGTH] == 0:
            return None

        match self.type:
            case 'h':
                ver = self.service[VHS.EXTRA].to_bytes(length=4)
                return f'{int.from_bytes(ver[:2])}.{int.from_bytes(ver[2:])}'
            case 's':
                return bytes(self.select(v)).decode('utf-16')
            case 'b':
                return '0x' + bytes(self.select(v)).hex()
            case 'i':
                return int.from_bytes(
                    bytes(self.select(v)),
                    'little'
                )
            case 'k':
                return SAMHash(self.select(v))
            case _:
                return None

    def __repr__(self):
        if self.type != 'h':
            service_string = f' @ V[0x{self.__base:04X} + 0x{self.service[VHS.OFFSET]:04X}]: |{self.service[VHS.LENGTH]}| / 0x{self.service[VHS.EXTRA]:04X}'
        else:
            service_string = f' (first entry: 0x{self.__base:02X} + 0x{self.service[1]:02X} = 0x{self.__base + self.service[1]:04X})'

        return (
            f'{'✔️ ' if self.data else '❌ '}' +
            f'{self.name + ':' : <30}' +
            colored(f'{self.data or self.service}', attrs=['bold']) +
            (service_string if self.data else '')
        )

    def __len__(self):
        return self.service[VHS.LENGTH]


# ResetData
class ResetData:
    def __init__(self, data):
        self.version = 0
        self.questions = []

        self.parse(data)

    def parse(self, data):
        data = json.loads(bytes(data).decode('utf-16-le'))

        self.version = data['version']

        for question in data['questions']:
            self.questions.append(
                {
                    'question': question['question'],
                    'answer': question['answer']
                }
            )

    def __repr__(self):
        return (
            colored(
                f'\nResetData v{self.version} [{len(self)} bytes]:\n', attrs=['bold']
            ) +
            '\n'.join(
                [
                    f'❓ {question["question"]}\n💡 {question["answer"]}\n'
                    for question in self.questions
                ]
            )
        )

    def __len__(self):
        return len(json.dumps(self.questions).encode('utf-16-le'))


class LMUser:
    def __init__(self, rid, data):
        self.rid = rid
        self.k = []
        self.v = V(data['V'])
        self.reset_data = ResetData(data['ResetData']) if 'ResetData' in data else None
        self.reset_force = not not int.from_bytes(bytes(data['ForcePasswordReset']), 'little') if 'ForcePasswordReset' in data else False
        self.hint = bytes(data['UserPasswordHint']).decode('utf-16-le') if 'UserPasswordHint' in data else None
        self.decrypted_hashes = None
        self.encrypted_hashes = None

        self.compute_keys()

    def compute_keys(self):
        # RID is a 32-bit LE integer
        rid = self.rid.to_bytes(32, 'little')

        # K1 = R[0] || R[1] || R[2] || R[3] || R[0] || R[1] || R[2]
        # K2 = R[3] || R[0] || R[1] || R[2] || R[3] || R[0] || R[1]
        self.k += [
            [rid[0], rid[1], rid[2], rid[3], rid[0], rid[1], rid[2]],
            [rid[3], rid[0], rid[1], rid[2], rid[3], rid[0], rid[1]]
        ]

        for i, key in enumerate(self.k):
            key = [
                key[0] >> 1,
                (key[0] & 0x01) << 6 | key[1] >> 2,
                (key[1] & 0x03) << 5 | key[2] >> 3,
                (key[2] & 0x07) << 4 | key[3] >> 4,
                (key[3] & 0x0F) << 3 | key[4] >> 5,
                (key[4] & 0x1F) << 2 | key[5] >> 6,
                (key[5] & 0x3F) << 1 | key[6] >> 7,
                key[6] & 0x7F
            ]

            for j in range(8):
                key[j] <<= 1
                key[j] &= 0xFE

            self.k[i] = bytes(key)

    def __repr__(self):
        return (
            f'👤 User ' +
            colored(f'{self.v.username.data}\n\n', attrs=['bold']) +
            colored(f'RID:', attrs=['bold']) +
            f'\n🪪 {self.rid} (0x{self.rid:08X})' +
            f'\n{self.v}\n' +
            (
                f'{self.reset_data}' if self.reset_data else ''
            ) +
            (
                colored(f'\n❗ Password reset next logon\n', attrs=['bold']) if self.reset_force else ''
            ) +
            (
                (
                    colored(f'\nPassword hint:', attrs=['bold']) +
                    f'\n🧵 {self.hint}'
                ) if self.hint else ''
            ) +
            colored('\nDeobfuscation keys:\n', attrs=['bold']) +
            '\n'.join(
                [
                    f'❗ K{i + 1} = 0x{key.hex()}'
                    for i, key in enumerate(self.k)
                ]
            ) +
            (
                (
                    colored('\n\n‼️🔓 Decrypted hashes:\n', attrs=['bold']) +
                    f'NT: {self.decrypted_hashes[0].hex() if len(self.decrypted_hashes[0]) else '🚫 None'}\n' +
                    f'LM: {self.decrypted_hashes[1].hex() if len(self.decrypted_hashes[1]) else '🚫 None (LM disabled/empty password)'}\n'
                ) if self.decrypted_hashes else ''
            ) +
            (
                (
                        colored('\n✔️ Encrypted hashes:\n', attrs=['bold']) +
                        f'NT: {self.encrypted_hashes[0].hex() if len(self.encrypted_hashes[0]) else '🚫 None'}\n' +
                        f'LM: {self.encrypted_hashes[1].hex() if len(self.encrypted_hashes[1]) else '🚫 None (LM disabled/empty password)'}\n'
                ) if self.encrypted_hashes else ''
            ) +
            '\n'
        )


class LMDomain:
    def __init__(self, file, jd=None, skew1=None, gbg=None, data=None, pw=None):
        self.users = []
        self.lsa_key = [0 for _ in range(16)]
        self.boot_key = None
        self.fd = None

        self.load_data(file)

        self.acquire_boot_key(jd, skew1, gbg, data)
        self.decrypt_hash()

        if pw is not None:
            self.encrypt_hash(pw)

    def load_data(self, file):
        with open(file, 'r', encoding='utf-16') as f:
            data = {}

            read_user = False
            read_domain = False
            next_key = None
            radix = 16
            rid = 0

            lines = f.readlines()

            for i, line in enumerate(lines):
                line = line.strip()

                if len(line) == 0:
                    if read_user:
                        self.users.append(LMUser(rid, data))
                        data.clear()
                        read_user = False

                    if read_domain:
                        self.fd = Fd(data['F'])
                        data.clear()
                        read_domain = False

                    next_key = None

                    continue

                if line.startswith('[') and line.endswith(']'):
                    current_key = line[1:-1]

                    if current_key == 'HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account':
                        read_domain = True

                    elif current_key.find('HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users') != -1:
                        user_key = line[1:-1].split('\\')

                        try:
                            rid = int(user_key[-1], 16)
                        except ValueError:
                            continue
                        else:
                            read_user = True

                    continue

                if read_user or read_domain:
                    if len(line) == 0:
                        continue

                    if not next_key:
                        kv = line.split('=')

                        if len(kv) != 2:
                            print(f'Potentially corrupt data on line {i + 1}! Skipping...')
                            continue

                        key = kv[0][1:-1]
                        value = kv[1]

                        if value.find(':') != -1:
                            chunks = value.split(':')

                            match chunks[0]:
                                case 'dword':
                                    radix = 10
                                case 'hex':
                                    radix = 16
                                case _:
                                    print(f'Unknown data type: {chunks[0]}! Skipping...')
                                    continue

                            value = chunks[1]

                        if value[-1] == '\\':
                            next_key = key
                            value = value[:-1]

                            if value[-1] == ',':
                                value = value[:-1]

                        current = [int(byte, radix) for byte in value.split(',')]

                        if key not in data:
                            data[key] = current
                        else:
                            data[key] += current

                    else:
                        trailing = False

                        if line[-1] == '\\':
                            line = line[:-1]
                            trailing = True

                        if line[-1] == ',':
                            line = line[:-1]

                        data[next_key] += [int(byte, radix) for byte in line.split(',')]

                        if not trailing:
                            next_key = None

    @staticmethod
    def is_valid_arg(arg):
        if len(arg) != 8:
            return False

        try:
            int(arg, 16)
        except ValueError:
            return False

        return True

    def hash_nt(self, password):
        """ Compute the NTLM hash of a password. """

        # Nice and simple, just hash the UTF-16-LE encoded password with MD4.
        # MD4(UTF-16-LE(password))
        encoded_password = password.encode('utf-16-le')
        md4 = MD4.new(encoded_password).digest()

        return md4

    def hash_lm(self, password):
        """ Compute the Lan Manager (LM) hash of a password. """

        # https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview#passwords-stored-as-owf
        # 1. The password is padded with NULL bytes to exactly 14 characters. If the password is longer than 14 characters, it is replaced with 14 NULL bytes for the remaining operations.
        # 2. The password is converted to all uppercase.
        # 3. The password is split into two 7-byte (56-bit) keys.
        # 4. Each key is used to encrypt a fixed string.
        # 5. The two results from step 4 are concatenated and stored as the LM hash.
        fixed_string = b'KGS!@#$%'
        hash_length = 14

        if len(password) > hash_length:
            password = password[:hash_length]

        password = password.upper().ljust(hash_length, '\x00').encode('utf-8')

        # DES parity bit calculation twiddle (64-bit value)
        # http://graphics.stanford.edu/~seander/bithacks.html#ParityParallel
        def parity(v):
            return (v << 1) | (0x9669 >> ((v ^ (v >> 4)) & 0x0F)) & 0x01 if not v & ~0x7F else 0

        k = [password[:hash_length // 2], password[hash_length // 2:]]

        # The part Microsoft doesn't disclose: DES encryption is used, we have to expand the keys
        # to 8 bytes and calculate a parity bit for each byte
        k = [
            b''.join(
                (
                    parity(int.from_bytes(key, 'big') >> (0x07 * (shift - 1)) & 0x7F)
                ).to_bytes() for shift in range(8, 0, -1)
            ) for key in k
        ]

        # The «fixed string» is KGS!@#$%, and it's encrypted with DES using the keys
        h = [
            DES.new(key, mode=DES.MODE_ECB).encrypt(fixed_string) for key in k
        ]

        return b''.join(h)

    def acquire_boot_key(self, jd, skew1, gbg, data):
        keys = [
            ('JD', jd),
            ('Skew1', skew1),
            ('GBG', gbg),
            ('Data', data)
        ]

        if jd is None or skew1 is None or gbg is None or data is None:
            print(colored('⚠️ The system boot key is required to decrypt the password hashes.', attrs=['bold']))
            print('The boot key is calculated using the following formula:')
            print(
                '\t' +
                colored('B', color='light_green') + ' = ' +
                colored('JD', color='light_red') + '[' + colored('c', color='cyan') +'] || ' +
                colored('Skew1', color='light_blue') + '[' + colored('c', color='cyan') +'] || ' +
                colored('GBG', color='yellow') + '[' + colored('c', color='cyan') +'] || ' +
                colored('Data', color='magenta') + '[' + colored('c', color='cyan') +'],'
            )
            print('where:')
            print(
                '• || is a concatenation operator\n' +
                '• c is the registry key ' + colored('class name', color='red', attrs=['bold']) +
                ' (❗ hidden away in the Registry Editor)\n' +
                '• JD, Skew1, GBG, and Data are LSA keys\n'
            )
            print('To acquire the boot key class name components, you have to navigate to:')
            print(colored('\tHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa', attrs=['bold']))
            print('of the target system and literally PRINT the LSA key to PDF.\n')
            print('Hit Ctrl+P, select «Microsoft Print to PDF», and save the file.')
            print('Then, open the PDF, find the JD, Skew1, GBG, and Data class names, and enter them below.')
            print('Each class name is a 4-byte hex value (8 characters), together composing a 16-byte Base16 encoded string.\n')
            print(colored('Example PDF entry:', attrs=['bold']))
            print('\tKey Name: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD')
            print('\tClass Name: ' + colored('37557b3a', color='red', attrs=['bold']) + ' ← this is what you need ❗')
            print('\tValue 0')
            print('\t  Name: Lookup')
            print('\t  Type: REG_BINARY')
            print('\t  Data:')
            print('\t00000000 25 9d f2 f8 59 27\n')

        lsa_key = b''

        for key, value in keys:
            while value is None or not self.is_valid_arg(value):
                if value is None:
                    print(colored(f'⚠️ {key} class name is missing.', color='yellow'))
                else:
                    print(colored(f'❌ Invalid hex value for {key}.', color='red'))

                value = input(f'Enter {key} ' + colored('class name', color='red', attrs=['bold']) + ': ')

            lsa_key += value.encode('utf-8')

        lsa_key = unhexlify(lsa_key)

        for index, scrambled in enumerate(
            [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
        ):
            self.lsa_key[index] = lsa_key[scrambled]

        print(f'{colored('LSA key:\n', attrs=['bold'])}🔑 0x{bytes(self.lsa_key).hex()}\n')

        self.boot_key = self.decrypt_aes(
            bytes(self.lsa_key),
            self.fd.key.data[:self.fd.key.datalength],
            bytes(self.fd.key.iv.data)
        )[:16]

        print(f'{colored('Boot key:\n', attrs=['bold'])}🔐 0x{self.boot_key.hex()}\n')

    def decrypt_hash(self):
        for user in self.users:
            d = [DES.new(key, mode=DES.MODE_ECB) for key in user.k]
            h = [user.v.nthash, user.v.lmhash]

            dec = [
                self.decrypt_aes(
                    self.boot_key,
                    hash.data.hashdata,
                    bytes(hash.data.iv.data)
                )[:16] for hash in h
            ]

            # NTHash is split into 2 8-byte chunks and passed through DES ← (K1, K2)
            user.decrypted_hashes = [
                d[0].decrypt(decr[:8]) + d[1].decrypt(decr[8:]) for decr in dec
            ]

    def encrypt_hash(self, pw):
        for user in self.users:
            user.v.nthash.data.hashdata = self.hash_nt(pw)
            user.v.lmhash.data.hashdata = self.hash_lm(pw)

            d = [DES.new(key, mode=DES.MODE_ECB) for key in user.k]
            h = [user.v.nthash, user.v.lmhash]

            enc = [
                self.encrypt_aes(
                    self.boot_key,
                    hash.data.hashdata,
                    bytes(hash.data.iv.data)
                ) for hash in h
            ]

            # NTHash is split into 2 8-byte chunks and passed through DES ← (K1, K2)
            user.encrypted_hashes = [
                d[0].encrypt(encr[:8]) + d[1].encrypt(encr[8:]) for encr in enc
            ]

    def decrypt_aes(self, key, value, iv=None):
        result = b''

        # If no IV is provided, use an empty vector
        # IV = (0, 0, ..., 0)
        if iv is None:
            iv = b'\x00' * 16

        aes256 = AES.new(key, AES.MODE_CBC, iv)

        for index in range(0, len(value), 16):
            cipher = value[index:index + 16]

            # Pad buffer to 16 bytes if it's less than a full block
            if len(cipher) < 16:
                cipher += b'\x00' * (16 - len(cipher))

            result += aes256.decrypt(cipher)

        return result

    def encrypt_aes(self, key, value, iv=None):
        result = b''

        # If no IV is provided, use an empty vector
        # IV = (0, 0, ..., 0)
        if iv is None:
            iv = b'\x00' * 16

        aes256 = AES.new(key, AES.MODE_CBC, iv)

        for index in range(0, len(value), 16):
            cipher = value[index:index + 16]

            # Pad buffer to 16 bytes if it's less than a full block
            if len(cipher) < 16:
                cipher += b'\x00' * (16 - len(cipher))

            result += aes256.encrypt(cipher)

        return result

    def __repr__(self):
        return (
                colored(f'LMDomain:\n', attrs=['bold'])
                + f'{self.fd}\n' +
                '\n'.join([str(user) for user in self.users])
        )


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decrypt NT/LM password hashes using boot key components.')

    parser.add_argument('--reg', required=True, help='HKLM\\SAM registry export file (non-binary .reg format)')
    parser.add_argument('--jd', help='LSA\\JD class name')
    parser.add_argument('--skew1', help='LSA\\Skew1 class name')
    parser.add_argument('--gbg', help='LSA\\GBG class name')
    parser.add_argument('--data', help='LSA\\Data key class name')
    parser.add_argument('--pw', help='Custom password to hash & encrypt')

    args = parser.parse_args()

    domain = LMDomain(args.reg, args.jd, args.skew1, args.gbg, args.data, args.pw)

    print(domain)