import socket
import struct


class DNSCacheServer:
    def __init__(self):
        self.cache = {}
        self.root_dns_server = '8.8.8.8'  # Пример: используем Google Public DNS

    def resolve(self, domain):
        if domain in self.cache:
            return self.cache[domain]
        else:
            ip = self.query_dns(domain)
            if ip:
                self.cache[domain] = ip
                return ip
            else:
                return None

    def query_dns(self, domain):
        try:
            query = self.construct_dns_query(domain)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)  # Установка таймаута на 2 секунды
                sock.sendto(query, (self.root_dns_server, 53))
                response, _ = sock.recvfrom(1024)
                ip = self.parse_dns_response(response)
                return ip
        except Exception as e:
            print("Error querying DNS:", e)
            return None

    def construct_dns_query(self, domain):
        # Формируем DNS запрос для заданного домена
        ID = 1234  # Произвольный идентификатор запроса
        flags = 0x0100  # Запрос рекурсивный и использует стандартные коды запроса
        qdcount = 1  # Количество записей в разделе запроса
        question = self.encode_domain(domain) + b'\x00'  # Кодируем доменное имя и добавляем нулевой байт
        qtype = 1  # Тип запроса A (IPv4)
        qclass = 1  # Класс запроса IN (Internet)

        query = struct.pack('!HHHHHH', ID, flags, qdcount, 0, 0, 0) + question + struct.pack('!HH', qtype, qclass)
        return query

    def parse_dns_response(self, response):
        # Парсим DNS ответ для получения IP адреса
        # Здесь необходимо реализовать полноценный парсинг ответа DNS
        # В этом примере мы просто возвращаем первый IPv4 адрес из ответа
        if len(response) < 12:
            return None  # Некорректный ответ DNS

        qdcount = struct.unpack('!H', response[4:6])[0]
        ancount = struct.unpack('!H', response[6:8])[0]

        if ancount == 0:
            return None  # Нет ответов в DNS

        start_index = 12
        while qdcount > 0:
            # Пропускаем записи в разделе запроса
            while response[start_index] != 0:
                start_index += 1
            start_index += 5  # Пропускаем тип и класс запроса
            qdcount -= 1

        # Парсим записи в разделе ответов
        for _ in range(ancount):
            name_ptr = self.get_domain_name(response, start_index)
            qtype, qclass, ttl, rdlength = struct.unpack('!HHIH', response[start_index + 10:start_index + 18])
            if qtype == 1 and qclass == 1 and rdlength == 4:  # IPv4 адрес
                ip = socket.inet_ntoa(response[start_index + 18:start_index + 22])
                return ip
            start_index += 18 + rdlength  # Переходим к следующей записи в ответе DNS

        return None  # Не удалось найти IPv4 адрес

    def encode_domain(self, domain):
        # Кодируем доменное имя в формат DNS
        labels = domain.split('.')
        encoded_labels = [len(label).to_bytes(1, 'big') + label.encode() for label in labels]
        return b''.join(encoded_labels) + b'\x00'

    def get_domain_name(self, response, start_index):
        # Получаем доменное имя из указателя в ответе DNS
        name = ''
        while True:
            length = response[start_index]
            if length == 0:
                break
            if length >= 192:
                # Переход по указателю
                offset = struct.unpack('!H', response[start_index:start_index + 2])[0] & 0x3FFF
                name += self.get_domain_name(response, offset)
                start_index += 2
                break
            name += response[start_index + 1:start_index + 1 + length].decode() + '.'
            start_index += length + 1
        return name.rstrip('.')
