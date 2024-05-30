import socket
import pickle
import threading
import time

from dns_generator.dns_generator import DNSGen


class DNSCache:
    def __init__(self):
        self.cache = {}
        self.lock = threading.Lock()

    def add_record(self, domain, record):
        with self.lock:
            self.cache[domain] = record

    def get_record(self, domain):
        with self.lock:
            return self.cache.get(domain)

    def remove_expired_records(self):
        with self.lock:
            current_time = time.time()
            self.cache = {domain: record for domain, (expiration_time, record) in self.cache.items() if
                          expiration_time > current_time}

    def serialize_cache(self):
        with open('dns_cache.pickle', 'wb') as f:
            pickle.dump(self.cache, f)

    def deserialize_cache(self):
        try:
            with open('dns_cache.pickle', 'rb') as f:
                self.cache = pickle.load(f)
        except FileNotFoundError:
            pass


class DNSServer:
    def __init__(self, cache):
        self.cache = cache
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind(('localhost', 53))
        self.dns_gen = DNSGen(data=None)  # Pass data=None initially

    def handle_request(self, data, addr):
        self.dns_gen.data = data  # Set the data attribute of DNSGen
        response_data = self.dns_gen.make_response()
        self.server_socket.sendto(response_data, addr)

    def run(self):
        while True:
            data, addr = self.server_socket.recvfrom(1024)
            threading.Thread(target=self.handle_request, args=(data, addr)).start()



if __name__ == '__main__':
    cache = DNSCache()
    cache.deserialize_cache()
    server = DNSServer(cache)
    server_thread = threading.Thread(target=server.run)
    server_thread.start()

    try:
        while True:
            time.sleep(10)  # Периодически удаляем устаревшие записи из кэша
            cache.remove_expired_records()
            cache.serialize_cache()
    except KeyboardInterrupt:
        cache.serialize_cache()
        server.server_socket.close()
