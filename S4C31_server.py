from time import sleep
from S4C28 import sha1
from S2C10 import xor_data
from binascii import unhexlify
from socketserver import TCPServer, StreamRequestHandler
from http.server import BaseHTTPRequestHandler, HTTPServer
from flask import Flask, request
from urllib.parse import urlparse, parse_qs

key = b"YELLOW_SUBMARINE"
delay = 0.005     # Change depending on the challenge


def hmac_sha1(key, message):
    """Returns the HMAC-SHA1 for the given key and message. Written following Wikipedia pseudo-code."""

    if len(key) > 64:
        key = unhexlify(sha1(key))
    if len(key) < 64:
        key += b'\x00' * (64 - len(key))

    o_key_pad = xor_data(b'\x5c' * 64, key)
    i_key_pad = xor_data(b'\x36' * 64, key)

    return sha1(o_key_pad + unhexlify(sha1(i_key_pad + message)))


def insecure_equals(s1, s2):
    """Implements the == operation by doing byte-at-a-time comparisons with early exit
    (ie, return false at the first non-matching byte). Sleeps 50ms after each byte.
    """
    for b1, b2 in zip(s1, s2):
        if b1 != b2:
            return False

        sleep(delay)

    return True


# region http web servers which do not use Flask
class RequestHandler(StreamRequestHandler):
    """Possible implementation of a request handler for a web server in Python."""

    RESPONSE_500 = b'HTTP/1.1 500 Internal Server Error\n'
    RESPONSE_200 = b'HTTP/1.1 200 OK\n'

    def handle(self):
        """Example link: http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
        Verify that the "signature" (HMAC-SHA1) on incoming requests is valid for "file".
        """
        request = self.rfile.readline().strip().decode()
        path = request.split()[1]
        result = urlparse(path)

        if result.path == '/test':
            q = parse_qs(result.query)

            file = q['file'][0].encode('ascii')
            digest = hmac_sha1(key, file).encode()
            signature = q['signature'][0].encode()

            if insecure_equals(digest, signature):
                print(request, "\t200 OK")
                self.wfile.write(self.RESPONSE_200)

            else:
                print(request, "\t500 BAD")
                self.wfile.write(self.RESPONSE_500)

        else:
            self.wfile.write(self.RESPONSE_500)


class HTTPRequestHandler(BaseHTTPRequestHandler):
    """Another possible implementation of a request handler for a web server in Python."""

    def _set_headers(self):
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        """Example link: http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
        Verify that the "signature" (HMAC-SHA1) on incoming requests is valid for "file".
        """
        result = urlparse(self.path)

        if result.path == '/test':
            q = parse_qs(result.query)

            file = q['file'][0].encode('ascii')
            digest = hmac_sha1(key, file).encode()
            signature = q['signature'][0].encode()

            if insecure_equals(digest, signature):
                self.send_response(200)
                self._set_headers()

            else:
                self.send_response(500)
                self._set_headers()

        else:
            self.send_response(500)
            self._set_headers()


def run_server(server_class, handler_class):
    """Run the server of the specified server_class with the given handler."""
    server_address = ('localhost', 8082)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()
# endregion


app = Flask(__name__)


@app.route('/test', methods=['GET'])
def login():

    # This example server supports only HTTP POST requests
    if request.method == 'GET':

        file = request.args.get('file').encode()

        digest = hmac_sha1(key, file).encode()
        signature = request.args.get('signature').encode()

        if insecure_equals(digest, signature):
            return "OK", 200

        else:
            return "BAD", 500


def main():
    """NOTE: choose only one of the three HTTP server implementations. They work the same.
    I did three just because I wanted to try them. In the end I realized that the simplest one
    was Flask.
    """
    # run_server(HTTPServer, HTTPRequestHandler)
    # run_server(TCPServer, RequestHandler, delay)
    app.run(port=8082)


if __name__ == '__main__':
    main()
