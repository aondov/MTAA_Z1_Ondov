import socketserver
import socket
import sip_library

HOST_IP = '0.0.0.0'
HOST_PORT = 5060

if __name__ == '__main__':
    socket_pair = (HOST_IP, HOST_PORT)

    proxy_ip = socket.gethostbyname_ex(socket.gethostname())[-1][-1]

    record_route = "Record-Route: <sip:%s:%d;lr>" % (proxy_ip, HOST_PORT)
    top_via = "Via: SIP/2.0/UDP %s:%d" % (proxy_ip, HOST_PORT)
    sip_library.initializeGlobalVars(record_route, top_via)

    proxy_server = socketserver.UDPServer(socket_pair, sip_library.UDPHandler)
    proxy_server.serve_forever()
