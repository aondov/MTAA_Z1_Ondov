#    Copyright 2014 Philippe THIRION
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import socketserver
import re
import string
import socket
# import threading
import sys
import time
import logging

rx_register = re.compile("^REGISTER")
rx_invite = re.compile("^INVITE")
rx_ack = re.compile("^ACK")
rx_prack = re.compile("^PRACK")
rx_cancel = re.compile("^CANCEL")
rx_bye = re.compile("^BYE")
rx_options = re.compile("^OPTIONS")
rx_subscribe = re.compile("^SUBSCRIBE")
rx_publish = re.compile("^PUBLISH")
rx_notify = re.compile("^NOTIFY")
rx_info = re.compile("^INFO")
rx_message = re.compile("^MESSAGE")
rx_refer = re.compile("^REFER")
rx_update = re.compile("^UPDATE")
rx_from = re.compile("^From:")
rx_cfrom = re.compile("^f:")
rx_to = re.compile("^To:")
rx_cto = re.compile("^t:")
rx_tag = re.compile(";tag")
rx_contact = re.compile("^Contact:")
rx_ccontact = re.compile("^m:")
rx_uri = re.compile("sip:([^@]*)@([^;>$]*)")
rx_addr = re.compile("sip:([^ ;>$]*)")
# rx_addrport = re.compile("([^:]*):(.*)")
rx_code = re.compile("^SIP/2.0 ([^ ]*)")
rx_invalid = re.compile("^192\.169")
rx_invalid2 = re.compile("^10\.")
rx_cseq = re.compile("^CSeq:")
rx_callid = re.compile("Call-ID: (.*)$")
rx_rr = re.compile("^Record-Route:")
rx_request_uri = re.compile("^([^ ]*) sip:([^ ]*) SIP/2.0")
rx_route = re.compile("^Route:")
rx_contentlength = re.compile("^Content-Length:")
rx_ccontentlength = re.compile("^l:")
rx_via = re.compile("^Via:")
rx_cvia = re.compile("^v:")
rx_branch = re.compile(";branch=([^;]*)")
rx_rport = re.compile(";rport$|;rport;")
rx_contact_expires = re.compile("expires=([^;$]*)")
rx_expires = re.compile("^Expires: (.*)$")

# global dictionnary
g_recordroute = ""
g_topvia = ""
registrar = {}
response_codes = {
    "OK": "200 Vsecko v poradku",
    "Not_Acceptable_Here": "488 Nemozem akceptovat toto tu",
    "Bad_Request": "400 Neviem co ziadas",
    "Temp_Unavailable": "480 Vyckaj chvilu, teraz nemozem",
    "Server_Error": "500 Server mi vyplo",
    "Not_Acceptable": "406 Tak toto ni",
    "Busy_Here": "486 Neni tu teraz",
    "Decline": "600 Nedviha"
}


def initializeGlobalVars(recordroute, topvia):
    global g_recordroute
    global g_topvia

    g_recordroute = recordroute
    g_topvia = topvia


def hexdump(chars, sep, width):
    str_chars = str(chars)
    while str_chars:
        line = str_chars[:width]
        str_chars = str_chars[width:]
        line = line.ljust(width, '\000')
        logging.debug("%s%s%s" % (sep.join("%02x" % ord(c) for c in line), sep, quotechars(line)))


def quotechars(chars):
    return ''.join(['.', c][c.isalnum()] for c in chars)


def showtime():
    logging.debug(time.strftime("(%H:%M:%S)", time.localtime()))


class UDPHandler(socketserver.BaseRequestHandler):

    def debugRegister(self):
        logging.debug("*** REGISTRAR ***")
        logging.debug("*****************")
        for key in registrar.keys():
            logging.debug("%s -> %s" % (key, registrar[key][0]))
        logging.debug("*****************")

    def changeRequestUri(self):
        # change request uri
        md = rx_request_uri.search(self.data[0].decode('utf-8'))
        if md:
            method = md.group(1)
            uri = md.group(2)
            if uri in registrar:
                uri = "sip:%s" % registrar[uri][0]
                self.data[0] = "%s %s SIP/2.0" % (method, uri)

    def removeRouteHeader(self):
        # delete Route
        data = []
        for line in self.data:
            if not isinstance(line, str):
                dline = line.decode('utf-8')
            else:
                dline = line
            if not rx_route.search(dline):
                data.append(dline)
        return data

    def addTopVia(self):
        branch = ""
        data = []
        for line in self.data:
            if not isinstance(line, str):
                dline = line.decode('utf-8')
            else:
                dline = line
            if rx_via.search(dline) or rx_cvia.search(dline):
                md = rx_branch.search(dline)
                if md:
                    branch = md.group(1)
                    via = "%s;branch=%sm" % (g_topvia, branch)
                    data.append(via)
                # rport processing
                if rx_rport.search(dline):
                    text = "received=%s;rport=%d" % self.client_address
                    via = dline.replace("rport", text)
                else:
                    text = "received=%s" % self.client_address[0]
                    via = "%s;%s" % (dline, text)
                data.append(via)
            else:
                data.append(dline)
        return data

    def removeTopVia(self):
        data = []
        for line in self.data:
            if not isinstance(line, str):
                dline = line.decode('utf-8')
            else:
                dline = line
            if rx_via.search(dline) or rx_cvia.search(dline):
                if not line.startswith(g_topvia):
                    data.append(dline)
            else:
                data.append(dline)
        return data

    def checkValidity(self, uri):
        addrport, socket, client_addr, validity = registrar[uri]
        now = int(time.time())
        if validity > now:
            return True
        else:
            del registrar[uri]
            logging.warning("registration for %s has expired" % uri)
            return False

    def getSocketInfo(self, uri):
        addrport, socket, client_addr, validity = registrar[uri]
        return (socket, client_addr)

    def getDestination(self):
        destination = ""
        for line in self.data:
            if not isinstance(line, str):
                dline = line.decode('utf-8')
            else:
                dline = line
            if rx_to.search(dline) or rx_cto.search(dline):
                md = rx_uri.search(dline)
                if md:
                    destination = "%s@%s" % (md.group(1), md.group(2))
                break
        return destination

    def getOrigin(self):
        origin = ""
        for line in self.data:
            if not isinstance(line, str):
                dline = line.decode('utf-8')
            else:
                dline = line
            if rx_from.search(dline) or rx_cfrom.search(dline):
                md = rx_uri.search(dline)
                if md:
                    origin = "%s@%s" % (md.group(1), md.group(2))
                break
        return origin

    def sendResponse(self, code):
        request_uri = "SIP/2.0 " + code
        self.data[0] = request_uri
        index = 0
        data = []
        for line in self.data:
            if not isinstance(line, str):
                dline = line.decode('utf-8')
            else:
                dline = line

            data.append(dline)

            if rx_to.search(dline) or rx_cto.search(dline):
                if not rx_tag.search(dline):
                    data[index] = "%s%s" % (dline, ";tag=123456")
            if rx_via.search(dline) or rx_cvia.search(dline):
                # rport processing
                if rx_rport.search(dline):
                    text = "received=%s;rport=%d" % self.client_address
                    data[index] = dline.replace("rport", text)
                else:
                    text = "received=%s" % self.client_address[0]
                    data[index] = "%s;%s" % (dline, text)
            if rx_contentlength.search(dline):
                data[index] = "Content-Length: 0"
            if rx_ccontentlength.search(dline):
                data[index] = "l: 0"
            index += 1
            if dline == "":
                break
        data.append("")
        text = "\r\n".join(data)
        self.socket.sendto(text.encode('utf-8'), self.client_address)
        showtime()
        logging.info("<<< %s" % data[0])
        logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def processRegister(self):
        fromm = ""
        contact = ""
        contact_expires = ""
        header_expires = ""
        expires = 0
        validity = 0
        authorization = ""
        index = 0
        auth_index = 0
        data = []
        size = len(self.data)
        for line in self.data:
            if rx_to.search(line.decode('utf-8')) or rx_cto.search(line.decode('utf-8')):
                md = rx_uri.search(line.decode('utf-8'))
                if md:
                    fromm = "%s@%s" % (md.group(1), md.group(2))
            if rx_contact.search(line.decode('utf-8')) or rx_ccontact.search(line.decode('utf-8')):
                md = rx_uri.search(line.decode('utf-8'))
                if md:
                    contact = md.group(2)
                else:
                    md = rx_addr.search(line.decode('utf-8'))
                    if md:
                        contact = md.group(1)
                md = rx_contact_expires.search(line.decode('utf-8'))
                if md:
                    contact_expires = md.group(1)
            md = rx_expires.search(line.decode('utf-8'))
            if md:
                header_expires = md.group(1)

        if rx_invalid.search(contact) or rx_invalid2.search(contact):
            if fromm in registrar:
                del registrar[fromm]
            self.sendResponse(response_codes["Not_Acceptable_Here"])
            return
        if len(contact_expires) > 0:
            expires = int(contact_expires)
        elif len(header_expires) > 0:
            expires = int(header_expires)

        if expires == 0:
            if fromm in registrar:
                del registrar[fromm]
                self.sendResponse(response_codes["OK"])
                return
        else:
            now = int(time.time())
            validity = now + expires

        logging.info("From: %s - Contact: %s" % (fromm, contact))
        logging.debug("Client address: %s:%s" % self.client_address)
        logging.debug("Expires= %d" % expires)
        registrar[fromm] = [contact, self.socket, self.client_address, validity]
        self.debugRegister()
        self.sendResponse(response_codes["OK"])

    def processInvite(self):
        logging.debug("-----------------")
        logging.debug(" INVITE received ")
        logging.debug("-----------------")
        origin = self.getOrigin()
        if len(origin) == 0 or origin not in registrar:
            self.sendResponse(response_codes["Bad_Request"])
            return
        destination = self.getDestination()
        if len(destination) > 0:
            logging.info("destination %s" % destination)
            if destination in registrar and self.checkValidity(destination):
                socket, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, g_recordroute)
                text = "\r\n".join(data)
                socket.sendto(text.encode('utf-8'), claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))
            else:
                self.sendResponse(response_codes["Temp_Unavailable"])
        else:
            self.sendResponse(response_codes["Server_Error"])

    def processAck(self):
        logging.debug("--------------")
        logging.debug(" ACK received ")
        logging.debug("--------------")
        destination = self.getDestination()
        if len(destination) > 0:
            logging.info("destination %s" % destination)
            if destination in registrar:
                socket, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, g_recordroute)
                text = "\r\n".join(str(data))
                socket.sendto(text.encode('utf-8'), claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def processNonInvite(self):
        logging.debug("----------------------")
        logging.debug(" NonInvite received   ")
        logging.debug("----------------------")
        origin = self.getOrigin()
        if len(origin) == 0 or origin not in registrar:
            self.sendResponse(response_codes["Bad_Request"])
            return
        destination = self.getDestination()
        if len(destination) > 0:
            logging.info("destination %s" % destination)
            if destination in registrar and self.checkValidity(destination):
                socket, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, g_recordroute)
                text = "\r\n".join(data)
                socket.sendto(text.encode('utf-8'), claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))
            else:
                self.sendResponse(response_codes["Not_Acceptable"])
        else:
            self.sendResponse(response_codes["Server_Error"])

    def processCode(self):
        origin = self.getOrigin()
        if len(origin) > 0:
            logging.debug("origin %s" % origin)
            if origin in registrar:
                socket, claddr = self.getSocketInfo(origin)
                self.data = self.removeRouteHeader()
                data = self.removeTopVia()
                text = "\r\n".join(data)
                socket.sendto(text.encode('utf-8'), claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def processRequest(self):
        # print "processRequest"
        if len(self.data) > 0:
            request_uri = self.data[0].decode('utf-8')
            if rx_register.search(request_uri):
                self.processRegister()
            elif rx_invite.search(request_uri):
                self.processInvite()
            elif rx_ack.search(request_uri):
                self.processAck()
            elif rx_bye.search(request_uri):
                self.processNonInvite()
            elif rx_cancel.search(request_uri):
                self.processNonInvite()
            elif rx_options.search(request_uri):
                self.processNonInvite()
            elif rx_info.search(request_uri):
                self.processNonInvite()
            elif rx_message.search(request_uri):
                self.processNonInvite()
            elif rx_refer.search(request_uri):
                self.processNonInvite()
            elif rx_prack.search(request_uri):
                self.processNonInvite()
            elif rx_update.search(request_uri):
                self.processNonInvite()
            elif rx_subscribe.search(request_uri):
                self.sendResponse(response_codes["OK"])
            elif rx_publish.search(request_uri):
                self.sendResponse(response_codes["OK"])
            elif rx_notify.search(request_uri):
                self.sendResponse(response_codes["OK"])
            elif rx_code.search(request_uri):
                self.processCode()
            else:
                logging.error("request_uri %s" % request_uri)

    def handle(self):
        data = self.request[0]
        self.data = data.split(b"\r\n")
        self.socket = self.request[1]
        request_uri = self.data[0].decode('utf-8')
        if rx_request_uri.search(request_uri) or rx_code.search(request_uri):
            showtime()
            logging.info(">>> %s" % request_uri)
            logging.debug("---\n>> server received [%d]:\n%s\n---" % (len(data), data))
            logging.debug("Received from %s:%d" % self.client_address)
            self.processRequest()
        else:
            if len(data) > 4:
                showtime()
                logging.warning("---\n>> server received [%d]:" % len(data))
                hexdump(data, ' ', 16)
                logging.warning("---")


