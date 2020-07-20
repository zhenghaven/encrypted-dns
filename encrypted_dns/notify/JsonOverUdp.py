# MIT License

# Copyright (c) 2020 Haofan Zheng

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import json
import socket
import hashlib
import logging

class JsonOverUdpException(Exception):
	"""JsonOverUdp base exception"""

	def __init__(self, message):
		self.message = message

		super(JsonOverUdpException, self).__init__(self.message)

class JsonOverUdpHashMismatchError(JsonOverUdpException):
	"""Raised when parse error happened"""

	def __init__(self, hash1, hash2):

		super(JsonOverUdpHashMismatchError, self).__init__("The HASH of payload in the package (" + str(hash1) + ") doesn't match the HASH in the package (" + str(hash2) + ") .")

class StrUdpPack(object):
	def __init__(self, payload):
		self.payload = payload
		self.hash = hashlib.sha1(payload.encode()).hexdigest()

	def ToJsonStr(self):
		return json.dumps(self.__dict__)

	@staticmethod
	def ParseJsonStr(cls, jStr):
		jObj = json.loads(jStr)

		pack = cls(jObj["payload"])

		if jObj["hash"] != pack.hash:
			raise JsonOverUdpHashMismatchError(jObj["hash"], pack.hash)

		return pack

class StrOverUdp(object):
	def __init__(self, ip, port, bufSize, logger=None):
		self.ip = ip
		self.port = port
		self.bufSize = bufSize

		self.sock=socket.socket(socket.AF_INET, # Internet
								socket.SOCK_DGRAM) # UDP

		if logger is None:
			self.logger = logging.getLogger("StrOverUdp-" + self.ip + "-" + str(self.port))
		else:
			self.logger = logger

	def Send(self, msgStr):
		pack = StrUdpPack(msgStr)

		msgToSend = pack.ToJsonStr()

		self.logger.debug("Send data: " + msgToSend + "  To: " + str((self.ip, self.port)))

		self.sock.sendto(msgToSend.encode(), (self.ip, self.port))

	def Recv(self, bufSize=None):
		if bufSize is None:
			bufSize = self.bufSize

		self.sock.bind((self.ip, self.port))
		data, addr = self.sock.recvfrom(bufSize)

		dataStr = data.decode()

		self.logger.debug("Recv data: " + dataStr + "  From: " + str(addr))

		pack = StrUdpPack.ParseJsonStr(dataStr)

		return pack.payload


class JsonOverUdp(StrOverUdp):
	def __init__(self, ip, port, bufSize):

		self.logger = logging.getLogger("JsonOverUdp-" + ip + "-" + str(port))

		super(JsonOverUdp, self).__init__(ip, port, bufSize, self.logger)

	def Send(self, jObj):
		return super(JsonOverUdp, self).Send(json.dumps(jObj))

	def Recv(self, bufSize=None):
		msgStr = super(JsonOverUdp, self).Recv(bufSize)

		return json.loads(msgStr)
