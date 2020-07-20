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

import logging

from .JsonOverUdp import JsonOverUdp
from .Utils import AnswersToObj

class LocalNotifier(object):
	def __init__(self, port):
		self.port = port
		self.sender = JsonOverUdp("127.0.0.1", port, 1024 * 1024)

		self.logger = logging.getLogger("LocalNotifier-" + str(self.port))

	def Notify(self, group, question, response, question_name, match):
		self.logger.debug("Notifying local port(s) for question name: " + question_name + "...")
		note = {
			"type"   : "outbound",
			"q_msg"  : question.to_text(),
			"r_msg"  : response.to_text(),
			"q_name" : question_name,
			"tag"    : group['tag'],
			"match"  : match,
			"a_list" : AnswersToObj(response.answer)
		}
		self.logger.debug("Notifying port " + str(self.port) + "...")
		self.sender.Send(note)
