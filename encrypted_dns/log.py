import os
from time import gmtime, strftime


class Log:
    def __init__(self):
        self.init_time = self.get_time()
        self.log_file = None
        self.create_log()

    @staticmethod
    def get_time():
        return strftime("%Y-%m-%d-%H-%M-%S", gmtime())

    def create_log(self):
        file_name = "logs/" + self.init_time + '.log'

        if not os.path.isdir("logs"):
            os.mkdir("logs")

        if os.path.isfile(file_name):
            self.log_file = open(file_name, "a+")
        else:
            self.log_file = open(file_name, "w+")

    def write_log(self, message):
        time = self.get_time()
        self.log_file.write(time + ": " + message)
        self.log_file.write('\n')

    def close(self):
        self.log_file.close()
        self.log_file = None


