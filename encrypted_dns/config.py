import os.path
import json


class Config:

    def __init__(self):
        self.DEFAULT_CONFIG = {}
        self.config = {}

    def get_config(self):
        return self.config

    def get_default_config(self):
        return self.DEFAULT_CONFIG

    def load(self, path):
        pass

    def save(self, path):
        pass
