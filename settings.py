import argparse
from dataclasses import dataclass
import sys


@dataclass
class Settings:
    host: str
    username: str
    password: str
    channel: str


def parse_args():
    parser = argparse.ArgumentParser(
        prog='mseven6demo',
        description='collecting eventlog records via ms-even6 protocol'
    )
    parser.add_argument('-a', '--address', required=True)
    parser.add_argument('-u', '--user', required=True)
    parser.add_argument('-p', '--password', required=True)
    parser.add_argument('-c', '--channel', required=True)
    data = parser.parse_args()
    return Settings(data.address, data.user, data.password, data.channel)
