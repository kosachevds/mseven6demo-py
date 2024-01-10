from dataclasses import dataclass
import sys


@dataclass
class Settings:
    host: str
    username: str
    password: str
    channel: str


def parse_args():
    return Settings(
        sys.argv[1],
        sys.argv[2],
        sys.argv[3],
        sys.argv[4],
    )
