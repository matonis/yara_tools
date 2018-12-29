#!/usr/bin/env python
"""Tools to make YARA interactions easier."""
import logging
import sys

from argparse import ArgumentParser
from yara_tools import yara_tools


def main():
    """Build me."""
    yr = yara_tools('Rule')
    raise NotImplementedError("TODO")
