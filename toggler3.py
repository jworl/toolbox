#!/usr/bin/python

"""
--- !deathtosecurity/^PWDI-attack
py author: Josh Worley
Version: 2
Date: 10/14/2016

function shoutout:
    - recipient: Amber
      example: all_casings
      url: stackoverflow.com
      path: >
        /questions/6792803/
        finding-all-possible-case-permutations-in-python
    - comment: |
        thank you for the explanation. you are amazing. <3
"""

from os import makedirs
from os import path
from os import statvfs
from pickle import dump
from sys import argv
from sys import exit
from sys import getsizeof


def _toggler(input_string):
    if not input_string:
        yield ""
    else:
        first = input_string[:1]
        print first
        if first.lower() == first.upper():
            for sub_casing in _toggler(input_string[1:]):
                yield first + sub_casing
        else:
            for sub_casing in _toggler(input_string[1:]):
                yield first.lower() + sub_casing
                yield first.upper() + sub_casing


def _loadlist(thefile):
    try:
        with open(thefile, 'r') as a:
            return a.read().splitlines()
    except IndexError:
        print 'Usage: ./toggler.py wordlist.file'
        exit(2)


def _diskspace(path):
    """
    Returns remaining disk space
    """
    s = statvfs(path)
    return s.f_bsize * s.f_bavail


def main():
    variations = {}
    for word in _loadlist(argv[1]):
        variations[word] = list(_toggler(word))

        """
        Test for the available disk space here
        """

        if path.isdir('dump') is False:
            makedirs('dump')
        if path.isdir('dump/pickles') is False:
            makedirs("dump/pickles")
        if path.isdir('dump/variants') is False:
            makedirs("dump/variants")

        dump(variations[word], open("dump/pickles/" + word + ".p", "w"))
        with open("dump/variants/" + word + ".dict", "w") as a:
            for variant in variations[word]:
                a.write(variant + '\n')

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit(1)
