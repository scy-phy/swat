# -*- coding: utf-8 -*-
# Copyright (c) 2015 David I. Urbina, UTD
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
from __future__ import print_function
import cmd
import importlib
import os


class SwatCmd(cmd.Cmd):
    module = None

    @staticmethod
    def __start():
        print('*** Nothing to start! Did you forget to load a module?')

    @staticmethod
    def __configure():
        print('*** Nothing to configure. Did you forget to load a module?')

    @staticmethod
    def __params():
        print('*** Nothing to display! Did you forget to load a module?')

    def __init__(self, **kwargs):
        self.prompt = '({}) '.format(self.__class__.__name__.lower())
        cmd.Cmd.__init__(self, **kwargs)

    def do_load(self, line):
        """Load an module. Check List for all available modules."""
        if line == '':
            print('*** ERROR: Not module name selected')
            return
        try:
            self.module = importlib.import_module(line)
        except ImportError as e:
            print('*** ERROR:', e)
            self.module = None

        if self.module:
            self.prompt = '({}:{}) '.format(self.__class__.__name__.lower(), line)
        else:
            self.prompt = '({}) '.format(self.__class__.__name__.lower())

    def do_configure(self, line):
        """Configure loaded module"""
        if not self.module:
            self.__configure()
        else:
            self.module.configure()

    # TODO: add command to list all available modules
    def do_list(self, line):
        """List all available modules"""
        print('*** TODO: not implemented... yet!!!')

    def do_params(self, line):
        """Display the configuration param of the current loaded module, if any."""
        if not self.module:
            self.__params()
        else:
            self.module.params()

    def do_start(self, line):
        """Start module execution. Stop with Ctrl-C"""
        if not self.module:
            self.__start()
        else:
            self.module.start()

    def do_shell(self, line):
        """Run a shell command"""
        print("running shell command:", line)
        output = os.popen(line).read()
        print(output)
        self.last_output = output

    def do_quit(self, line):
        """Exit command line interface. You can also use Ctrl-D."""
        return True

    do_EOF = do_quit
