#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Copyright (c) 2015 David I. Urbina, david.urbina@utdallas.edu
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
"""Functions and constants to scale current 4-20 mA to measurements, and vice versa.
"""


class P1Level:
    EUMAX = 1225.0
    EUMIN = 0.0
    RAWMAX = 31208.0
    RAWMIN = 0.0


class P1Flow:
    EUMAX = 10.0
    EUMIN = 0.0
    RAWMAX = 31208.0
    RAWMIN = -15.0


def current_to_signal(raw_in, scaling):
    """Scales the input signal from current 4 - 20 mA to the human readable measurements."""
    result = raw_in - scaling.RAWMIN
    result *= (scaling.EUMAX - scaling.EUMIN) / (scaling.RAWMAX - scaling.RAWMIN)
    result += scaling.EUMIN
    return result


def signal_to_current(scale_in, scaling):
    """Scales the input signal from human readable measurements to current 4 - 20 mA."""
    result = scale_in - scaling.EUMIN
    result /= (scaling.EUMAX - scaling.EUMIN) / (scaling.RAWMAX - scaling.RAWMIN)
    result += scaling.RAWMIN
    return 0 if result < 0 else result
