# isaac [![Build Status](https://travis-ci.org/irontec/isaac.svg)](https://travis-ci.org/irontec/isaac)

Isaac (Ivozng simplified Asterisk AMI Connector) is a small application that serves as interface and translator for Asterisk Manager Interface (aka AMI).
 
This interface has a little big problem: It broadcast all events to all clients, no matter if they are interested or not in the information.

Issac uses a small protocol, where each command is called action and must be implemented in loadable module.

## Installing

Prerequisites

 - libconfig - for configuration parsing
 - libedit - for CLI implementation

On most systems the commands to build will be the standard autotools procedure:

    ./bootstrap.sh
	./configure
	make
	make install (as root)

## Usage

See `--help` for a list of available flags and their syntax

To start isaac just type `isaac` or `isaac -d` if you want to run in foreground.

You can connect any isaac server through its CLI using `isaac -r`   

## License 
    isaac - SIP Messages flow viewer
    Copyright (C) 2013-2015 Irontec S.L.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations
    including the two.
    You must obey the GNU General Public License in all respects
    for all of the code used other than OpenSSL.  If you modify
    file(s) with this exception, you may extend this exception to your
    version of the file(s), but you are not obligated to do so.  If you
    do not wish to do so, delete this exception statement from your
    version.  If you delete this exception statement from all source
    files in the program, then also delete it here.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

