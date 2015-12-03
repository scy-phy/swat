#!/bin/bash
# based on http://stackoverflow.com/questions/12121558/how-to-develop-netfilter-queue-in-centos-6
git clone git://git.netfilter.org/libnfnetlink.git /* needed for dependency */
git clone git://git.netfilter.org/libnetfilter_queue.git
git clone https://github.com/kti/python-netfilterqueue.git
cd libnfnetlink
./autogen.sh
./configure --prefix=/usr
make
sudo make install
cd ../libnetfilter_queue
./autogen.sh
./configure --prefix=/usr
make
sudo make install
cd ../python-netfilterqueue
sudo python setup.py install
