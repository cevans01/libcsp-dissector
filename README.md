# libcsp-dissector
Libcsp plugin dissector for Wireshark

### About
This was made using the following as resources:

https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=doc/README.developer

https://www.wireshark.org/docs/wsdg_html_chunked/

https://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html

INSTALL

README.md

README.linux

doc/README.developer

doc/README.dissector

I also referenced the following rust implementation:
https://github.com/sevagh/wireshark-dissector-rs

And of course, references for the protocol we are trying to dissect, libcsp:

https://en.wikipedia.org/wiki/Cubesat_Space_Protocol

https://github.com/libcsp/libcsp


### How to use
First clone the git repo for Wireshark and go through its installation. (I made
a small fork which includes the necessary files to build the plugin along with
wireshark)

    sudo apt install libpcap0.8 libpcap0.8-dev libgcrypt11-dev libgcrypt20 libgcrypt20-dev libtool-bin libtool
    git clone https://github.com/cevans01/wireshark.git
    cd wireshark
    ./autogen.sh
    ./configure
    make -j12

