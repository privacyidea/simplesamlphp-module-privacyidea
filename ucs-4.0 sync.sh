#!/bin/bash

echo "scp files to ucs - server 192.168.56.102 "
scp -r -q * root@192.168.56.102:/usr/share/simplesamlphp/modules/privacyidea

