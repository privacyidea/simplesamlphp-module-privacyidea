#!/bin/bash

echo "scp files to ucs - server 10.0.5.22 "
scp -r -q * root@10.0.5.22:/usr/share/simplesamlphp/modules/privacyidea

