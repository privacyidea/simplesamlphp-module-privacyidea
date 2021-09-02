#!/bin/bash

echo "scp files to saml - server 192.168.56.115 "
scp -r -q * root@192.168.56.115:/var/simplesamlphp/modules/privacyidea

