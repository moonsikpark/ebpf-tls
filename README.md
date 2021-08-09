# eBPF TLS Filter

This project aims to monitor and filter TLS {Client|Server}Hello packets using eBPF.

The goal of this project is to be able to 

a) tag TLS ClientHello packets by SNI extension.

b) tag TLS ServerHello packets by their certificates.

c) monitor and filter tagged packets using eBPF

# Copyright

Copyright (c) 2021 Moonsik Park. All rights reserved.
