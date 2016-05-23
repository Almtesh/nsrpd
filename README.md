# Special notice
I'm not the author of that, so I'm not sure that the name NSRPD means actually "Network sharing routes protocol daemon".
The original author is Emmanuel "Mahoru Tsunemi" JOORIS, but he will not maintain this code since he died on March 2014.

The project was firstly named "lapis" before taking the name of "nsrpd".

If you nead maintenance on the code, open an issue, either, I will keep the code as is.

# Purpose
This program is a network routes sharer, it used on interconnected routers to share their local routes.

It was written in first place for a VPN inter-connection between multi-lan sites, but does not manage networks conflits.

# Usage
Open the script to change the configs at the beginning.

MCAST_LAPIS_IFACE: the VPN or inter-routers network interface

IGNORE_IFACE: list of interfaces names to ignore in route computation

MCAST_ANNOUNCE_TIME: interval between discoveries

NET_CALC_TIME: interval between networks computations

NET_GC_TIME: I don't know

STATIC_KEY: shared key between nodes

SECURITY: I don't know

Then, start it as root on every routers of the network.
