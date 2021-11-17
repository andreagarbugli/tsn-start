# Notes

## `tc-taprio`

The Qdisc `taprio` permits to setup a TSN schedule based on IEEE 802.1Qbv. There are some parameters that could be of interest to discuss:

- `flags`: The parameter sets the flags for the entire time-aware window and schedule. Currently, seems that only the `0x1` flag is supported by `tc`. This flag set an _assisted mode_, which means that the `taprio_enqueue` routine automatically associate a _txtime_ to each packet that is enqueued in the window. In this way, if the packet is then received by the `etf` Qdisc, the latter can enqueue the packet without dropping it because of **Invalid Param** error.
- `txtime-delay`: The parameters can be used when we enable the **offload** mode in the `etf` Qdisc.

