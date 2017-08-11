Apia 1.0.11-rc1
=============

What is Apia?
--------------

[Apia](https://apia.network/) is an implementation of the "Zerocash" protocol.
Based on Bitcoin, and [Zcash](https://z.cash/) code, it intends to offer a far higher standard of privacy
through a sophisticated zero-knowledge proving scheme that preserves
confidentiality of transaction metadata. Technical details are available
in our [Protocol Specification](https://github.com/zcash/zips/raw/master/protocol/protocol.pdf).

This software is the Apia client. It downloads and stores the entire history
of Apia transactions; depending on the speed of your computer and network
connection, the synchronization process could take a day or more once the
blockchain has reached a significant size.

Security Warnings
-----------------

See important security warnings in
[doc/security-warnings.md](doc/security-warnings.md).

**Apia is experimental and a work-in-progress.** Use at your own risk.

Deprecation Policy
------------------

This release is considered deprecated 16 weeks after the release day. There
is an automatic deprecation shutdown feature which will halt the node some
time after this 16 week time period. The automatic feature is based on block
height and can be explicitly disabled.

Where do I begin?
-----------------
We have a guide for joining the Apia network:
https://github.com/apia/apia/wiki/1.0-User-Guide

### Need Help?

* See the documentation at the [Apia Wiki](https://github.com/apia/apia/wiki)
  for help and more information.
* Ask for help on the [Apia](https://forum.apia.network/) forum.

Participation in the Apia project is subject to a
[Code of Conduct](code_of_conduct.md).

Building
--------

Build Apia along with most dependencies from source by running
./util/build.sh. Currently only Linux is officially supported.

License
-------

For license information see the file [COPYING](COPYING).
