# Tinyproxy:EX

## About

*Tinyproxy:EX* is a fast light-weight HTTP/FTP proxy for POSIX operating
systems. It is based on the well known tinyproxy-1.6.3 code base.
*Tinyproxy:EX* adds FTP-Support, basic ACLs to extend tinyproxy's filtering
capabilities and maybe much more in the future.

## :EX what?

I've started to develop *Tinyproxy:EX*, because I needed a small
HTTP/FTP-Proxy for a ressource restricted device. There are billions of
proxies out there, but either they are are bloated, dead, converted to
c++, ancient or simply not able to do FTP. Or even all of it.

So, you may choose from one of the following terms:

* :Ex-tended
* :Ex-hausted
* :Ex-orbitant
* :Ex-aggerated
* :Ex-pandable
* "to be filled by your favorite :EX-word"

## Features

Apart from functionality inherited from tinyproxy-1.6.3, *Tinyproxy:EX*
supports the following features:

* Access control: *Tinyproxy:EX* can be configured to allow access only
  from certain subnets/ip-ranges and/or certain ip addresses.
* Filtering: Based on access control lists, *Tinyproxy:EX* is able to
  allow or block the access to different ressources for each client
  traversing the proxy.
* FTP-Support: Tinyproxy:EX supports "FTP over HTTP" like squid (and a
  handfull other proxies).
* Small footprint: Compiled and linked against a small libc
  implementation like [dietlibc](http://www.fefe.de/dietlibc/) or
  [uClibc](http://www.uclibc.org/), *Tinyproxy:EX* is ideal for use
  within embedded environments.
* Support for Upstream-Proxies: *Tinyproxy:EX* can forward and
  authenticate requests to Upstream-Proxies.
* Limitted support to serve local files: This will give you the ability,
  to serve nicer Error-Pages (with icons, stylesheets, backgrounds and
  all the other nifty stuff.
* Better logging: Access logging with source ip, bytes sent and
  received, time elapsed per connection...

## Planned features

* Time based access control
* Full transparent proxy support: TPROXY
* Full HTTP/1.1 support
* IPv6 support
* Support more broken FTP-Servers: like ftp://ftp.cisco.com

## Download

Currently there is no stable release available at all. Nevertheless you
can obtain the sources via GIT.

## Build

In order to build *Tinyproxy:EX* you need [CMake](http://www.cmake.org/) which
is included by default in most modern Linux distributions.

    git clone https://github.com/tenchman/tinyproxy-ex.git
    mkdir tinyproxy-ex.build
    cd tinyproxy-ex.build
    ccmake ../tinyproxy-ex
    make
    sudo make install
