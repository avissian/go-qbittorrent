go-qbittorrent
==================

Golang wrapper for qBittorrent Web API (for versions above v4.1) forked from [superturkey650](https://github.com/superturkey650/go-qbittorrent) version (only supporting older API version)

This wrapper is based on the methods described in [qBittorrent's Official Web API](https://github.com/qbittorrent/qBittorrent/wiki/WebUI-API-(qBittorrent-4.1))

Some endpoints require qBittorrent features added after the v4.1-era baseline described in the wiki; use a current release and the API documentation for version-specific behavior.

An example can be found in go-qbittorrent.go.

A concise index of `qbt.Client` methods (grouped by source file): [METHODS.md](METHODS.md).

Installation
============

The best way is to install with go get::

    $ go get github.com/avissian/go-qbittorrent/qbt
