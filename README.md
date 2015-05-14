# Cloud Detector

Cloud Detector scans your network for traffic from Dropbox, Box, SugarSync, and
other public cloud storage platforms. Detecting public cloud storage usage is
often necessary to prevent data leakage in the enterprise.

## Limitations

Currently, Cloud Detector only listens for DNS traffic and is therefore only
useful for detecting the number of public cloud installations on your network.

In the future, Cloud Detector could be extended to collect information about
the size of content, frequency of transfer, etc., associated with public cloud
server usage.

## Installation and Usage

Install the following prerequisites:

* `tshark` (the `wireshark` command line network analyzer).
* `python2.7`
* The following pip modules: `pyshark` and `tabulate`.

Run the Cloud Detector application using the following command. N.B.: you must
run this application in an appropriate network location, such that it is able
to see all the relevant traffic in your organization.

```
    python2.7 cloud-detector.py
```

For example,

```
    $ python cloud-detector.py 
    DNS Query: drive.google.com (src: 172.19.10.242)
    DNS Query: sugarsync.com (src: 172.19.10.242)
    DNS Query: sugarsync.com (src: 172.19.10.242)
    DNS Query: onedrive.google.com (src: 172.19.10.242)
    DNS Query: onedrive.google.com (src: 172.19.10.242)
    DNS Query: box.com (src: 172.19.10.242)
    DNS Query: box.com (src: 172.19.10.242)
    DNS Query: box.com (src: 172.19.10.242)
    DNS Query: box.com (src: 172.19.10.242)
    DNS Query: box.com (src: 172.19.10.242)
    DNS Query: dropbox.com (src: 172.19.10.242)
    DNS Query: dropbox.com (src: 172.19.10.242)
    ^C

    DNS Query Summary

    Domain                 Uniques    Total
    -------------------  ---------  -------
    box.com                      1        5
    drive.google.com             1        1
    dropbox.com                  1        2
    onedrive.google.com          1        2
    sugarsync.com                1        2
```
