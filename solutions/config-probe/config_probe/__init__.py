"""Read-only configuration probe for Amazon FSx for NetApp ONTAP, from an attacker's viewpoint.

The probe reads ONTAP settings over the REST API (GET only) and the AWS side of the file system
(read-only boto3 calls), and reports, for each setting, what an attacker who already holds a
given precondition could do with it. It is a configuration review, not a penetration test: it
sends no write, exploits nothing and stores no response body.

Modules:

* ``transport``  GET-only HTTPS client with certificate fingerprint pinning and lockout guard
* ``collect``    the ONTAP endpoints read, with their fields
* ``checks``     pure functions from collected records to findings, and output masking
* ``aws_side``   FSx, KMS and S3 Access Points reads through injectable boto3 clients
* ``cli``        argument parsing, secret selection, JSON output and exit codes
"""

from __future__ import annotations

import logging

SCHEMA = "config-probe/v1"

# botocore logs request and response bodies at DEBUG, and the GetSecretValue response holds the
# password. Keep the SDK loggers at WARNING whatever the root level is.
for _name in ("boto3", "botocore", "urllib3", "s3transfer"):
    logging.getLogger(_name).setLevel(logging.WARNING)
