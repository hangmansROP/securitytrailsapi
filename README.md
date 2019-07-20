# SecurityTrails API
[![Build Status](https://travis-ci.org/hangmansROP/securitytrails-api.svg?branch=master)](https://travis-ci.org/hangmansROP/securitytrails-api) 
[![Known Vulnerabilities](https://snyk.io//test/github/hangmansROP/securitytrails-api/badge.svg?targetFile=requirements.txt)](https://snyk.io//test/github/hangmansROP/securitytrails-api?targetFile=requirements.txt)

This is an initial version of a module that wraps the SecurityTrails API. This should allow you to query each endpoint listed [here](https://docs.securitytrails.com/v1.0/reference).
The API itself doesn't require any form of authentication and so should be fairly easy to use. The main point to bare in mind is on a free account you are limited to 50 requests per month!

It should be noted that this wrapper was tested with a free account. All functionality that requires premium accounts will be marked as *_Experimental_* as I couldn't test it fully. If there's any issues with these endpoints, let me know or feel free to open a PR!