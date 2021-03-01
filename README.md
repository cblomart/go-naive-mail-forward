# Go Naive Mail Forward

[![Go Report Card](https://goreportcard.com/badge/github.com/cblomart/go-naive-mail-forward)](https://goreportcard.com/report/github.com/cblomart/go-naive-mail-forward)
![Docker Cloud Build Status](https://img.shields.io/docker/cloud/build/cblomart/go-naive-mail-forward?style=plastic)

This project aims to provide mail forwarding service. 
It does use a simple rules to describe the fowardings to operate.

The service contains a few simple protection mechanisms:
* Sender Policy Framework: this will check that the source of the mail is an authorized sender
* Reverse Black list: checks the presence of the sender in known black list before sending

> **TODO**: allow enforcing signed message over tls 

The service supports starttls and will warn while relaying unsigned email or in clear text


## Rules

> **TODO**: define fallbacks smtp servers

Rules are defined per block separated by ";".
All blocks are evaluated to define the set of destinations addresses.

Each block is defined by multiple statements separated by ":".

The first statement defines the source address:
* can be defined as a mail address
* if empty will match all addresses of the domain
* the user part can contain the "*" wildcard that will match zero or more characters
* the user part can contain the "?" wildcard that will match exactly one character
* the user part can contain the "#" wildcard that will match exactly on digit
* the user part can be prefixed with "!" that will negate the match done

The following statements are destination addresses:
* they are mail addresses
* the domain cannot be the same as in the source statement
* if the user part is missing the user part of the source address is used

Samples

> Forward all mails for "test.it" to one user "admin@hello.com" : 
>
>```@test.it:admin@hello.com```

> Forward all users ending with fw in the "test.it" domain to the same user (fw included) in the "hello.com" domain:  
>
>```*fw@test.it:@hello.com```

> Forward all except "admin" in the "test.it" domain to one user "admin@hello.com":
>
>```!admin@test.it:admin@hello.com```