# Go Naive Mail Forward

[![Go Report Card](https://goreportcard.com/badge/github.com/cblomart/go-naive-mail-forward)](https://goreportcard.com/report/github.com/cblomart/go-naive-mail-forward)
![Docker Cloud Build Status](https://img.shields.io/docker/cloud/build/cblomart/go-naive-mail-forward?style=flat)


[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcblomart%2Fgo-naive-mail-forward%2Fmaster%2Fazuredeploy.json)

This project aims to provide mail forwarding service. 
It does use a simple rules to describe the fowardings to operate.

The service contains a few simple protection mechanisms:
* Sender Policy Framework: this will check that the source of the mail is an authorized sender
* Reverse Black list: checks the presence of the sender in known black list before sending

> **TODO**: 
> * allow enforcing signed message over tls 
> * evaluate if checking SPF on helo hostname makes sense

> **OVER CONTAINERS AND SPF**:
> 
> Sender Policy Framework does provide a series of mechanisms to validate if a sender is authorized to send a mail.
>
> Most often this will rely on the source ip of the connection. This source IP cannot be easily identified in containers that are often natted.
>
> To the recieving end of the mail the source ip may also be randomised by your container platform. Especially when hosting containers in a cloud, the source IP may be difficult to identify.
>
> In these situation to avoid being flagged as spam it is always best to use DKIM to sign message. That is why a warning is provided when relaying unsigned messages.

The service supports starttls and will warn while relaying unsigned email or in clear text


## Rules

Rules are defined per block separated by ";".
All blocks are evaluated to define the set of destinations addresses.

Each block is defined by multiple statements separated by ":".

The first statement defines the source address:
* can be defined as a mail address
* if empty will match all addresses of the domain
* the user part can contain the ```*``` wildcard that will match zero or more characters
* the user part can contain the ```?``` wildcard that will match exactly one character
* the user part can contain the ```#``` wildcard that will match exactly on digit
* the user part can be prefixed with ```!``` that will negate the match done

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