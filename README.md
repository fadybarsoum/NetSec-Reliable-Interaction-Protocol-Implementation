Hello~

This is my RIP and KISS protocols implementation.

Important Notes:
- If you want to turn on debug messages (they'll be green and start with "[RIP]" to make it easy to see), in the RIPProtocol Class, in __init__, change s.debug to True. There are two other printouts for debugging (status and error) you can turn on there.
- CERTIFICATE CHAIN VALIDATION IS BAD! There are three known vulnerabilities I haven't patched: issuer vs parent's subject verification, common name vs peer address checking, and parent's common name prefixing the current certificate's common name.

I think that's basically it.
