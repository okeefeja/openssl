I'm trying to understand all the different variants of stealthy ECH we've discussed, and it turns out I have some questions about pretty much all of them. Here we go...

# SECH.2 Static OOB Secret
Something I'm still not sure about for the static OOB secret method is how we signal to the server that we are attempting SECH.
Does the server have to assume that every request might be an SECH request?
Do we include some sort of label which is bound to the symmetric key we are using to encrypt the data?
The only solution I see at the moment that doesn't violate stealthiness is for the server to attempt to decrypt the inner SNI etc. every time.

# SECH.3 Dynamic OOB Secret
I'm not actually sure what 'dynamic' is supposed to mean here. Does it mean that the secret is shared multiple times, e.g. every 90 days, or that from some master secret the successive symmetric keys are derived?
Is the motivation for the dynamic OOB secret to prevent repeated handshakes having the same cipher texts for SNI and ALPN? Isn't this already achieved by using and sending an Initialization Vector?I think I don't understand the motivation for this method compared to the static OOB secret method.

# SECH.4 Tickets
Since I don't think I understand SECH.3 and SECH.4 builds on SECH.3, I doubt I understand SECH.4 but let me make a guess.
When we first establish a connection we obviously have no ticket, so in this case the handshake starts off the same as in SECH.3, except that server returns an encrypted extension containing a session ticket (I guess this is already part of TLS1.3).As in session resumption in TLS 1.3, when we have a ticket we can send the ticket in the "pre_shared_key" extension. The ticket value is associated with a PSK, which the client uses to encrypt SNI etc. When the server sees the "pre_shared_key" extension it tries to decrypt the SNI etc. with the PSK.Couple of questions here: Is it ok to use the "pre_shared_key" extension, which is also used in normal TLS 1.3? I suppose if we use the "pre_shared_key" extension then we should behave as would be done in TLS 1.3 when using "pre_shared_key" with a session ticket value.And in this version would the PSK be the symmetric key for encrypting the inner SNI etc. or should a symmetric key be derived from it?

# SECH.5 PKC
I think I have a good understanding of this method, but for completeness here's what I'm thinking:
The client makes a DoH request to get the public key of the server it wishes to speak to.
We probably also want to validate the public key's association to the server with CAs.
The client encrypts the SNI etc. with server's public key (using an IV?).
The server attempts to decrypt with its private key. On success it carries on with key derivation etc. and responds with a signal of SECH acceptance,
e.g. an encrypted extension called "accept_sech".
On failure the server might also continue with key derivation and respond with ServerHello,
but will not include the "accept_sech" value, so now the client should abort the handshake.
The tricky stuff here will be finding enough entropy in the ClientHello to fit in the large digest for PKC.
