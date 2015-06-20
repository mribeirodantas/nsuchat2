# NSUChat2 (Not So Unsafe Chat, 2nd attempt)

#### Important Note: NSUChat should NOT be used in a real scenario. I developed it in order to perfect my skills in network programming, cryptography and Python but it lacks several features that make a network application really safe. That's why I named it Not So Unsafe Chat, though it is still somewhat safe.

## What is it?

NSUChat was born out of a final project for the Computer Networks class at university. Every student was supposed to develop a chat application with its own application protocol in which several users should be able to connect, talk, get the list of connected users and send private messages. All this sencrypted with a global symmetric key. Flawed, isn't it? Well, it wasn't a cryptography or network security class, so I guess it's fine. I wanted to make it better so I developed NSUChat which had assymetric criptography for the exchange of symmetric keys. Yes, keys. Every user would have its own personal and unique symmetric key so that even if you're within the chat, you can't easily break anybody else messages. I implemented my own algorithms for doing such and even my own event loop and so on. It worked well for the tested cases and assured me a great grade. However, the code wasn't beautiful and efficent and well, it was basically the first time I tried to develop a "safe" chat.

NSUChat2 is the second real attempt built from scratch with all the experience obtained from NSUChat. I'm using RSA (assymetric criptography) to exchange the symmetric keys (that are really [pseudo]random now, not specific "unique" values I chose), which in the other hand use the AES cipher. Also, the application protocol is much more efficient. All data units have headers with the same length (two bytes) and are well described in the apdu.py file (Application Protocol Data Units). I still implement my own event loop, and for sure I would use Twisted in a real world application, but I think it's good to try to build your own stuff before using some ready to use solution. I also use pickle for transfering Python objects through a socket and this should NOT be done if you can't guarantee a few things. It's easy to break things if you have malicious information being sent.

Anyways, I hope you learn something from it, even if it's how NOT to do something :-D. It's distributed under the terms of the GNU General Public License version 3 or any other version later released by the Free Software Foundation, which means I really care about freedom. This software is free software (free as in freedom, but coincidently free as free ber too :-)

Marcel Ribeiro Dantas <mribeirodantas at fedoraproject.org>
http://mribeirodantas.fedorapeople.org

