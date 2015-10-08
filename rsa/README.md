# RSA demonstration

This simple RSA demonstration was created during my systemsecurity course at university<br>
It was designed to demonstrate simple RSA calculations based on 64bit integers

`p` and `q` should be chosen at random<br>
`n` is used as modulus for public and private keys<br>
`e` is the public key exponent<br>
`d` is the private key exponent

A sample run may look like:<br>
`./rsa_genkey      <p>   <q>`<br>
`	./rsa_genkey 11411 33533`<br>
`	Private key (e,n) = (43,382645063)`<br>
`	Public  key (d,n) = (169055867,382645063)`<br>
Now we have generated our keys

With the use of our public key we encrypt a sample message (1234567890)<br>
`./rsa_crypt enc        <m>   <e>    <n>`<br>
`	./rsa_crypt enc 123456789 43  382645063`<br>
`	166261588 <- our encrypted message`

Now we decrypt the given message with our calculated private key<br>
`./rsa_crypt dec        <m>       <d>      <n>`<br>
`	./rsa_crypt dec 166261588 169055867 382645063`<br>
`	123456789 <- our plaintext`

Now we try to bruteforce the private key, by prime factorization<br>
`./rsa_crack     <e>    <n>`<br>
`	./rsa_crack 43  382645063`<br>
`	Private key (d,n) = (169055867,382645063)`
