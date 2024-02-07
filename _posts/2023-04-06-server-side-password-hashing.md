---
title: "Server-side password hashing"
permalink: /post/server-side-password-hashing
layout: default
tags: authentication password hash SHA-1 SHA-256 salt PBKDF2 bcrypt scrypt rainbow
is_series: true
series_title: "Web Security"
series_number: 13
---

Real world applications that implement their own authentication process (e.g. user accounts with sign-in forms) must ensure user passwords are secured, and unreadable in the event the server is compromised.

Password hashing enables an application to verify a password provided by the user without the app's server ever having stored the password. The server instead stores a hash of the password, which is computationally infeasible to reverse back to the user's plaintext password - assuming a strong hashing algorithm is used correctly.

When a user's authenticity later needs to be verified, such as for a sign-in request, the password provided is then hashed using the same hashing algorithm, and verified that it matches the hash stored in the database.

### Typical Use-Case Scenario

Let's assume we've created a web app requiring user authentication.

The authentication is implemented by the application, instead of outsourcing authentication to an Identity Provider.

The user first creates an account by submitting their email and password securely in plaintext. 

The server typically creates an entry in its database for the user and stores their email, usually for a variety of verification and recovery purposes - but for this example it's only required along with their password to prove the user is authentic when they make a login request.

### Simple Hash Implementation

The password itself is not saved. Instead it is input to a type of algorithm called a [Cryptographic Hash Function](https://en.wikipedia.org/wiki/Cryptographic_hash_function) (CHF) which then returns its corresponding 'hash' value as a sequence of bits of fixed length, the length dependent on the CHF used - 256 bits in the SHA-256 algorithm we will demonstrate below. 

For readability and convenience this is often converted to its base64 equivalent, resulting in a fixed length string of 44 characters (for 256 bits), with no discernable pattern or structure. 

Using Powershell we can compute the SHA-256 hash for the password "Password123":

```powershell
$inputString = "Password123"

$sha256 = [System.Security.Cryptography.SHA256]::Create()
$bytes = [System.Text.Encoding]::UTF8.GetBytes($inputString)
$hashBytes = $sha256.ComputeHash($bytes)

$base64String = [System.Convert]::ToBase64String($hashBytes)

$binaryString = [System.Text.StringBuilder]::new()
foreach ($byte in $hashBytes) {
    $binaryString.Append([Convert]::ToString($byte, 2).PadLeft(8, '0'))
}

Write-Output "`nHash of $inputString in 256 bit binary: $binaryString"

Write-Output "`nHash of $inputString in base64: $base64String"
```

(<a href="https://gist.github.com/zola-25/4da0aea2421c1b11a16c5d265416bb98" target="_blank">Gist</a>)

Hash of Password123 in 256 bit binary: `00000000100011000111000000111001001011100011101010111111101111010000111110100100011110111011110000
10111011011001011010101010100110011011110101001001111000010101100101110010011111111100101110100000111100101110011010101011111010110011101
010011101011000000001`

Hash of Password123 in base64: `AIxwOS46v70PpHu8LtlqqZvUnhWXJ/y6Dy5qvrOp1gE=`

This hash is a simple fixed length string of different characters, and has the appearance of being randomly generated, although it is not. 

If the password differs only slightly, perhaps by one character, the CHF produces a hash with a completely different set of characters - this is a property all CHFs have and is called the [avalanche effect](https://en.wikipedia.org/wiki/Avalanche_effect).

For example, if our password is instead "Password12**4**", the SHA-256 hash in base64 becomes `UawBynkjzYgRe3aBNDuR0h0/a65csNlJYnCZ/AL0ubw=`

CHFs are designed to ensure a 'uniform distribution' of hash value character string combinations. As long as we use a strong, industry-proven CHF that creates sufficiently large hash values - 256 bits is considered large enough for most use cases - each possible hash value is equally probable of being computed for a password.

SHA-256 generates hash values of 256 bits in length, resulting in 2<sup>256</sup> possible hash values, each one having a probability of 1 / 2<sup>256</sup> of being chosen, which is [effectively impossible to guess](https://crypto.stackexchange.com/a/45310).

It's important to note that this doesn't imply randomness in the CHF - the algorithm is deterministic and for a known plaintext password, exactly one of the 2<sup>256</sup> possible hashes will have a 100% probability of being generated.

### Simple Hashing Vulnerabilities

The previous example demonstrates a rudimentary approach to securing passwords through hashing. When hashing was introduced as a security measure, over time vulnerabilities in the process became evident. If an attacker gains access to the to the database, obtaining the password from a hash can be possible, especially if the CHF used is known to the attacker. 

An attacker could simply hash random string combinations and see if the resulting hash matched any stored in the database. The larger the database, the more likely a match will be found. This is the 'brute force' approach, relying on simply processing power, and hence time. 

Instead, an attacker could do the hash processing first, by pre-computing password/hash combinations and storing them, before performing the lookup - but simply storing the hash for every possible string would require an impossible amount of storage. A more realistic approach would be pre-computing hashes for a set of likely passwords. This is a pre-computed 'dictionary attack'. Many pre-generated hash/password databases for typical CHFs exist, for vast numbers of word and character combinations. These are often made using algorithms to generate human-memorable passwords, including typical letter-digit substitutions.

The use of memorable passwords makes dictionary attacks more successful. Dictionary attacks aren't effective when random strings are used as passwords. Password managers can be helpful to generate and store large, random strings for passwords. Attackers are then forced back to hashing random string combinations. However there is an additional type of attack that uses pre-computation of vast numbers of possible string/hash combinations, but requires only a limited amount of storage space. These are '[Rainbow Tables](https://kestas.kuliukas.com/RainbowTables/)', constructed from reproducible chains of string hashing and hash-to-string 'reducing'. Depending on password size and possible characters, these chains can cover a large percentage of possible string/hash combinations, but their reproducibility means they can be omitted from the final table - drastically reducing its size. For an attacker, a Rainbow Table can then be used to deduce a password from a hash by reproducing some of these chains - so Rainbow Tables trade increased processing time for realistic storage size. 

#### 2012 LinkedIn Data Breach

A notable example of the vulnerabilities of simple hashing techniques is the [2012 LinkedIn data breach](https://en.wikipedia.org/wiki/2012_LinkedIn_hack). Passwords were stored [unsalted](/post/server-side-password-hashing#salting) using the compromised SHA-1 algorithm. The user database was leaked and a large proportion of passwords were cracked using rainbow tables and dictionary attacks.

### Secure Cryptographic Hash Functions

Modern password hashing uses Secure Cryptographic Hash Functions. These Secure CHFs have advantages over traditional CHFs:

1. **Adaptability**
   
   Secure CHFs can allow the adjustment of the computational resources needed to derive a hash. This is designed to make the generation of vast amounts of password/hash combinations computationally impractical for an attacker, while ensuring hash generation speed for legitimate purposes is practical.

2. **Salting** 
   
   <a name="salting"></a>
   
   A salt is a random value generated for each password, and added to the password before hashing. The salt is then stored, unencrypted, with the resulting hash. For later password verification, the hash is recreated by including the salt in the hash algorithm. 
   
   Password salting ensures:
   
	1. Unique hashes for identical passwords  
      
	   This prevents an attacker from identifying duplicate passwords in a database
      
	2. Pre-computation attack protection  
      
	   Pre-computation attacks become impractical, as an attacker must compute hashes for each possible salt-password combination, making the resulting tables exponentially larger compared to ones generated for just password plaintext. 
   
   A unique salt should be generated for every password, and whenever a password is changed. Salts are usually generated by a [Cryptographically secure pseudorandom number generator](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator) (CSPRNG), ensuring they are unpredictable, without any pattern or structure, and independent of each other. These properties ensure an attacker cannot guess anything about the salt that may aide them in an attack.
   
   Salts are generated as a fixed-length string of bits, with the longer the salt, the more security provided. 

	However the longer the salt, the more storage space required, and a salt of 128 bits is generally considered secure for password hashing scenarios.

***

While there are CHFs that are secure against collision attacks, like SHA-256, only CHFs that provide all of the above advantages are considered 'Secure Cryptographic Hash Functions', making them suitable for modern-day password security. Such Secure CHFs include PBKDF2, bcrypt and scrypt. The ASP.NET Core Identity framework uses PBKDF2.

Using a CHF like SHA-256 alone is not considered 'Secure' for password hashing purposes. These kinds of CHFs designed to be fast, and are used for other purposes than password hashing. Secure CHFs, on the other hand, are designed to be slow for attack prevention. 

Secure CHFs often use algorithms such as SHA-256 as a component of their hash generation algorithm.


#### Dictionary-attack Example with Salting and Computation Adjustment protections

Even in the event the user database is compromised, there are additional properties of the hashing process that can prevent an attacker from cracking the hashed passwords. 

First let's demonstrate dictionary attack on a compromised database. In a dictionary attack, the attacker has a large list of common, 'guessable' passwords. The compromised database will include all password hashes along with each hash's unique salt that was used to generate it by the hashing function. The attacker's list of guessable passwords does not come with pre-computed hashes - the unique salt makes it necessary to compute a hash for each salt/password combination. 

If the attacker knows the hashing algorithm, they input a guessable password, along with one of the database's salts, and see if the resulting hash matches the hash in the database created from the salt.

The full attack involves attempting every guessable password with every database salt. For each password, the attacker hashes it with every salt in the database, checking for matches in the list of stored hashes.

Some dictionary attacks attempt millions of common passwords. So if we consider the scenario where the attacker has one million guessable passwords, and a compromised database of 10,000 hashes and salts, the attacker would run the hashing algorithm 10 billion times in an attempt to generate a hash that matched one in the database. If they found a match, they'd have found the genuine password that corresponded to that hash.

10 billion hash creations is obviously a lot, but the feasibility of such an attack depends on the execution time of the particular hash algorithm. Strong CHFs are designed to be computationally resource intensive, making them sufficiently slow, which helps mitigate against this kind of dictionary attack and other 'brute-force' methods. 

Ideally they are slow enough to mitigate these attacks but not so slow that their legitimate uses are affected, such as fast credential verification for authentication. Typically these algorithms are configured to generate a hash in 0.1-1 seconds. 

In our dictionary attack example, a 0.5 second hash time would take 158 years to test all one million guessable passwords.

Once an algorithm's computational parameters have been set, they cannot be changed without changing the algorithm's hash outputs. If an attacker changes the parameters to be much faster, so they can test a massive numbers of potential passwords as quickly as possible, the adjusted algorithm will just create different hashes that won't match those of the original algorithm.

***

### Additional precautions

This article highlighted how to securely hash user passwords stored on a server. It's worth noting additional precautions that mitigate password exposure:

1. Limiting number of login attempts within a set time period. This becomes a vital protection in the event an attacker's range of potential guesses is very low, if for example they already know a portion of the user's password.
   
2. Notifying users of login attempts, particularly emphasizing those that failed and are from new devices or locations.

3. Ensuring a minimum degree of password complexity. This should avoid enforcing overly complex passwords that are impossible to memorize, that are often stored insecurely by the user, becoming vulnerable to exposure. However, modern password manager applications are invaluable tools that both allow password complexity and minimizing exposure risk.

4. Enforcing HTTPS and maintaining certificate validity.

5. Encouraging Multi-factor Authentication.

