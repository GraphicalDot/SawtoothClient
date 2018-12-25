

BOB: The user who wants to store his mnemonic decentrally

Kanika, sofia, ravya, shikha and Asha are the users who will have a share of the mnemonic
  after it is split using shamir secret.

Shared_secret contracts which will be floated on shared_secret addresses who were
    derived from the random indexs generated from BOB's mnemonic.

Store Mnemonic

    THe user if wants to share his Mnemonic starts by making a ping /share_mnemonic api.
    The two args which will be accepted are :
        Email_list: list of email ids of the users who are already registred on the platform
        minimum required: Mimimum of users who when activated, Mnemmonic can be rev=covered from
                their share


    Now, BOB will generate 5 random indexes from 1 to 2**32 and get the corresponding
      Public/Private key pairs corresponding to these indexes,

    Bob will now generate 5 secret_share addresses from the public keys generated above.

    Encryption of Mnemonic with Scrypt key generated from BOB email address.



    NOw, according to the maximum and minimum shares rewiured Encrypted Menmonic will
    be split into secrets, minimum shares are required to recover the encrypted mnemonic.
    
    The whole point of encrypting the mnemonic before split is to tackle the case,
    in which if all any three of kanika, ravya, shikha, asha and sofia would collude
    to combine the mnemonic from their shares, THey cant recover it even if they know
    the BOB's user email address since they dont know the 32 byte salt used to
    generate scrypt key. the 32 bytes salt has entropy which cant be cracked as of now.

    Sharing the mnemonic with Users

    At this point, Sharemnemonic api will make five transactions and these transactions
    will be  shared with the account addresses of Kanika, Ravya, Shikha, asha and sofia.

    Each transaction will be genrated from the following process. Since the menmonic
    is already split into five shares.

    A new 16 bytes AES key will be generated  for every user,  Encrypt their share with
    AES key, and append tag in front and nonce at the back of the ciphertext

    Now encrypt the AES key with the public key of the account of the user, lets
    say public key present on kanika's account.

    Now float a transaction with all these details.
