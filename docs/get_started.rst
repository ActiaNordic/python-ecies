===========
Get started
===========


Installation
============

From pypi
---------
In the future we hope to add the package to pypi so it can be installed by just doing pip install.

From source
-----------
Obtain the source from  gitlab (or wherever it is distributed)

Execute

.. code-block:: bash

    $ pip install .
    ...


Basic Usage
===========
python_ecies is a library, and as such does not currently have any command line tool to interact
with it.

Example usage
-------------

The below sample shows a quick example of how to use the library.

.. code-block:: python

    from cryptography.hazmat.primitives.asymmetric import ec
    import python_ecies
    import python_ecies.factory

    # Create a public/private key pair, using SECP256R1 curve
    my_private_key = ec.generate_private_key(ec.SECP256R1())

    # Setup a encryper/decrypter object, using one of the default configs
    E = python_ecies.factory.get_default_hkdf_aesgcm_binary()

    # Perform some encryption
    data = "Hello World!".encode()
    output = E.encrypt(data, my_private_key.public_key())
    print(output)

    # Perform validation and decryption
    decrypted = E.decrypt(output, my_private_key)
    print(decrypted)

In a real implementation the generation of the key would be one-time, offline and the private
key kept private while the public part can be distributed to anyone who should be allowed to encrypt
data.

Saving/loading of the public and private key can be done using commin python-cryptography functions.


Example usage using YubiHSM
---------------------------

The library has a few helpers to use private keys stored on YubiHSM hardware security modules.
Assuming a private key of the correct type is stored in slot 10, the code below shows an example
of how to use it for encryption and decryption.

Requires the yubihsm python library (available on pypi)

.. code-block:: python

    from cryptography.hazmat.primitives.asymmetric import ec
    import python_ecies
    import python_ecies.factory
    import python_ecies.yubihsm_helper
    import yubihsm

    # Connect to the YubiHSM and get a key wrapper object
    hsm = yubihsm.YubiHsm.connect()
    sess = hsm.create_session_derived(1, "password")
    key = sess.get_object(10, yubihsm.defs.OBJECT.ASYMMETRIC_KEY)
    my_private_key = python_ecies.yubihsm_helper.YubiPrivateKey(key)

    # Setup a encryper/decrypter object, using one of the default configs
    E = python_ecies.factory.get_default_hkdf_aesgcm_binary()

    # Perform some encryption
    data = "Hello World!".encode()
    output = E.encrypt(data, my_private_key.public_key())
    print(output)

    # Perform validation and decryption
    decrypted = E.decrypt(output, my_private_key)
    print(decrypted)
