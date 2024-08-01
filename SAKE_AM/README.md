# SAKE-AM

SAKE-AM es la variante 'Agressive-mode' del protocolo SAKE. SAKE es un protocolo de intercambio de claves simétricas que permite establecer claves de sesión seguras entre las entidades participantes.

Este protocolo fue desarrollado y publicado en 2019 por Gildas Avoine, Sebastian Canard y Loic Ferreira.

En este proyecto encontraremos la implementación en lenguaje python siguiendo una arquitectura modular del protocolo SAKE-AM. Para ayudarnos en la implementación, hemos usado las siguientes referencias:

- [Symmetric-key Authenticated Key Exchange (SAKE) with Perfect Forward Secrecy](https://eprint.iacr.org/2019/444.pdf)
- [Tunnels sécurisés pour environnements contraints](https://hal.science/tel-02881758v1/file/M%C3%A9moire%20th%C3%A8se%20Lo%C3%AFc%20Ferreira%202019.pdf)

Nuestra implementación está diseñada en lenguaje **Python**, usando la versión ```3.12```, y además la implementación no necesita la instalación de librerías.

## CÓMO EJECUTAR SAKE-AM

Se han definido tres instancias en la función ```main```de [sake_am.py](sake_am.py). Por instancia entendemos a cada implementación posible dependiendo de los elementos que hayamos elegido. Para entenderlo mejor, nuestras instancias dependerán de qué función MAC y KDF elijamos. Además, estableceremos que el valor del desafío (challenge) está fijado para cada entidad.

En cuanto a las instancias que existen y las funciones MAC y KDF elegidas, son las siguientes:

- Instancia 1: HMAC_SHA256 y HKDF_SHA256
- Instancia 2: HMAC_SHA384 y HKDF_SHA384
- Instancia 3: HMAC_SHA512 y HKDF_SHA512

Se puede observar que el tamaño de longitud de función resumen generada son el mismo para MAC y KDF.

Para usar una instancia u otra, símplemente debemos comentar o descomentar el fragmento de código de cada instancia que encontraremos en la función ```main```de [sake_am.py](sake_am.py). Además de elegir la función MAC y KDF que usaremos, es necesario que en cada instancia se declare cual es el tamaño de los challenges (desafíos) usados, indicar cual es el valor de los challenges, y por último indicar cual es el valor del par de claves (```K``` y ```K_prime```):

```python
# INSTANCE 1
MAC_instance = HMAC_SHA256()
KDF_instance = HKDF_SHA256()
challenge_size = 128                   # Must be initialized with the size of the challenge: [128, 256, 384, 512]
# CHALLENGE VALUES                   # Both values must be initialized (not necessarily with the same value)
challenge_a_value = bytes.fromhex("10b67e2f56f15652fd75520ee6b62d2b20a1072bdeee2b7c622c78522508b36ce9d4bbc8d11cd00f0fb4d2ba8fad7fc951c895f890b4fa6413505711222d28ae1e285d4f6d40fbb769c0e296845e620e7511ee32165231823676e42aed26674c836f6f748486f06245f2fb2988a421a325327ee0e2834911877edb59c0dd8dfe")
challenge_b_value = bytes.fromhex("084aa626347c37419585b0b29f193762ef8e13eb6f7c907644ed172920a4b19ad1ae8404b0fe6dd10a088a2895e255c52e4c5bfe9a7f1c5124ceff7c0cccae0339c15499b4ab8069b8b837f627406e0601f57c1b42819ebff8a2d92647d6d45654132b25a0214b0a25b9b7752e783ba98c2ae480507e5c715a1a8ffef346995a")             
# MASTER KEYS -- The size of master keys must are determined by MAC function used (HMAC-SHA256, HMAC-SHA384, HMAC-SHA512)
K = bytes.fromhex("ceb50e3bffdea3dfb8bb896628aeeb619dade0c84c14fe61bf2ac866e5a219a3")
K_prime = bytes.fromhex("f24a7b3a262e331ef13dfd9bea61ada8ef85f2a2c699b2ab05764b202eac5bab")

# INSTANCE 2
# MAC_instance = HMAC_SHA384()
# KDF_instance = HKDF_SHA384()
# challenge_size = 128               # Must be initialized with the size of the challenge: [128, 256, 384, 512]
# CHALLENGE VALUES                   # Both values must be initialized (not necessarily with the same value)
# challenge_a_value = bytes.fromhex("cda4f4801b0e0a6644e434f285c39c48086ddd8a228bf07d2303b86915a2a0d667fbab2a10ff71fb63a61543996888d82bf6f35be1795c9dacad9e8d4a7ab7bd301b83697b9a4a9ca2e2ec8210c013a5facee3946429577f7df7d8bdf14212bf615a3231838d4c56e529d4c54f65af61556c80e903b2da1f57737864fce2d04b")
# challenge_b_value = bytes.fromhex("87d244290fb088c28641c2a9688728977af7101ad1a4c5aab02f8e191b9d9f67fe1dc315d3d0b47e563ac315bb20fe526541696d181e52db480cef40ccb9638a3481542954faee9385a947ea5f7921a1760c8deed480b8e53459afeec2edcc3a7b8ec201644e1e5f3623a4d54f9e80eb746be3fb89dbcc7b8facc82fb1be2006")             
# MASTER KEYS -- The size of master keys must are determined by MAC function used (HMAC-SHA256, HMAC-SHA384, HMAC-SHA512)
# K = bytes.fromhex("ae1a2cc5327209bbd273de538ae2f5cd33b4178d56e2b8491f84aa4d307de9adf97af9c76c66f2b4b211325eb79cffc2")
# K_prime = bytes.from("fa569166b26639e31d63dc4120eb72615a6d66d0e8824160511050d929bff050c711dcd60313d32397409a03d318f974")


# INSTANCE 3
# MAC_instance = HMAC_SHA512()
# KDF_instance = HKDF_SHA512()
# challenge_size = 128               # Must be initialized with the size of the challenge: [128, 256, 384, 512]
# CHALLENGE VALUES                   # Both values must be initialized (not necessarily with the same value)
# challenge_a_value = bytes.fromhex("de292c3048c5e6f6969e64c4d40962674e0fd2183f154b14705a1860ae6413cc7d71781a07e3823de7e5edbee73d4fbc5dbbc0fd674c97815222ac3abe349e70d4bd085ecfd996fdb51a3f34983b839f6cab7deb10377a7facaa2f3b8fc51a385648389f2ad81e899e703af185c4fdf363c7d088ffcef13c4495bea1d4953812")
# challenge_b_value = bytes.fromhex("d7c4526025ccbb390ee17f4d4bcee3cbc6daba7f089d117175c41ea93d2ec3d2b10aaefdf0f263934f185f70a96dfa4d94edf22e63538f2fd222368c3e61fe7dc033f8db8d29bd0c9883ab8d997ab491ade8ea2d70eb36e79ec6b24766aea1fb438ced29e71de510bc3dd433e88e334d1686a8c57bb356868e1b281d4c831d4e")             
# MASTER KEYS -- The size of master keys must are determined by MAC function used (HMAC-SHA256, HMAC-SHA384, HMAC-SHA512)
# K = bytes.fromhex("0076c1cb5315cd61411a307fcff46bc07d00a932a84c4a64787968c9229af79e613354ef19da57b758d12cf04ce025377a60bec5a28a35f755112be994d45bb5")
# K_prime = bytes.from("8e495cc72bfafaae322777bc6cc68bf2197f5dd523be83baca6fc039d5fe8f11dfe1214252aa2ff4ab036082adac8ca0daadd3627ebbbeadd8d2b7b80d33d981")

```

Por lo tanto, una vez se han definido los elementos de cada instancia, obtendremos dos entidades (objetos) participantes en el protocolo:

```python
initiator = Initiator("Initiator","Responder", challenge_value, challenge_size, K, K_prime, MAC_instance, KDF_instance)
responder = Responder("Initiator","Responder", challenge_value, challenge_size, K, K_prime, MAC_instance, KDF_instance)
```

El valor de los identificadores de las entidades los hemos definido como ```"Initiator"``` y ```"Responder"```

## CÓMO EJECUTAR LOS TEST VECTORS

El objetivo principal de los test vectors es proporcionar un conjunto de datos predefinidos que pueden ser usado para verificar que la implementación ha sido correcta y la esperada ejecución del algoritmo, protocolo o sistema.

Para poder usar los test vectors que hemos generado, tendrás que ejecutar el script [read_test_vector.py](read_test_vector.py), y en la linea ```96``` modificar la ruta del test vector que deseas leer. Los test ya generados disponibles los encontramos en el directorio [test_generated](/SAKE_AM/test_generated/), y tenemos los siguientes ficheros:

- [test_vectors_100_sha256_1.txt](/SAKE_AM/test_generated/test_vectors_100_sha256_1.txt)
- [test_vectors_100_sha384_1.txt](/SAKE_AM/test_generated/test_vectors_100_sha384_1.txt)
- [test_vectors_100_sha512_1.txt](/SAKE_AM/test_generated/test_vectors_100_sha512_1.txt)

## DESCRIPCIÓN DE LOS TEST-VECTORS

El conjunto de datos predefinido que se muestra en nuestros test vectors son los siguientes:

- **Tipo de test**: ```COMPLETED``` o ```ABORTED```. Este resultado depende de si el test se ha completado exitosamente o ha finalizado por un error (ha abortado). El tipo de test determinará el contenido final de cada test.
  
  - Si el test es ```COMPLETED```, se guardan las **claves de sesión (SK) generadas**. Podemos encontrarnos que las claves de sesión guardadas pueden ser iguales o diferentes.
  - Si el test es ```ABORTED```, se almacena el **error** que se ha producido, por ejemplo, si la verificación del segundo mensaje enviado ha fallado: ```ERROR: Verification of the 2nd message failed```.

- **Identificador** de A. Por ejemplo: ```Initiator```.
- **Valor** del desafío (challenge) de A.
- **Identificador** de B. Por ejemplo: ```Responder```.
- **Valor** del desafío (challenge) de B.
- **Tamaño** de los desafíos (challenges A y B).
- **Función MAC** usada. Por ejemplo ```hmac_sha384```
- **Función KDF** usada.
- Par de claves ```K```y ```K_prime```.

Hay que destacar que los valores de las claves de sesión generadas, los valores de los desafíos (challenge) y del par de claves maestras, aunque son una secuencia de bytes, se guardan en valor hexadecimal.

## DESCRIPCIÓN DE SAKE-AM

En esta sección se comentan todas las decisiones de diseño que hemos tomado y que no estaban definidas en [Symmetric-key Authenticated Key Exchange (SAKE) with Perfect Forward Secrecy](https://eprint.iacr.org/2019/444.pdf) en caso de que se quiera replicar la implementación y obtener los mismos test-vectors,

Las funciones MAC y KDF se han instanciado como hemos mencionado anteriormente, es decir, son HMAC y HKDF respectivamente (ambas funciones usarán la misma longitud de función SHA).

Dentro de la implementación de KDF, al usar HKDF el parámetro ```info``` se ha fijado como la cadena ```b"Session Key"``` en todas las llamadas de HKDF.

La función ```update``` (en nuestro código ```update_key```), que se usa para evolucionar claves maestras, si nos fijamos en [Symmetric-key Authenticated Key Exchange (SAKE) with Perfect Forward Secrecy](https://eprint.iacr.org/2019/444.pdf) en la página 20, se define como una PRF (función pseudoaleatoria), que toma como valores de entrada la clave de derivación (K) y para un valor *x*: update: K = PRF (K,x). Esta PRF se ha instanciado haciendo uso de la **función KDF** que se usa para obtener la clave de sesión, el cual tomará como valores de entradas ```salt```, que adquirirá el valor de la **clave de derivación (K)**, y el ```input_key_material```, será el valor de ***x***, que se ha instanciado como ```b"Update Key"```.

```python
# Llamada a update_key
K = PRF (K,kdf_instance)

# Función update_key

def update_key (Key, KDF_instance):
    return KDF_instance.derive(Key, b"Key Update")
```

Por otro lado, durante la implementación de SAKE-AM, encontramos un **error** el cual impedía la ejecución completa del protocolo. En el esquema original que encontramos en la página 157 de [Tunnels sécurisés pour environnements contraints](https://hal.science/tel-02881758v1/file/M%C3%A9moire%20th%C3%A8se%20Lo%C3%AFc%20Ferreira%202019.pdf), la definición del desafío (challenge) de la entidad B se realiza erróneamente de manera tardía una vez se ha ejecutado todo el bloque de condicionales if-else tras el envío del primer mensaje. Para una ejecución correcta, el valor del desafío (challenge) de la entidad B debe ser generado una vez se ha realizado el envío del primer mensaje, es decir, una vez la entidad B recibe el primer mensaje, debe definir el valor del desafío (challenge).
