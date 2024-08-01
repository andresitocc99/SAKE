# *****************************************************************************
# *                                                                           *
# *                                SAKE-AM                                    *
# *                                                                           *
# *  Description:                                                             *
# *  Implementation of the SAKE protocol with Perfect Forward Secrecy (PFS).  *
# *  This script demonstrates the establishment of a secure communication     *
# *  session using the SAKE protocol, with the addition of PFS for enhanced   *
# *  security.                                                                *
# *                                                                           *
# *  Author:                                                                  *
# *  ANDRÉS CASTELLANOS CANTOS                                                *
# *                                                                           *
# *  Creation Date:                                                           *
# *                     05/03/2024                                            *
# *                                                                           *
# *  Last Modified:                                                           *
# *                     29/09/2024                                            *
# *                                                                           *
# *****************************************************************************

import os
from abc import ABC, abstractmethod
import hashlib
import hmac

# *****************************************************************************
# *                                                                           *
# *                              MAC with Objects                             *
# *                                                                           *
# *  Description:                                                             *
# *  Implementation of the Message Authentication Code (MAC) using objects.   *
# *                                                                           *
# *****************************************************************************

class MAC (ABC):

    def __init__(self,identifier, LENGTH):
        self.identifier = identifier
        self.LENGTH = LENGTH

    @abstractmethod
    def mac(self, key, message):
        pass

class HMAC (MAC):
    def __init__ (self, identifier, length, hash):
        super().__init__(identifier, length)
        self.hash = hash

    def mac(self, key, message):
        return hmac.new(key, message, self.hash).digest()

class HMAC_SHA256(HMAC):

    def __init__(self):
        super().__init__("hmac_sha256", 32,hashlib.sha256)

class HMAC_SHA384(HMAC):

    def __init__(self):
        super().__init__("hmac_sha384", 48,hashlib.sha384)
    
class HMAC_SHA512(HMAC):
    def __init__(self):
        super().__init__("hmac_sha512", 64, hashlib.sha512)

# *****************************************************************************
# *                                                                           *
# *                               KDF with Objects                            *
# *                                                                           *
# *  Description:                                                             *
# *  Implementation of the Key Derivation Function (KDF) using objects.       *
# *                                                                           *
# *****************************************************************************

class KDF(ABC):
    @abstractmethod
    def __init__ (self, identifier):
        self.identifier = identifier

    def derive(self, salt, input_key_material):
        pass

class HKDF(KDF):

    def __init__(self, identifier, hash_function, digest_size):
        super().__init__(identifier)
        self.hash_function = hash_function
        self.digest_size = digest_size

    def derive(self, salt, input_key_material):
        info = b"Session Key"
        LENGTH = self.digest_size

        if salt is None:
            salt = bytes([0] * self.digest_size)

        input_key_material = self.hash_function(input_key_material).digest()

        if len(input_key_material) < self.digest_size:
            raise ValueError("Pseudo-key too short")

        if LENGTH > 255 * self.digest_size:
            raise ValueError("Requested key length too long")

        okm = b''
        output_block = b''
        counter = 1

        while len(okm) < LENGTH:
            hmac_input = output_block + info + bytes([counter])
            output_block = hmac.new(salt, hmac_input, self.hash_function).digest()
            okm += output_block
        return okm[:LENGTH]

class HKDF_SHA256(HKDF):
    
    def __init__(self):
        super().__init__("hkdf_sha256",hashlib.sha256, hashlib.sha256().digest_size)

class HKDF_SHA384(HKDF):

    def __init__(self):
        super().__init__("hkdf_sha384",hashlib.sha384, hashlib.sha384().digest_size)
    
class HKDF_SHA512(HKDF):
    
    def __init__(self):
        super().__init__("hkdf_sha512",hashlib.sha512, hashlib.sha512().digest_size)


# *****************************************************************************
# *                                                                           *
# *                             SAKE AM PROTOCOL                              *
# *                                                                           *
# *  Description:                                                             *
# *  Implementation of the SAKE protocol with Perfect Forward Secrecy (PFS).  *
# *                                                                           *
# *****************************************************************************

class Initiator:
    def __init__(self, id_a, id_b, challenge_value, challenge_length, K, K_prime, MAC_instance, KDF_instance):
        self.id_a = id_a
        self.id_b = id_b
        self.r_a = challenge_value
        self.r_b = None
        self.challenge_length = challenge_length
        self.MAC_instance = MAC_instance
        self.KDF_instance = KDF_instance
        self.K = K
        self.K_prime = K_prime
        self.session_key = None
        self.tag_a = None
        self.tag_b = None
        self.tag_a_prime = None
        self.tag_b_prime = None
        self.ERROR = None

    def evolve (self):
        self.K = update_key(self.K, self.KDF_instance)
        self.K_prime = update_key(self.K_prime, self.KDF_instance)

    def start_session (self):
        self.tag_a = self.MAC_instance.mac(self.K_prime, str(self.id_a).encode() + str(self.id_b).encode() + self.r_a)

    def receive_2nd_message(self, sync, r_b, tag_b):

        self.r_b = r_b 
        if not Vrfy(self.K_prime, str(sync).encode() + str(self.id_b).encode() + str(self.id_a).encode() + r_b + self.r_a, tag_b, self.MAC_instance):
            self.ERROR = "ERROR: Verification of the 2nd message failed"
            return

        if sync == 1:
            self.evolve()
   
        self.session_key = self.KDF_instance.derive(self.K, self.r_a + self.r_b)
        self.evolve()
        self.tag_a_prime = self.MAC_instance.mac(self.K_prime, str(self.id_a).encode() + str(self.id_b).encode() + self.r_a + self.r_b)
        return self.tag_a_prime

    def receive_4th_message(self, tag_b_prime):
        if not Vrfy(self.K_prime, self.r_b + self.r_a, tag_b_prime, self.MAC_instance):
            self.ERROR = "ERROR: Verification of the 4th message failed"
            return
        return "Success"

class Responder:
    def __init__(self, id_a, id_b, challenge_value, challenge_length, K, K_prime, MAC_instance, KDF_instance):
        self.id_a = id_a
        self.id_b = id_b
        self.r_a = None
        self.r_b = challenge_value
        self.challenge_length = challenge_length
        self.MAC_instance = MAC_instance
        self.KDF_instance = KDF_instance
        self.K = K
        self.K_prime = K_prime
        self.K_j_prime = self.K_prime
        self.K_j_prime_before = None
        self.K_j_prime_after = update_key(self.K_j_prime, KDF_instance)
        self.sync = 0
        self.gap = None
        self.session_key = None
        self.tag_b = None
        self.tag_b_prime = None
        self.ERROR = None   

    def evolve (self):
        self.K = update_key(self.K, self.KDF_instance)
        self.K_j_prime_before = self.K_j_prime
        self.K_j_prime = self.K_j_prime_after
        self.K_j_prime_after = update_key(self.K_j_prime_after, self.KDF_instance)

    def receive_1st_message(self, id_a, r_a, tag_a):

        self.r_a = r_a
        
        if Vrfy(self.K_prime, str(id_a).encode() + str(self.id_b).encode() + r_a, tag_a, self.MAC_instance):
            self.gap = 0
            self.K_prime = self.K_j_prime
            self.session_key = self.KDF_instance.derive(self.K, r_a + self.r_b)
            self.evolve()
            self.sync = 0
        
        elif Vrfy(self.K_j_prime_before, str(id_a).encode() + str(self.id_b).encode() + r_a, tag_a, self.MAC_instance):
            self.gap = 1
            self.K_prime = self.K_j_prime_before
            self.sync = 1

        elif Vrfy(self.K_j_prime_after, str(id_a).encode() + str(self.id_b).encode() + r_a, tag_a, self.MAC_instance):
            self.gap = -1
            self.K_prime = self.K_j_prime_after
            self.evolve()
            self.session_key = self.KDF_instance.derive(self.K, r_a + self.r_b)
            self.evolve()
            self.sync = 0

        else:
            self.ERROR = "ERROR: Verification of the 1st message failed"
            return
        
        self.tag_b = self.MAC_instance.mac(self.K_prime, str(self.sync).encode() + str(self.id_b).encode() + str(self.id_a).encode() + self.r_b + self.r_a)
        return self.sync, self.r_b, self.tag_b
    
    def receive_3rd_message(self, tag_a_prime):
        if self.sync == 0:
            self.K_prime = self.K_j_prime

            if not Vrfy(self.K_prime, str(self.id_a).encode() + str(self.id_b).encode() + self.r_a + self.r_b, tag_a_prime, self.MAC_instance):
                self.ERROR = "ERROR: Verification of the 3rd message failed"
                return
        
        elif self.sync == 1:
            self.K_prime = self.K_j_prime_after

            if not Vrfy(self.K_prime, str(self.id_a).encode() + str(self.id_b).encode() + self.r_a + self.r_b, tag_a_prime):
                self.ERROR = "ERROR: Verification of the 3rd message failed"
                return
            
            self.session_key = self.KDF_instance.derive(self.K, self.r_a + self.r_b)
            self.evolve()
        
        self.tag_b_prime = self.MAC_instance.mac(self.K_prime, self.r_b + self.r_a)
        return self.tag_b_prime

def Vrfy(Key, data, original_tag, MAC_instance):
    if Key == None:
        return False
    calculated_tag = MAC_instance.mac(Key, data)
    return calculated_tag == original_tag

def update_key(Key, KDF_instance):
    return KDF_instance.derive(Key, b"Key Update")

def SAKE_AM_Procedure(initiator,responder):

    Completed = True
    initiator.start_session()

    if responder.receive_1st_message(initiator.id_a, initiator.r_a, initiator.tag_a) == None:
        Completed = False
        return Completed

    if initiator.receive_2nd_message(responder.sync, responder.r_b, responder.tag_b) == None:
        Completed = False
        return Completed
    
    if responder.receive_3rd_message(initiator.tag_a_prime) == None:
        Completed = False
        return Completed
    
    if initiator.receive_4th_message(responder.tag_b_prime) == None:
        Completed = False
        return Completed

    return Completed



if __name__ == "__main__":

    # EVERY INSTANCE WILL HAVE THE FOLLOWING ELEMENTS:
    # - id_a: Identifier of the entity A
    # - id_b: Identifier of the entity B
    # - challenge_a_value: Challenge value of the entity A
    # - challenge_b_value: Challenge value of the entity B
    # - challenge_size: Size of the challenges
    # - K and K_prime: Master keys of the entities
    # - MAC_instance: Instance of the MAC function
    # - KDF_instance: Instance of the KDF function

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

    # Entities constructor
    # Here you can change id_a and id_b, in this case are 'Initiator' and 'Responder'
    initiator = Initiator("Initiator","Responder", challenge_value, challenge_size, K, K_prime, MAC_instance, KDF_instance)
    responder = Responder("Initiator","Responder", challenge_value, challenge_size, K, K_prime, MAC_instance, KDF_instance)
    

    if SAKE_AM_Procedure(initiator, responder) is True:
        if (initiator.session_key == responder.session_key):
            print ("Session Key: ", initiator.session_key.hex())
        else:
            print ("Sessions Key are different")
    else:
        print ("Protocol Aborted")
   