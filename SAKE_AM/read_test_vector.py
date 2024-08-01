# *****************************************************************************
# *                                                                           *
# *                  Test Vector Parsing for SAKE AM Protocol                 *
# *                                                                           *
# *  Description:                                                             *
# *  Implementation of parsing for previously generated test vectors. The     *
# *  script takes as input the values obtained from a '.txt' file, where each *
# *  line represents a test conducted. The goal is verify that the generated  *
# *  test vectors are deterministic and, above all, successful.               *
# *                                                                           *
# *  Author:                                                                  *
# *  ANDRÉS CASTELLANOS CANTOS                                                *
# *                                                                           *
# *  Creation Date:                                                           *
# *                     10/04/2024                                            *
# *                                                                           *
# *  Last Modified:                                                           *
# *                     26/04/2024                                            *
# *                                                                           *
# *****************************************************************************

import os
from sake_am import *

def read_test_vectors(filename):
    test_vectors = []
    with open(filename, 'r') as file:
        for line in file:
            components = line.split()
            if components[0] == 'COMPLETED':
                id_a, challenge_value_a, id_b, challenge_value_b, challenge_length, mac_id, kdf_id, initiator_K, initiator_K_prime,responder_K, responder_K_prime, initiator_session_key, responder_session_key = components[1:]
                
                if bytes.fromhex(initiator_K) == bytes.fromhex(responder_K):
                    test_vectors.append((0,id_a, bytes.fromhex(challenge_value_a), id_b, bytes.fromhex(challenge_value_b), int(challenge_length), mac_id.upper(), kdf_id.upper(), bytes.fromhex(initiator_K), bytes.fromhex(initiator_K_prime), bytes.fromhex(responder_K), bytes.fromhex(responder_K_prime), bytes.fromhex(initiator_session_key), bytes.fromhex(responder_session_key)))
                elif bytes.fromhex(initiator_K) != bytes.fromhex(responder_K):
                    test_vectors.append((3,id_a, bytes.fromhex(challenge_value_a), id_b, bytes.fromhex(challenge_value_b), int(challenge_length), mac_id.upper(), kdf_id.upper(), bytes.fromhex(initiator_K), bytes.fromhex(initiator_K_prime), bytes.fromhex(responder_K), bytes.fromhex(responder_K_prime), bytes.fromhex(initiator_session_key), bytes.fromhex(responder_session_key)))
            
            elif components[0] == 'ABORTED':
                
                id_a, challenge_value_a, id_b, challenge_value_b, challenge_length, mac_id, kdf_id, initiator_K, initiator_K_prime,responder_K, responder_K_prime = components[1:12]
                error =' '.join(components[12:])

                if bytes.fromhex(initiator_K) != bytes.fromhex(responder_K):
                    test_vectors.append((1,id_a, bytes.fromhex(challenge_value_a), id_b, bytes.fromhex(challenge_value_b), int(challenge_length), mac_id.upper(), kdf_id.upper(), bytes.fromhex(initiator_K), bytes.fromhex(initiator_K_prime), bytes.fromhex(responder_K), bytes.fromhex(responder_K_prime), error))
                if bytes.fromhex(initiator_K) == bytes.fromhex(responder_K):
                    test_vectors.append((2,id_a, bytes.fromhex(challenge_value_a), id_b, bytes.fromhex(challenge_value_b), int(challenge_length), mac_id.upper(), kdf_id.upper(), bytes.fromhex(initiator_K), bytes.fromhex(initiator_K_prime), bytes.fromhex(responder_K), bytes.fromhex(responder_K_prime), error))
                
    return test_vectors

def analyze_test_vectors (test_vectors, mac_dict, kdf_dict):
    test_success = 0
    test_fail = 0
    i=0
    for test in test_vectors:
        test_type = test[0]
        MAC_instance = mac_dict[test[6]]
        KDF_instance = kdf_dict[test[7]]

        initiator = Initiator(test[1], test[3], test[2], test[5], test[8], test[9], MAC_instance, KDF_instance)
        responder = Responder(test[1], test[3], test[4], test[5], test[10], test[11], MAC_instance, KDF_instance)

        if test_type == 0 or test_type == 3:
            
            if SAKE_AM_Procedure(initiator, responder) == True:
                if initiator.session_key == test[12] and responder.session_key == test[13]:
                    test_success += 1
                else:
                    test_fail += 1
            else:
                test_fail += 1
        
        elif test_type == 1 or test_type == 2:

            if SAKE_AM_Procedure(initiator, responder) == False:
                if initiator.ERROR == test[12] or responder.ERROR == test[12]:
                    test_success += 1
                else:
                    test_fail += 1
            else:
                test_fail += 1
        i+=1
    
    print(f"Test Success: {test_success} || Test Fail: {test_fail}")

def get_leaf_subclasses(cls):
    leaf_subclasses = {}
    for subclass in cls.__subclasses__():
        if not subclass.__subclasses__():
            leaf_subclasses[subclass.__name__] = subclass()
        else:
            leaf_subclasses.update(get_leaf_subclasses(subclass))
    return leaf_subclasses

if __name__ == "__main__":

    FILENAME = "test_generated/test_vectors_100_sha256_1.txt"
    if not os.path.exists(FILENAME):
        print(f"ERROR: File {FILENAME} does not exist")
        exit(1)

    mac_dict = get_leaf_subclasses(MAC)
    kdf_dict = get_leaf_subclasses(KDF)
    test_vectors = read_test_vectors(FILENAME)

    analyze_test_vectors(test_vectors, mac_dict, kdf_dict)
