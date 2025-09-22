from tweakable_block_cipher import TweakableBlockCipher
from inverse_tweakable_block_cipher import InverseTweakableBlockCipher
from additional_functions import AdditionalFunctions
from state_update_function import StateUpdateFunction
from inverse_state_update_function import InverseStateUpdateFunction
from romulus_adversary_attack import RomulusAdversaryAttack
from romulus_encryption import RomulusEncryption

#THIS CLASS GENERATED FOR TESTING THE ALGORITHMS
class RomulusTestClass():
    def __init__(self):
        self.tbc = TweakableBlockCipher()
        self.inv_tbc = InverseTweakableBlockCipher()
        self.af = AdditionalFunctions()
        self.suf = StateUpdateFunction()
        self.inv_suf = InverseStateUpdateFunction()
        self.adv = RomulusAdversaryAttack()
        self.re = RomulusEncryption()


    def test_adversary_attack(self):
        #Generating random inputs for the initial encryption process E(K,N,AD, M) -> CT, T
        rnd = self.af.random_bitstring
        
        key = bytes(rnd(48)) #Key should be 48-byte length
        nonce = bytes(rnd(16)) #Nonce should be 16-byte length
        ad = bytes(rnd(32)) #Associated data can be arbitrary length
        message = bytes(rnd(64)) #Message can be arbitrary length

        success = self.adv.adversary(key, nonce, ad, message)
        print("Adversary attack successful ✅" if success else "Adversary attack failed ❌")
        

if __name__ == '__main__':
    test = RomulusTestClass()
    test.test_adversary_attack()

    
    
