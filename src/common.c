/*  
 * Skype Login
 * 
 * Based on:
 *   FakeSkype : Skype reverse engineering proof-of-concept client
 *               Ouanilo MEDEGAN (c) 2006   http://www.oklabs.net
 *   pyskype   : Skype login Python script by uunicorn
 *
 * Written by:   leecher@dose.0wnz.at (c) 2015 
 *
 * Module:       Common stuff, especially Skype Modulus
 *
 */
#include "common.h"

char	*SkypeModulus1536[] = {"c095de9e868dc9fe1de94ab5e38e8dbdcae7e6249ef147de503f3e1c76e65af06f7714872f3527ee16410170196e4b2277db206827505bc48b4b63159f8eb0d56d14de686e5f6840e32522f8b7dafc6b901b83495757f4269b59440bc7824d4543eae2b00b9d4d21b0b056ae53d6cc6c3a35a5b10e72710cad00db5a42903e277e361cd1761a074afe997cc4a2c77427854ea1176da481cadb981ee145711c7160c5b31f5194f64ec919bf57dc544656f39bad7bbdacb6e46f22c30173df2ea7",
							   "a8f223612f4f5fc81ef1ca5e310b0b21532a72df6c1af0fbec87304aec983aab5d74a14cc72e53ef7752a248c0e5abe09484b597692015e796350989c88b3cae140ca82ccd9914e540468cf0edb35dcba4c352890e7a9eafac550b3978627651ad0a804f385ef5f4093ac6ee66b23e1f8202c61c6c0375eeb713852397ced2e199492aa61a3eab163d4c2625c873e95cafd95b80dd2d8732c8e25638a2007acfa6c8f1ff31cc2bc4ca8f4446f51da404335a48c955aaa3a4b57250d7ba29700b",
							   "aa4bc22ba5b925573c48bf886efad103a37d697283a3d37b8bf5a3eb2d09a9ae73e6905fcb3c6af06e4170b7a1856c70eab972cd3a468a28d7a87ceaad2404126dd5843f8895a0cfd9b07085afe60b8ae391a703479846d800737ab02fca5ead5673f416d5fb4a95e1d27bb4b7ca5411e74e98623f563b1d3709d749b3ee6d87242a8da04f39fd61ea679acc8e28601dadcc4434918dc544cd365f7b897600b3fb62875f4517ae32601764ae8d28b924074e47ebc2bcaaa42d9d8feb82137787",
							   NULL
							  };

#ifdef CRYPT_WOLFSSL
#include "wolfssl.c"
#endif
