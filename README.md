# Basalt
A simple pure python library with hash functions Md5, Sha1 and Sha2  
  
## Usage
Md5:          md5(message)  
Sha1:         sha1(message)  
Sha2-256:     sha2(message)                    Or: sha2(message, digest=256) sha2(message, digest=(256, 256))  
Sha2-512:     sha2(message, digest=512)        Or: sha2(message, digest=(512, 512))  
Sha2-224:     sha2(message, digest=224)        Or: sha2(message, digest=(256, 224))  
Sha2-384:     sha2(message, digest=384)        Or: sha2(message, digest=(512, 384))  
Sha2-512/224: sha2(message, digest=(512, 224))  
Sha2-512/256: sha2(message, digest=(512, 256))  
  
Accepts string, bytes, or bytearray   
Returns bytes  
You can copy the functions into your code or put it in the same folder and import it as a library  
  
Licenced under the MIT licence, see LICENCE for more info
