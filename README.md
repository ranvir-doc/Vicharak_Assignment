# Vicharak_Assignment

#sha- 256 hashing in c++
A lightweight and modular implementation of the SHA - 256 algorithm , designed fro single- block hashing in c++ . This implementation adheres to cryptographic standard are avoid direct reuse of external content . 

# key Features 
- Implement all SHA-256 components: round function , bitwise operations , and block processing . 
- Processes a single 512-bit bloack , producing a 256-bit digest .
- Clear , modular code structure for easy undersatanding extension .
- 
#build the project
bash 
g++ -o  sha256 src/main.cpp src/sha256.cpp

#run the program : 
./sha256

# test with known vectors : 
g++ -o test test/test_vectors.cpp src/sha256.cpp
./test 
