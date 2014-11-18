GSHADE
======


--- Description ---

Privacy preserving distance computation framework for: Hamming distance, Euclidean distance, Scalar Product and Normalized Hamming distance (currently not implemented) on the publication [1]. 
--- Requirements ---
- Miracl (set up in /util/Miracl/ )
- The GMP library
- OpenSSL

--- Compiling ---

- Compile the Miracl library for elliptic curve cryptography (util/Miracl) using "bash linux" / "bash linux64" (depending on the system)
- Compile the distance computation framework by invoking "make" in the folder of the README file

--- Execution ---

Currently, the server routine can be invoked by starting "./dst.exe 0" in one terminal and the connecting client can be invoked using "./dst.exe 1" in a second terminal on the same machine. The parameters can be changed in the code. 

--- Current Status ---
Currently, the Euclidean distance and the Scalar product have been tested and should work properly. The Hamming distance is executed but might result in the wrong result. The Normalized Hamming distance is currently not implemented, due to problems with the internal program structure. 


[1] Julien Bringer, Herve Chabanne, Melanie Favre, Alain Patey, Thomas Schneider, and Michael Zohner. GSHADE: Faster Privacy-Preserving Distance Computation and Biometric Identification, 2nd ACM Workshop on Information Hiding and Multimedia Security (IH&MMSEC 2014). 
