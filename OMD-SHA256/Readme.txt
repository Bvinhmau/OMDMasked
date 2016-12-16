The main.c contains an exemple of execution that rely on clock_gettime for performance evalutation.

The way to use sec_omdsha256_process is roughly the same than for the unmasked version, except that youy have to provide the input masked, with their mask.

Methods used for the RNG are located in the RNG.h file. Only getRand(output,index), getRandMessageBlock(output,index) and getRandHashBlock(output,index) needs to be properly implemented, as they are the only methods called in other parts of the code. In is advised to store each random numberd (defined by their unique index) in a array, as done by the dummy implementations.

