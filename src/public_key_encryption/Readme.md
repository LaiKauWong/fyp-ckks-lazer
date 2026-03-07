Command of Module_lwe_pke_test.c
gcc -c src/public_key_encryption/module_lwe_pke.c -I. -Ipython/demo
gcc -c src/public_key_encryption/module_lwe_pke_test.c -I. -Ipython/demo
g++ module_lwe_pke.o module_lwe_pke_test.o -L. -llazer ./third_party/hexl-development/build/hexl/lib/libhexl.a -lmpfr -lgmp -lm -o lwe_test
LD_LIBRARY_PATH=. ./lwe_test


command of bench.c
gcc -c src/public_key_encryption/module_lwe_pke.c -I. -Ipython/demo
gcc -c src/public_key_encryption/module_lwe_pke_bench.c -I. -Ipython/demo
g++ module_lwe_pke.o module_lwe_pke_bench.o -L. -llazer ./third_party/hexl-development/build/hexl/lib/libhexl.a -lmpfr -lgmp -lm -o lwe_bench
LD_LIBRARY_PATH=. ./lwe_bench