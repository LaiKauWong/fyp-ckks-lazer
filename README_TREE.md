lazer/
├── ckks/
│   ├── tests/
│   │   └── test_polyio.py
│   ├── __init__.py
│   ├── context.py
│   ├── encoding.py
│   └── polyio.py
├── demos/
│   ├── blindsig/
│   │   ├── blindsig-demo.c
│   │   ├── blindsig-demo.h
│   │   ├── Makefile
│   │   ├── privkey.bin
│   │   └── pubkey.bin
│   ├── ckks/
│   │   ├── bridge_demo.c
│   │   ├── encode_demo.c
│   │   ├── he_add_demo.c
│   │   ├── he_demo.c
│   │   └── ntt_smoketest.c
│   ├── kyber1024/
│   │   ├── data.h
│   │   ├── kyber1024-demo.c
│   │   ├── Makefile
│   │   ├── params.h
│   │   └── params.py
│   └── kyber512-secrets/
│       ├── lnp-params-kyber.sage
│       └── lnp-params-kyber512.h
├── docs/
│   ├── source/
│   │   ├── AggregateSignature.rst
│   │   ├── anoncred.rst
│   │   ├── bibliography.bib
│   │   ├── blindsig.rst
│   │   ├── conf.py
│   │   ├── examples_c.rst
│   │   ├── examples_py.rst
│   │   ├── getting_started.rst
│   │   ├── index.rst
│   │   ├── interface_c.rst
│   │   ├── interface_py.rst
│   │   ├── kyber1024.rst
│   │   ├── library.rst
│   │   ├── linrel.rst
│   │   ├── linrel_c.rst
│   │   ├── params_c.rst
│   │   ├── params_py.rst
│   │   ├── python_module.rst
│   │   ├── ref_c.rst
│   │   ├── ref_py.rst
│   │   └── references.rst
│   └── Makefile
├── golang/
│   ├── lazer/
│   │   ├── go.mod
│   │   └── lazer.go
│   ├── demo.go
│   └── go.mod
├── lazer/
├── misc/
│   └── debug.sage
├── python/
│   ├── anon_cred/
│   │   ├── anon_cred.py
│   │   ├── anon_cred_p1_params.py
│   │   ├── anon_cred_p2_params.py
│   │   ├── anon_cred_params.h
│   │   └── Makefile
│   ├── blindsig/
│   │   ├── blindsig.py
│   │   ├── blindsig_p1_params.py
│   │   ├── blindsig_p2_params.py
│   │   ├── blindsig_params.h
│   │   └── Makefile
│   ├── cbdc/
│   │   ├── cbdc.py
│   │   ├── cbdc_p1_params.py
│   │   ├── cbdc_p2_params.py
│   │   ├── cbdc_params.h
│   │   ├── cbdc_popen_params.py
│   │   └── Makefile
│   ├── demo/
│   │   ├── demo.py
│   │   ├── demo_params.h
│   │   ├── demo_params.py
│   │   └── Makefile
│   ├── kyber1024/
│   │   ├── kyber1024.py
│   │   ├── kyber1024_params.h
│   │   ├── kyber1024_params.py
│   │   └── Makefile
│   ├── public_key_encryption/
│   │   ├── demo_input_pke.py
│   │   ├── demo_pke.py
│   │   ├── demo_sentence.py
│   │   └── module_lwe_pke.py
│   ├── swoosh/
│   │   ├── Makefile
│   │   ├── swoosh.py
│   │   ├── swoosh_params.h
│   │   └── swoosh_params.py
│   ├── treethings/
│   │   └── tree.py
│   ├── agg_sig.py
│   ├── example.py
│   ├── example2.py
│   ├── labrador.py
│   ├── lazer.py
│   ├── lazer_cffi_build.py
│   ├── Makefile
│   ├── no_crypto_quadratic_to_linear.py
│   ├── params.h
│   ├── params_cffi_build.py
│   ├── quadratic_to_linear.py
│   ├── silly_exper.py
│   └── template.py
├── scripts/
│   ├── abdlop-codegen.sage
│   ├── codegen.sage
│   ├── lin-codegen.sage
│   ├── lnp-params-falcon.sage
│   ├── lnp-params-swoosh.sage
│   ├── lnp-params.sage
│   ├── lnp-quad-codegen.sage
│   ├── lnp-quad-eval-codegen.sage
│   ├── lnp-tbox-codegen.sage
│   └── moduli.sage
├── src/
│   ├── ckks/
│   │   ├── ckks_bridge.c
│   │   ├── ckks_bridge.h
│   │   ├── ckks_encode.c
│   │   ├── ckks_encode.h
│   │   ├── ckks_he.c
│   │   └── ckks_he.h
│   ├── labrador/
│   ├── public_key_encryption/
│   │   ├── bridge_module_lwe_pke.c
│   │   ├── bridge_module_lwe_pke.h
│   │   ├── module_lwe_pke.c
│   │   ├── module_lwe_pke.h
│   │   ├── module_lwe_pke_bench.c
│   │   ├── module_lwe_pke_test.c
│   │   └── README.md
│   ├── abdlop.c
│   ├── aes256ctr-amd64.c
│   ├── aes256ctr.c
│   ├── aes256ctr.h
│   ├── blindsig-p1-params.h
│   ├── blindsig-p1-params.py
│   ├── blindsig-p2-params.h
│   ├── blindsig-p2-params.py
│   ├── blindsig.c
│   ├── blindsig.h
│   ├── brandom.c
│   ├── brandom.h
│   ├── bytes.c
│   ├── coder.c
│   ├── dcompress.c
│   ├── dom.h
│   ├── dump.c
│   ├── falcon.patch
│   ├── grandom.c
│   ├── grandom.h
│   ├── hexl.cpp
│   ├── hexl.h
│   ├── int.c
│   ├── intmat.c
│   ├── intvec.c
│   ├── intvec.h
│   ├── labrador24_py.h
│   ├── labrador32_py.h
│   ├── labrador40_py.h
│   ├── labrador48_py.h
│   ├── lazer-in1.h
│   ├── lazer-in2.h
│   ├── lazer.c
│   ├── lin-proofs.c
│   ├── lnp-quad-eval.c
│   ├── lnp-quad-many.c
│   ├── lnp-quad.c
│   ├── lnp-tbox.c
│   ├── lnp-tbox.h
│   ├── lnp-tboxXXX.c
│   ├── lnp.c
│   ├── memory.c
│   ├── memory.h
│   ├── moduli.h
│   ├── moduliXXX.h
│   ├── mont.h
│   ├── ntt.c
│   ├── ntt.h
│   ├── poly.c
│   ├── poly.h
│   ├── polymat.c
│   ├── polyring.c
│   ├── polyvec.c
│   ├── quad.c
│   ├── rejection.c
│   ├── rng.c
│   ├── rng.h
│   ├── shake128.c
│   ├── shake128.h
│   ├── spolymat.c
│   ├── spolyvec.c
│   ├── stopwatch.c
│   ├── stopwatch.h
│   ├── urandom.c
│   ├── urandom.h
│   └── version.c
├── tests/
│   ├── abdlop-params1.h
│   ├── abdlop-params1.sage
│   ├── abdlop-params2.h
│   ├── abdlop-params2.sage
│   ├── abdlop-params3.h
│   ├── abdlop-params3.sage
│   ├── abdlop-params4.h
│   ├── abdlop-params4.sage
│   ├── abdlop-test.c
│   ├── brandom-test.c
│   ├── bytes-test.c
│   ├── coder-test.c
│   ├── dcompress-test.c
│   ├── grandom-test.c
│   ├── int-test.c
│   ├── intmat-test.c
│   ├── intvec-test.c
│   ├── lazer-test.c
│   ├── lnp-quad-eval-params1.h
│   ├── lnp-quad-eval-params1.sage
│   ├── lnp-quad-eval-params1_.h
│   ├── lnp-quad-eval-params2.h
│   ├── lnp-quad-eval-params2.sage
│   ├── lnp-quad-eval-test.c
│   ├── lnp-quad-many-test.c
│   ├── lnp-quad-params1.h
│   ├── lnp-quad-params1.sage
│   ├── lnp-quad-params2.h
│   ├── lnp-quad-params2.sage
│   ├── lnp-quad-params3.h
│   ├── lnp-quad-params3.sage
│   ├── lnp-quad-test.c
│   ├── lnp-tbox-params1.h
│   ├── lnp-tbox-params1.sage
│   ├── lnp-tbox-test.c
│   ├── poly-test.c
│   ├── polymat-test.c
│   ├── polyring-test.c
│   ├── polyvec-test.c
│   ├── quad-test.c
│   ├── rejection-test.c
│   ├── rng-test.c
│   ├── run-tests
│   ├── sage-test.c
│   ├── sage-test.sh
│   ├── shake128-test.c
│   ├── spolymat-test.c
│   ├── test.c
│   ├── test.h
│   ├── urandom-test.c
│   └── valgrind-test.c
├── third_party/
│   ├── estimator.py
│   ├── Falcon-impl-20211101.zip
│   └── hexl-development.zip
├── .clang-format
├── .gdbinit
├── .gitignore
├── .gitmodules
├── bench_pke
├── config.h
├── LICENSE
├── lwe_bench
├── lwe_test
├── Makefile
├── Makefile.pke
├── README
└── README_TREE.md
