Lazer Library — README Tree

lazer/
├── README                        # Project overview & build instructions
├── LICENSE                       # License file
├── Makefile                      # Root build (C library, liblazer.a/so)
├── config.h                      # Configuration header
├── lazer.h                       # Public API header
├── liblazer.a  liblazer.so       # Prebuilt C library (optional)
├── src/                          # Core C library implementation
│   ├── lazer.c  lazer.h          # Main library entry
│   ├── ntt.c  ntt.h              # Number Theoretic Transform
│   ├── poly.c  poly.h            # Polynomial operations
│   ├── polymat.c  polyring.c     # Matrix / ring polynomial ops
│   ├── polyvec.c                 # Polynomial vectors
│   ├── rng.c  rng.h              # Random number generation
│   ├── grandom.c  brandom.c      # Gaussian / uniform randomness
│   ├── shake128.c  shake128.h    # SHAKE128 hash
│   ├── urandom.c  urandom.h      # System randomness
│   ├── mont.h                    # Montgomery arithmetic helpers
│   ├── lnp.c                     # Linear proofs main
│   ├── lin-proofs.c              # Linear proof implementation
│   ├── lnp-quad.c  lnp-quad-many.c
│   ├── lnp-quad-eval.c  lnp-tbox.c
│   ├── blindsig.c  blindsig.h    # Blind signature scheme
│   ├── abdlop.c                  # ABDLOP signature
│   ├── int.c  intvec.c  intmat.c # Integer helpers, vectors, matrices
│   ├── ckks/                     # CKKS integration (encoding, HE)
│   │   ├── ckks_encode.c
│   │   ├── ckks_he.c
│   │   └── ckks_bridge.c
│   └── labrador/                 # Labrador submodule (poly utils, tests)
├── demos/                        # Demonstrations and example programs
│   ├── ckks/
│   │   ├── he_demo.c
│   │   ├── he_add_demo.c
│   │   ├── encode_demo.c
│   │   ├── bridge_demo.c
│   │   └── ntt_smoketest.c
│   ├── blindsig/
│   └── kyber1024/
├── python/                       # Python bindings, CFFI, examples
│   ├── lazer.py
│   ├── lazer_cffi_build.py
│   ├── example.py
│   └── demo/
├── docs/                         # Sphinx documentation (docs/source)
└── tests/                        # C tests, Sage parameter files, test harnesses

Other directories
- golang/                         # Go demo / bindings
- scripts/                        # Codegen and Sage scripts
- third_party/                    # External archives / libs

Notes
- Keep `lazer/src` as the C implementation and internal headers.
- Expose a single public header (`lazer.h`) with stable API; keep experimental headers inside `src/`.
- Use this file content in `lazer/README` or copy into documentation as needed.
