#!/bin/bash

# Activate Python virtual environment
source .venv/bin/activate

# Native cryptographic dependencies
export PBC_PREFIX="$(brew --prefix pbc)"
export GMP_PREFIX="$(brew --prefix gmp)"
export OPENSSL_PREFIX="$(brew --prefix openssl@3)"

# Compiler configuration
export CPPFLAGS="-I$PBC_PREFIX/include -I$GMP_PREFIX/include -I$OPENSSL_PREFIX/include"

export CFLAGS="$CPPFLAGS"

export LDFLAGS="-L$PBC_PREFIX/lib -L$GMP_PREFIX/lib -L$OPENSSL_PREFIX/lib"

export PKG_CONFIG_PATH="$PBC_PREFIX/lib/pkgconfig:$GMP_PREFIX/lib/pkgconfig:$OPENSSL_PREFIX/lib/pkgconfig"

echo "Project environment activated."
python --version