## xorstr
A heavily vectorized c++17 compile time string encryption.

# usage
```cpp
auto xs = xorstr("Adasdads"); // xorstr(L"Adasdads") supported too
xs.crypt(); // does a pass of xor encryption
xs.get(); // returns pointer to data
xs.crypt_get(); // same as calling crypt() and then get()
xs.size(); // returns string size
```

# noteworthy things
* All keys are 64bit and generated during compile time.
* Data blocks go in increments of 16 bytes so some space may be wasted.
* The code has been crafter so that all the data would be embedded directly into code and not stored on .rdata and such.
* The entirety of string encryption and decryption will be inlined.

# supported compilers
Tested to be working on clang 5.0+, gcc 7.1+ and MSVC v141.
