## xorstr
A heavily vectorized c++17 compile time string encryption.

# quick example
```cpp
int main() {
    std::puts(xorstr_("an extra long hello_world"));
}
```

# API
```cpp
// This macro creates an encrypted xor_string string instance.
#define xorstr(string) xor_string<...>{string}

// For convenience sake there is also a macro to instantly decrypt the string
#define xorstr_(string) xorstr(string).crypt_get()

struct xor_string<CharType, ...> {
    using size_type     = std::size_t;
    using value_type    = CharT;
    using pointer       = value_type*;
    using const_pointer = const value_type*;
    
    // Returns string size in characters, not including null terminator.
    constexpr size_type size() const;
    
    // Runs the encryption/decryption algorithm on the internal storage.
    void crypt() noexcept;
    
    // Returns const pointer to the storage, without doing any modifications to it.
    const_pointer get() const;
    
    // Returns non const pointer to the storage, without doing any modifications to it.
    pointer get();

    // Runs crypt() and returns the pointer to the internal storage.
    pointer crypt_get();
}
```

# noteworthy things
* All keys are 64bit and generated during compile time.
* Data blocks go in increments of 16 bytes so some space may be wasted.
* The code has been crafted so that all the data would be embedded directly into code and not stored on .rdata and such.
* The entirety of string encryption and decryption will be inlined.

# supported compilers and platforms
Tested to be working on clang 5.0+, gcc 7.1+ and MSVC v141.
If your CPU does not support AVX define JM_XORSTR_DISABLE_AVX_INTRINSICS to only use SSE.

# example assembly output
Output of gcc (trunk) from the quick example
```asm
main:
  movabs rax, -4762152789334367252
  push rbp
  mov rbp, rsp
  and rsp, -32
  sub rsp, 64
  mov QWORD PTR [rsp], rax
  mov rdi, rsp
  movabs rax, -6534519754492314190
  mov QWORD PTR [rsp+8], rax
  movabs rax, -2862143164529545214
  mov QWORD PTR [rsp+16], rax
  movabs rax, -4140208776682645948
  mov QWORD PTR [rsp+24], rax
  vmovdqa ymm1, YMMWORD PTR [rsp]
  movabs rax, -2550414817236710003
  mov QWORD PTR [rsp+32], rax
  movabs rax, -4595755740016602734
  mov QWORD PTR [rsp+40], rax
  movabs rax, -5461194525092864914
  mov QWORD PTR [rsp+48], rax
  movabs rax, -4140208776682645984
  mov QWORD PTR [rsp+56], rax
  vpxor ymm0, ymm1, YMMWORD PTR [rsp+32]
  vmovdqa YMMWORD PTR [rsp], ymm0
  vzeroupper
  call puts
  xor eax, eax
  leave
  ret
  ```
