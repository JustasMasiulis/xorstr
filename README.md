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
* The code has been crafted so that all the data would be embedded directly into code and not stored on .rdata and such.
* The entirety of string encryption and decryption will be inlined.

# supported compilers and platforms
Tested to be working on clang 5.0+, gcc 7.1+ and MSVC v141.
If your CPU does not support AVX define JM_XORSTR_DISABLE_AVX_INTRINSICS to only use SSE.

# example assembly output
Input code
```cpp
int main() {
    // or alternatively xorstr_(...) which includes crypt_get call
    std::puts(xorstr("an extra long hello_world").crypt_get());
}
```
Output of gcc (trunk)
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
