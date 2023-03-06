# wasmwraptest
##编译
cargo build --target wasm32-wasi --release

##运行
wasmedge target/wasm32-wasi/release/testapi.wasm

 
