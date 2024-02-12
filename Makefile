build:
	wasm-pack build --release --out-dir ./lib/node --target nodejs
	cargo build --target wasm32-unknown-unknown --release
	wasm-bindgen ./target/wasm32-unknown-unknown/release/svm_merkle_tree.wasm --out-dir lib/node --target nodejs --weak-refs
	wasm-opt -O4 --dce ./lib/node/svm_merkle_tree_bg.wasm -o ./lib/node/svm_merkle_tree_bg.wasm