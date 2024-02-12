build:
	wasm-pack build --release --out-dir ./lib/ --target bundler
	cargo build --target wasm32-unknown-unknown --release
	wasm-bindgen ./target/wasm32-unknown-unknown/release/svm_merkle_tree.wasm --out-dir lib --target bundler --weak-refs
	wasm-opt -O4 --dce ./lib/svm_merkle_tree_bg.wasm -o ./lib/svm_merkle_tree_bg.wasm
	rm ./lib/package.json