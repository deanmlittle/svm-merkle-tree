build-node:
	wasm-pack build --release --out-dir ./dist/node --target nodejs
	cargo build --target wasm32-unknown-unknown --release
	wasm-bindgen ./target/wasm32-unknown-unknown/release/svm_merkle_tree.wasm --out-dir dist/node --target nodejs --weak-refs
	wasm-opt -O4 --dce ./dist/node/svm_merkle_tree_bg.wasm -o ./dist/node/svm_merkle_tree_bg.wasm
	rm ./dist/node/package.json && rm ./dist/node/.gitignore && rm ./dist/node/Readme.md

build-bundler:
	wasm-pack build --release --out-dir ./dist/bundler --target bundler
	cargo build --target wasm32-unknown-unknown --release
	wasm-bindgen ./target/wasm32-unknown-unknown/release/svm_merkle_tree.wasm --out-dir dist/bundler --target bundler --weak-refs
	wasm-opt -O4 --dce ./dist/bundler/svm_merkle_tree_bg.wasm -o ./dist/bundler/svm_merkle_tree_bg.wasm
	rm ./dist/bundler/package.json && rm ./dist/bundler/.gitignore && rm ./dist/bundler/Readme.md

build:
	make build-node; make build-bundler