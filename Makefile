OUT = ./dist
build-node:
	wasm-pack build --release --no-pack --out-dir ${OUT}/node --target nodejs
	cargo build --target wasm32-unknown-unknown --release
	wasm-bindgen ./target/wasm32-unknown-unknown/release/svm_merkle_tree.wasm --out-dir ${OUT}/node --target nodejs --weak-refs
	wasm-opt -O4 --dce ${OUT}/node/svm_merkle_tree_bg.wasm -o ${OUT}/node/svm_merkle_tree_bg.wasm
	rm ${OUT}/node/package.json && rm ${OUT}/node/.gitignore && rm ${OUT}/node/Readme.md

build-bundler:
	wasm-pack build --release --no-pack --out-dir ${OUT}/bundler --target bundler
	cargo build --target wasm32-unknown-unknown --release
	wasm-bindgen ./target/wasm32-unknown-unknown/release/svm_merkle_tree.wasm --out-dir ${OUT}/bundler --target bundler --weak-refs
	wasm-opt -O4 --dce ${OUT}/bundler/svm_merkle_tree_bg.wasm -o ${OUT}/bundler/svm_merkle_tree_bg.wasm
	rm ./dist/bundler/package.json && rm ${OUT}/bundler/.gitignore && rm ${OUT}/bundler/Readme.md

build:
	make build-node; make build-bundler