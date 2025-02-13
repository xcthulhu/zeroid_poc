.PHONY = all all-ios setup-ios

RUST_SOURCES = uniffi-bindings/src/lib.rs passport-verifier-core/src/lib.rs

all:
	@echo "Please run 'make all-ios' to build for iOS"

all-ios: setup-ios ZeroIDRustPassportUtils.xcframework

setup-ios:
	rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

target/debug/libzeroid_rust_passport_utils.dylib: $(RUST_SOURCES)
	cargo build

target/aarch64-apple-ios/release/libzeroid_rust_passport_utils.a: $(RUST_SOURCES)
	cargo build --release --target aarch64-apple-ios

target/aarch64-apple-ios-sim/release/libzeroid_rust_passport_utils.a: $(RUST_SOURCES)
	cargo build --release --target aarch64-apple-ios-sim

target/x86_64-apple-ios/release/libzeroid_rust_passport_utils.a: $(RUST_SOURCES)
	cargo build --release --target x86_64-apple-ios

libzeroid_rust_passport_utils_universal.a: target/aarch64-apple-ios-sim/release/libzeroid_rust_passport_utils.a target/x86_64-apple-ios/release/libzeroid_rust_passport_utils.a
	lipo -create -output $@ $^

bindings: target/debug/libzeroid_rust_passport_utils.dylib
	rm -rf $@
	cargo run --bin uniffi-bindgen generate --library $< --language swift --out-dir $@
	mv $@/zeroid_rust_passport_utilsFFI.modulemap $@/module.modulemap

ZeroIDRustPassportUtils.xcframework: target/aarch64-apple-ios/release/libzeroid_rust_passport_utils.a libzeroid_rust_passport_utils_universal.a bindings
	rm -rf $@
	xcodebuild -create-xcframework \
        -library libzeroid_rust_passport_utils_universal.a -headers ./bindings \
        -library ./target/aarch64-apple-ios/release/libzeroid_rust_passport_utils.a -headers ./bindings \
        -output $@

clean:
	cargo clean
	rm -f libzeroid_rust_passport_utils_universal.a
	rm -rf bindings
	rm -rf ZeroIDRustPassportUtils.xcframework