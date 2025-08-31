pacman -S pacman-mirrors --noconfirm
pacman -S diffutils m4 make mingw-w64-x86_64-clang --noconfirm
PATH=$PATH:/mingw64/bin:/c/users/runneradmin/.cargo/bin
rustup target add x86_64-pc-windows-gnu
rustup toolchain install stable-x86_64-pc-windows-gnu
rustup default stable-x86_64-pc-windows-gnu
CC=clang cargo +stable-x86_64-pc-windows-gnu build --workspace --release --target x86_64-pc-windows-gnu