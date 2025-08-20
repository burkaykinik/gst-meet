#!/bin/bash

for dir in */; do
  if [ -f "$dir/Cargo.toml" ]; then
    echo "Running cargo bitbake in $dir"
    (
      cd "$dir" || exit 1
      cargo bitbake

      # Extract crate name from Cargo.toml (or use directory name)
      crate_name=$(basename "$PWD")
      
      # Ensure destination directory exists
      dest_dir="../yocto-recip/$crate_name"
      mkdir -p "$dest_dir"
      
      # Move .bb files to the destination
      for bb_file in *.bb; do
#         echo "BB_STRICT_CHECKSUM = \"0\"
# # inherit pkgconfig" >> "$bb_file"

        echo "BB_STRICT_CHECKSUM = \"0\"
">> "$bb_file"

echo "\
DEPENDS = \" \\
    gstreamer1.0 \\
    gstreamer1.0-plugins-base \\
    glib-2.0 \\
    openssl \\
    pkgconfig \\
    \"

DEPENDS += \"\\
    libnice \\
    pkgconfig-native \\
    clang-native \\
    \"
" >> "$bb_file"

        [ -e "$bb_file" ] && mv "$bb_file" "$dest_dir/"

      done
    )
  else
    echo "Skipping $dir — no Cargo.toml"
  fi
done

cp -r yocto-recip/* /media/user/1342590a-3f2a-482b-b541-f9f2c43f99c7/myStuff/imx-yocto-bsp/sources/meta-custom/recipes-gst-meet/
