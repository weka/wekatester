!/^[[:space:]]*#/ {gsub(/[[:space:]]/, "", $3);
    if ($3 != "" && $3 != "ioengine") print $3}
