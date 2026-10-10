FNR == 1 { if (out != "") close(out); out = ""; host = substr(FILENAME, length(ENVIRON["WT_PFX"]) + 1) }
/^=== WEKATESTER_SYSINFO / { if (out != "") close(out); out = ENVIRON["WT_ROOT"] "/" host "/" $3 ENVIRON["WT_SFX"]; next }
out != "" { print > out }
