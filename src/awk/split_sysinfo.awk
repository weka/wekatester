FNR == 1 { if (out != "") close(out); out = ""; host = substr(FILENAME, length(ENVIRON["SYSI_PFX"]) + 1) }
/^=== WEKATESTER_SYSINFO / { if (out != "") close(out); out = ENVIRON["SYSI_ROOT"] "/" host "/" $3 ENVIRON["SYSI_SFX"]; next }
out != "" { print > out }
